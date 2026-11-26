//! A person's access: the People list, and everything one user or service user can do and why.
//!
//! Both read the grant graph backwards from the principal
//! ([`principal_reach`](crate::service_users::reads)), so a person's page costs what they hold,
//! not the size of Gauge's tables. Every read runs on the caller's Valence; nothing switches to
//! System.

use std::collections::{BTreeMap, HashSet};

use lepton_identity::service_users::ServiceUserId;
use valence::{RecordId, Valence};

use crate::actor_can_raw::model_pk_id;
use crate::generated::{
    Permission, PermissionHistory, PermissionRequest, PermissionServiceUserPrincipal,
    PermissionUserPrincipal,
};
use crate::service_users::reads::{
    group_principal_record, principal_reach, service_user_principal_record, ALLOWED_EDGE,
    MEMBER_EDGE, OWNER_EDGE,
};
use crate::service_users::SERVICE_USER_PRINCIPAL_TABLE;
use crate::types::{
    AccessPath, GroupMembership, GroupRef, Page, PersonRow, PrincipalAccess, PrincipalKey,
    PrincipalKind, RecordKind, RecordRef,
};

use super::access::actor_is_gauge_admin;
use super::helpers::{
    canonical_user_id, get_group_raw, get_permission_raw, principal_ref_from_record,
    raw_table_rows, require_user_id, user_label, user_principal_id,
};
use super::holders::{group_ref, permission_ref};
use super::permissions::permission_display_name;
use super::requests::request_row_from_model;
use super::GaugeServiceError;

/// Rows per page of [`list_people`].
pub const PEOPLE_PAGE_SIZE: usize = 50;

/// The users and service users Gauge knows (everyone with a principal row: on an allow list or
/// in a group, now or before), sorted by name, one page at a time.
///
/// `query` matches a person's name, email or id, or a service user's handle (any case). Each row
/// carries the groups the principal is directly in and the permissions granted straight to it.
/// Pass the previous page's `next_cursor` as `cursor` for the next page.
///
/// # Who may call it
///
/// Gauge admins only.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for anyone else; `Validation` for a cursor this
/// function didn't hand out. Valence failures otherwise.
pub async fn list_people(
    query: Option<&str>,
    cursor: Option<&str>,
    v: &Valence,
) -> anyhow::Result<Page<PersonRow>> {
    if !actor_is_gauge_admin(v).await? {
        return Err(GaugeServiceError::not_authorized("list people").into());
    }
    let offset = parse_cursor(cursor)?;
    let needle = query
        .map(|q| q.trim().to_lowercase())
        .filter(|q| !q.is_empty());

    // The People list is an admin directory of every principal; a full scan of the two principal
    // tables is intended here.
    let mut people = Vec::new();
    for table in ["permission_user_principal", SERVICE_USER_PRINCIPAL_TABLE] {
        for row in raw_table_rows(table, v).await? {
            let id = if table == SERVICE_USER_PRINCIPAL_TABLE {
                serde_json::from_value::<PermissionServiceUserPrincipal>(row)?
                    .id()
                    .cloned()
            } else {
                serde_json::from_value::<PermissionUserPrincipal>(row)?
                    .id()
                    .cloned()
            };
            let Some(principal) = id else {
                continue;
            };
            let Some(reference) = principal_ref_from_record(&principal, v).await? else {
                continue;
            };
            if let Some(needle) = &needle {
                if !reference.label.to_lowercase().contains(needle)
                    && !reference.id.to_lowercase().contains(needle)
                {
                    continue;
                }
            }
            people.push((principal, reference));
        }
    }
    people.sort_by(|a, b| {
        a.1.label
            .to_lowercase()
            .cmp(&b.1.label.to_lowercase())
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    let total = people.len();
    let mut items = Vec::new();
    for (principal, reference) in people.into_iter().skip(offset).take(PEOPLE_PAGE_SIZE) {
        let backend = v
            .backend_for_table("permission_group")
            .map_err(|e| anyhow::anyhow!("resolve permission_group backend: {e}"))?;
        let mut groups = Vec::new();
        let mut seen = HashSet::new();
        for edge in [MEMBER_EDGE, OWNER_EDGE] {
            for group in backend.get_edge_sources(&principal, edge).await? {
                if seen.insert(group.id().to_string()) {
                    if let Some(group) = get_group_raw(group.id(), v).await? {
                        groups.push(group_ref(&group));
                    }
                }
            }
        }
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        let backend = v
            .backend_for_table("permission")
            .map_err(|e| anyhow::anyhow!("resolve permission backend: {e}"))?;
        let mut direct_permissions = Vec::new();
        for permission in backend.get_edge_sources(&principal, ALLOWED_EDGE).await? {
            if let Some(permission) = get_permission_raw(permission.id(), v).await? {
                direct_permissions.push(permission_ref(&permission));
            }
        }
        direct_permissions.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        items.push(PersonRow {
            principal: reference,
            groups,
            direct_permissions,
        });
    }
    let next = offset + PEOPLE_PAGE_SIZE;
    Ok(Page {
        items,
        next_cursor: (next < total).then(|| next.to_string()),
    })
}

/// Everything `principal` can do in Gauge, and why.
///
/// - `permissions`: each permission it holds, with every path to it (direct, or through groups
///   outermost first).
/// - `groups`: the groups it is directly a member (or, for a person, owner) of, with who added
///   it and when, from the group's history.
/// - `owns`: the groups it owns directly or through an owner group, and the permissions those
///   groups own.
/// - `open_requests`: its pending access requests (for a service user, the ones filed for it).
///
/// A suspended or deleted service user still lists what it is granted; checks refuse it while
/// it isn't active.
///
/// # Who may call it
///
/// Gauge admins, for anyone. Everyone else only for themselves; see [`principal_access_self`].
///
/// # Errors
///
/// [`GaugeServiceError`]: `NotAuthorized` for a caller reading someone else without being a
/// Gauge admin; `Validation` for a principal kind other than user or service user, or a
/// malformed service user id. Valence failures otherwise.
pub async fn principal_access(
    principal: &PrincipalKey,
    v: &Valence,
) -> anyhow::Result<PrincipalAccess> {
    let is_self = principal.kind == PrincipalKind::User
        && v.actor()
            .user_id()
            .is_some_and(|me| canonical_user_id(me) == canonical_user_id(&principal.id));
    if !is_self && !actor_is_gauge_admin(v).await? {
        return Err(GaugeServiceError::not_authorized("read someone else's access").into());
    }
    let (record, is_user) = match principal.kind {
        PrincipalKind::User => (
            RecordId::new(
                "permission_user_principal",
                user_principal_id(&principal.id),
            ),
            true,
        ),
        PrincipalKind::ServiceUser => {
            let service_user = ServiceUserId::parse(principal.id.trim())
                .map_err(|_| GaugeServiceError::validation("That service user id is not valid"))?;
            (service_user_principal_record(&service_user), false)
        }
        _ => {
            return Err(GaugeServiceError::validation(
                "Only a person or a service user has access to list",
            )
            .into())
        }
    };

    let reach = principal_reach(&record, is_user, v).await?;

    let mut permissions: BTreeMap<String, (crate::types::PermissionRef, Vec<AccessPath>)> =
        BTreeMap::new();
    for (permission, via) in &reach.permissions {
        let path = match via {
            None => AccessPath::Direct,
            Some(index) => AccessPath::ThroughGroup(reach.groups[*index].chain.clone()),
        };
        let entry = permissions
            .entry(model_pk_id(permission.id()))
            .or_insert_with(|| (permission_ref(permission), Vec::new()));
        if !entry.1.contains(&path) {
            entry.1.push(path);
        }
    }
    let mut permissions: Vec<_> = permissions.into_values().collect();
    permissions.sort_by(|a, b| {
        a.0.display_name
            .to_lowercase()
            .cmp(&b.0.display_name.to_lowercase())
    });

    let mut groups = Vec::new();
    for group in &reach.direct_groups {
        let (added_by_label, added_at) = added_to_group(&group.id, &principal.id, v).await?;
        groups.push(GroupMembership {
            group: GroupRef {
                id: group.id.clone(),
                name: group.group.name().clone(),
            },
            added_by_label,
            added_at,
        });
    }
    groups.sort_by(|a, b| a.group.name.cmp(&b.group.name));

    let owns = if is_user {
        owned_records(&record, &reach, v).await?
    } else {
        Vec::new()
    };

    let pending = PermissionRequest::query(v, valence::use_!(r"When someone opens **a person's access page** in **Gauge**, we **list that person's pending access requests** (or the ones filed for a service user) so the page shows what is still waiting. Gauge admins, and each person for themselves, see the list."))
        .where_status(valence::StringPredicate::Equals("PENDING".to_string()));
    let pending = if is_user {
        pending.where_requestor(valence::RecordPredicate::Equals(RecordId::new(
            "user",
            canonical_user_id(&principal.id),
        )))
    } else {
        pending.where_on_behalf_of(valence::RecordPredicate::Equals(record.clone()))
    };
    let mut open_requests = Vec::new();
    for request in pending
        .order_by_created_at(valence::SortDirection::Desc)
        .await?
    {
        open_requests.push(request_row_from_model(&request, v).await?);
    }

    Ok(PrincipalAccess {
        permissions,
        groups,
        owns,
        open_requests,
    })
}

/// [`principal_access`] for the signed-in caller.
///
/// # Errors
///
/// An error when the caller isn't a signed-in user; Valence failures otherwise.
pub async fn principal_access_self(v: &Valence) -> anyhow::Result<PrincipalAccess> {
    let me = require_user_id(v)?;
    principal_access(
        &PrincipalKey {
            kind: PrincipalKind::User,
            id: canonical_user_id(&me),
        },
        v,
    )
    .await
}

/// Who added `principal_id` to `group_id` and when: the newest add row for it in the group's
/// history. `(None, None)` when the history has none (seeded or older memberships).
async fn added_to_group(
    group_id: &str,
    principal_id: &str,
    v: &Valence,
) -> anyhow::Result<(Option<String>, Option<chrono::DateTime<chrono::Utc>>)> {
    let rows = PermissionHistory::query(v, valence::use_!(r"When someone opens **a person's access page** in **Gauge**, we **read the group's history** to show who added the person to each group and when. Gauge admins, and each person for themselves, see that line."))
        .where_source(valence::RecordPredicate::Equals(RecordId::new("permission_group", group_id)))
        .order_by_changed_at(valence::SortDirection::Desc)
        .await?;
    let wanted = canonical_user_id(principal_id);
    for row in rows {
        let is_add = matches!(
            row.field_name().as_str(),
            "member_users" | "owner_users" | "member_service_users"
        );
        if is_add && canonical_user_id(row.new_value()) == wanted {
            let added_by = match row.actor() {
                Some(actor) => Some(user_label(actor.id(), v).await),
                None => None,
            };
            return Ok((added_by, Some(*row.changed_at())));
        }
    }
    Ok((None, None))
}

/// Groups the person owns (directly, or as a holder of an owner group) and the permissions
/// those groups own.
async fn owned_records(
    record: &RecordId,
    reach: &crate::service_users::reads::Reach,
    v: &Valence,
) -> anyhow::Result<Vec<RecordRef>> {
    let backend = v
        .backend_for_table("permission_group")
        .map_err(|e| anyhow::anyhow!("resolve permission_group backend: {e}"))?;
    let mut owners = vec![record.clone()];
    owners.extend(reach.groups.iter().map(|g| group_principal_record(&g.id)));
    let mut owned = Vec::new();
    let mut seen = HashSet::new();
    for owner in owners {
        for group in backend.get_edge_sources(&owner, OWNER_EDGE).await? {
            if seen.insert(group.id().to_string()) {
                if let Some(group) = get_group_raw(group.id(), v).await? {
                    owned.push(group);
                }
            }
        }
    }

    let mut out = Vec::new();
    for group in &owned {
        let group_id = model_pk_id(group.id());
        out.push(RecordRef {
            kind: RecordKind::Group,
            id: group_id.clone(),
            label: group.name().clone(),
        });
        let permissions = Permission::query(v, valence::use_!(r"When someone opens **a person's access page** in **Gauge**, we **list the permissions each group they own owns**, so the page shows what they manage. Gauge admins, and each person for themselves, see the list."))
            .where_owners_group(valence::RecordPredicate::Equals(RecordId::new(
                "permission_group",
                &group_id,
            )))
            .await?;
        for permission in permissions {
            // Re-read raw: typed list reads can drop trait fields (`name`) on some paths.
            let id = model_pk_id(permission.id());
            if let Some(permission) = get_permission_raw(&id, v).await? {
                out.push(RecordRef {
                    kind: RecordKind::Permission,
                    id,
                    label: permission_display_name(&permission),
                });
            }
        }
    }
    out.sort_by_key(|record| record.label.to_lowercase());
    out.dedup();
    Ok(out)
}

/// Offset encoded in a cursor from [`list_people`]; `0` for none.
fn parse_cursor(cursor: Option<&str>) -> anyhow::Result<usize> {
    cursor
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map_or(Ok(0), |c| {
            c.parse()
                .map_err(|_| GaugeServiceError::validation("That page link is not valid").into())
        })
}
