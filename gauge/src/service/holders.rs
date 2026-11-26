//! Who holds a permission: every user who holds a named permission, for fan-out (notifications,
//! digests), and the holders of one permission with how each gets it, for its page.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use lepton_identity::service_users::ServiceUserId;
use valence::{RecordId, Valence};

use crate::actor_can_raw::{model_pk_id, permissions_named_raw, raw_get_json};
use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionHistory,
    PermissionUserPrincipal,
};
use crate::service_users::access::service_user_is_active;
use crate::service_users::reads::{group_principal_record, principal_reach};
use crate::service_users::{GAUGE_LIST_PERMISSION_HOLDERS, SERVICE_USER_PRINCIPAL_TABLE};
use crate::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID};
use crate::types::{AccessPath, GroupRef, HolderRow, PermissionRef, PrincipalKind};

use super::access::{actor_is_gauge_admin, can_edit_group, can_edit_permission};
use super::helpers::{
    canonical_user_id, get_group_raw, get_permission_raw, principal_ref_from_record,
};
use super::permissions::permission_display_name;
use super::GaugeServiceError;

/// Bare user ids of everyone who holds `permission_name`, directly or through groups.
///
/// A user holds the permission when it is granted straight to them, or to a group they
/// own or are a member of, at any depth of nested groups (the same rule as
/// [`crate::service::user_can`]). Service users on the grant graph are not listed. The ids
/// come back sorted, without duplicates and without the `user:` table prefix. A blank or
/// unknown name gives an empty list.
///
/// Every read is a raw backend read on `v`; nothing elevates to System.
///
/// # Who may call it
///
/// - A System actor, for jobs that started as System.
/// - A registered service user that holds [`GAUGE_LIST_PERMISSION_HOLDERS`] (seeded with the
///   [`crate::service_users::PERMISSION_HOLDER_READERS_GROUP_ID`] group), while it is active.
/// - A super user, or a user who can edit every permission with that name.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for anyone else, including anonymous callers and
/// built-in service users. Backend read and decode failures are returned as they are.
pub async fn list_permission_holders(
    v: &Valence,
    permission_name: &str,
) -> anyhow::Result<Vec<String>> {
    let permission_name = permission_name.trim();
    let permissions = permissions_named_raw(permission_name, v).await?;
    if !may_list_holders(v, &permissions).await? {
        return Err(GaugeServiceError::not_authorized("list_permission_holders").into());
    }

    let mut holders = BTreeSet::new();
    let mut groups = Vec::new();
    for permission in &permissions {
        for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission** (for example to notify them), **Gauge** **follows the allowed-principal edges** to find the users and groups it is granted to. The service uses the ids to reach those people; nothing else is shown.")).await? {
            collect_principal(&principal, v, &mut holders, &mut groups).await?;
        }
    }

    let mut visited = HashSet::new();
    while let Some(group) = groups.pop() {
        if !visited.insert(model_pk_id(group.id())) {
            continue;
        }
        let owners = group.get_owners_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission**, **Gauge** **follows a holding group's owner edges**, because group owners hold what the group holds. The service uses the ids to reach those people; nothing else is shown.")).await?;
        let members = group.get_members_record_ids(v, valence::use_!(r"When a **service** needs **everyone who holds a permission**, **Gauge** **follows a holding group's member edges**, including nested groups. The service uses the ids to reach those people; nothing else is shown.")).await?;
        for principal in owners.iter().chain(&members) {
            collect_principal(principal, v, &mut holders, &mut groups).await?;
        }
    }

    Ok(holders.into_iter().collect())
}

/// System, a service user holding the lookup permission, a super user, or an editor of
/// every permission row with the name.
async fn may_list_holders(
    v: &Valence,
    permissions: &[crate::generated::Permission],
) -> anyhow::Result<bool> {
    let actor = v.actor();
    if actor.is_system() {
        return Ok(true);
    }
    if let Some(service_user) = lepton_identity::service_users::ServiceUserId::from_actor(actor) {
        let decision = crate::service_users::access::service_user_decision(
            v,
            &service_user,
            GAUGE_LIST_PERMISSION_HOLDERS,
        )
        .await;
        crate::service_users::access::log_decision(GAUGE_LIST_PERMISSION_HOLDERS, &decision);
        return decision.map(crate::service_users::access::ServiceUserDecision::allowed);
    }
    if actor.user_id().is_none() {
        return Ok(false);
    }
    if actor_is_super_user(v).await? {
        return Ok(true);
    }
    if permissions.is_empty() {
        return Ok(false);
    }
    for permission in permissions {
        if !can_edit_permission(permission, v).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Add a user principal's id to `holders`, or queue the group behind a group principal.
async fn collect_principal(
    principal: &RecordId,
    v: &Valence,
    holders: &mut BTreeSet<String>,
    groups: &mut Vec<PermissionGroup>,
) -> anyhow::Result<()> {
    let principal_id = principal.id().to_string();
    match principal.table() {
        "permission_user_principal" => {
            if let Some(row) = raw_get_json("permission_user_principal", &principal_id, v).await? {
                let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                let user_id = valence::extract_id_from_record(principal.user()).unwrap_or_default();
                if !user_id.is_empty() {
                    holders.insert(canonical_user_id(&user_id));
                }
            }
        }
        "permission_group_principal" => {
            if let Some(row) = raw_get_json("permission_group_principal", &principal_id, v).await? {
                let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                let group_id =
                    valence::extract_id_from_record(principal.group()).unwrap_or_default();
                if let Some(row) = raw_get_json("permission_group", &group_id, v).await? {
                    groups.push(serde_json::from_value(row)?);
                }
            }
        }
        // Service users are not people; they never receive a holder fan-out.
        _ => {}
    }
    Ok(())
}

/// Every principal that passes `permission_id`'s check, each with the ways it gets there.
///
/// Walks forward from the permission's allow list: a user or service user on it holds the
/// permission [`AccessPath::Direct`]; a group on it passes it to its owners and members, and to
/// nested groups' owners and members, as [`AccessPath::ThroughGroup`] (outermost group first).
/// Service users only ever hold through membership, and only while active. Super users pass
/// every check, so the Super User group's people are listed with [`AccessPath::SuperUser`].
/// `since` is when the direct grant was made, from the permission's history. Rows are sorted by
/// label. Never scans every group: the walk starts from the allow list's edges.
///
/// Every read runs on `v`; nothing switches to System.
///
/// # Who may call it
///
/// The permission's owners (through its owners group) and every Gauge admin.
///
/// # Errors
///
/// [`GaugeServiceError`]: `NotFound` for an unknown id, `NotAuthorized` for anyone else (the
/// page shows the owner line instead). Valence failures otherwise.
pub async fn list_effective_holders(
    permission_id: &str,
    v: &Valence,
) -> anyhow::Result<Vec<HolderRow>> {
    let permission = get_permission_raw(permission_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("Permission", permission_id))?;
    if !can_edit_permission(&permission, v).await? && !actor_is_gauge_admin(v).await? {
        return Err(GaugeServiceError::not_authorized("list who has access").into());
    }

    let mut holders: BTreeMap<(String, String), (RecordId, Vec<AccessPath>)> = BTreeMap::new();
    let mut add = |principal: &RecordId, path: AccessPath| {
        let entry = holders
            .entry((principal.table().to_string(), principal.id().to_string()))
            .or_insert_with(|| (principal.clone(), Vec::new()));
        if !entry.1.contains(&path) {
            entry.1.push(path);
        }
    };

    let mut queue: VecDeque<(PermissionGroup, Vec<GroupRef>)> = VecDeque::new();
    for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **follows the allowed-principal edges** to find the people, service users and groups it is granted to. They see each holder by name with how they got access.")).await? {
        if let Some(group) = group_behind(&principal, v).await? {
            let chain = vec![group_ref(&group)];
            queue.push_back((group, chain));
        } else {
            add(&principal, AccessPath::Direct);
        }
    }

    let mut visited = HashSet::new();
    while let Some((group, chain)) = queue.pop_front() {
        if !visited.insert(model_pk_id(group.id())) {
            continue;
        }
        let owners = group.get_owners_record_ids(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **follows a holding group's owner edges**, because group owners hold what the group holds. They see each holder by name with how they got access.")).await?;
        let members = group.get_members_record_ids(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **follows a holding group's member edges**, including nested groups. They see each holder by name with how they got access.")).await?;
        for principal in owners.iter().chain(&members) {
            if let Some(child) = group_behind(principal, v).await? {
                let mut child_chain = chain.clone();
                child_chain.push(group_ref(&child));
                queue.push_back((child, child_chain));
            } else if principal.table() == SERVICE_USER_PRINCIPAL_TABLE
                && !members.contains(principal)
            {
                // Service users are only ever members; an owner edge to one is a forged row.
            } else {
                add(principal, AccessPath::ThroughGroup(chain.clone()));
            }
        }
    }

    if let Some(super_group) = get_group_raw(SUPER_USER_GROUP_ID, v).await? {
        let owners = super_group.get_owners_record_ids(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **reads the Super User group's people**, who pass every check. They are listed as holding it as Super User.")).await?;
        let members = super_group.get_members_record_ids(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **reads the Super User group's people**, who pass every check. They are listed as holding it as Super User.")).await?;
        for principal in owners.iter().chain(&members) {
            if principal.table() == "permission_user_principal" {
                add(principal, AccessPath::SuperUser);
            }
        }
    }

    let since = direct_grant_times(permission_id, v).await?;
    let mut out = Vec::new();
    for (principal, paths) in holders.into_values() {
        if principal.table() == SERVICE_USER_PRINCIPAL_TABLE {
            let Ok(service_user) = ServiceUserId::parse(principal.id()) else {
                continue;
            };
            if !service_user_is_active(v, &service_user).await? {
                continue;
            }
        }
        let Some(reference) = principal_ref_from_record(&principal, v).await? else {
            continue;
        };
        if !matches!(
            reference.kind,
            PrincipalKind::User | PrincipalKind::ServiceUser
        ) {
            continue;
        }
        out.push(HolderRow {
            label: reference.label.clone(),
            kind: reference.kind.clone(),
            owner_label: reference.owner_label.clone(),
            since: since.get(&reference.id).copied(),
            principal: reference,
            paths,
        });
    }
    out.sort_by(|a, b| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then_with(|| a.principal.id.cmp(&b.principal.id))
    });
    Ok(out)
}

/// The permissions a group's members get: those granted to the group, and to every group it is
/// a member or owner of, sorted by display name.
///
/// Walks edges backwards from the group's principal, so the cost follows what the group holds.
///
/// # Who may call it
///
/// The group's owners and every Gauge admin.
///
/// # Errors
///
/// [`GaugeServiceError`]: `NotFound` for an unknown id, `NotAuthorized` for anyone else.
/// Valence failures otherwise.
pub async fn list_group_access(group_id: &str, v: &Valence) -> anyhow::Result<Vec<PermissionRef>> {
    let group = get_group_raw(group_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("permission_group", group_id))?;
    if !can_edit_group(&group, v).await? && !actor_is_gauge_admin(v).await? {
        return Err(GaugeServiceError::not_authorized("list a group's access").into());
    }
    let reach = principal_reach(&group_principal_record(group_id), true, v).await?;
    let mut seen = HashSet::new();
    let mut out: Vec<PermissionRef> = reach
        .permissions
        .iter()
        .map(|(permission, _)| permission_ref(permission))
        .filter(|p| seen.insert(p.id.clone()))
        .collect();
    out.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    });
    Ok(out)
}

/// A permission named for people.
pub fn permission_ref(permission: &Permission) -> PermissionRef {
    PermissionRef {
        id: model_pk_id(permission.id()),
        key: permission.name().clone(),
        display_name: permission_display_name(permission),
    }
}

pub fn group_ref(group: &PermissionGroup) -> GroupRef {
    GroupRef {
        id: model_pk_id(group.id()),
        name: group.name().clone(),
    }
}

/// The group a group principal stands for; `None` for any other principal.
async fn group_behind(
    principal: &RecordId,
    v: &Valence,
) -> anyhow::Result<Option<PermissionGroup>> {
    if principal.table() != "permission_group_principal" {
        return Ok(None);
    }
    let Some(row) = raw_get_json("permission_group_principal", principal.id(), v).await? else {
        return Ok(None);
    };
    let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
    let group_id = valence::extract_id_from_record(principal.group()).unwrap_or_default();
    get_group_raw(&group_id, v).await
}

/// When each user or service user still on `permission_id`'s allow list was granted it,
/// keyed by bare id: the newest grant row in the permission's history.
async fn direct_grant_times(
    permission_id: &str,
    v: &Valence,
) -> anyhow::Result<HashMap<String, DateTime<Utc>>> {
    let rows = PermissionHistory::query(v, valence::use_!(r"When an owner or Gauge admin opens **who has access** to a permission, **Gauge** **reads the permission's history** to show since when each person or service user has held it directly. They see the date next to the name."))
        .where_source(valence::RecordPredicate::Equals(RecordId::new("permission", permission_id)))
        .order_by_changed_at(valence::SortDirection::Desc)
        .await?;
    let mut out = HashMap::new();
    for row in rows {
        if !matches!(
            row.field_name().as_str(),
            "granted_users" | "granted_service_users"
        ) || row.new_value().is_empty()
        {
            continue;
        }
        let at = *row.changed_at();
        out.entry(canonical_user_id(row.new_value())).or_insert(at);
    }
    Ok(out)
}
