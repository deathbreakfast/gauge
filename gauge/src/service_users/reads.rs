//! Read a service user's groups and effective permissions under the caller's own Valence.
//!
//! Both reads are for the service user's owner, or a user who manages every service user. They
//! check that the caller can see the service user, then walk the grant graph backwards from the
//! service user's principal ([`principal_reach`]) with the holder rules of
//! [`service_user_decision`](super::access::service_user_decision).
//! Nothing here switches to [`valence::Actor::System`].

use lepton::generated::ServiceUserAccount;
use lepton_identity::service_users::ServiceUserId;
use valence::{Model, RecordId, Valence};

use super::access::service_user_is_active;
use super::{service_user_principal_id, SERVICE_USER_PRINCIPAL_TABLE};
use crate::actor_can_raw::{model_pk_id, raw_get_json};
use crate::generated::{Permission, PermissionGroup};
use crate::service::GaugeServiceError;
use crate::types::{GroupRef, ServiceUserGroupDto, ServiceUserPermissionDto};

/// Fail with `NotFound` unless the caller is a signed-in user who can see `service_user`.
///
/// Visibility is Lepton's own privacy rule: the owner, or a user holding
/// `lepton.service_user.manage_any`. A service user the caller can't see looks the same as one
/// that doesn't exist.
async fn require_visible_service_user(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<()> {
    if !matches!(v.actor(), valence::Actor::User { .. }) {
        return Err(GaugeServiceError::not_authorized("read service user access").into());
    }
    let visible = ServiceUserAccount::get(service_user.as_str(), v, valence::use_!(r"When an owner opens a **service user's access page**, we **check that they can see the service user**, meaning they own it or manage every service user. Nothing about the service user is shown here; the check only decides whether its groups and permissions are listed."))
        .await?
        .is_some();
    if visible {
        Ok(())
    } else {
        Err(GaugeServiceError::not_found("service_user", service_user.as_str()).into())
    }
}

fn group_dto(group: &PermissionGroup) -> ServiceUserGroupDto {
    ServiceUserGroupDto {
        id: model_pk_id(group.id()),
        name: group.name().clone(),
        description: group.description().cloned().unwrap_or_default(),
    }
}

/// Edge table from a group to its member principals.
pub const MEMBER_EDGE: &str = "permission_group_member_principal";
/// Edge table from a group to its owner principals.
pub const OWNER_EDGE: &str = "permission_group_owner_principal";
/// Edge table from a permission to the principals on its allow list.
pub const ALLOWED_EDGE: &str = "permission_allowed_principal";

thread_local! {
    /// Backend reads made by [`principal_reach`] on this thread (tests run one per thread).
    static REACH_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn note_reach_read() {
    REACH_READS.with(|c| c.set(c.get() + 1));
}

/// Reset this thread's [`principal_reach`] read counter.
#[doc(hidden)]
pub fn __test_reset_reach_read_count() {
    REACH_READS.with(|c| c.set(0));
}

/// Backend reads [`principal_reach`] made on this thread since the last reset.
#[doc(hidden)]
#[must_use]
pub fn __test_reach_read_count() -> usize {
    REACH_READS.with(std::cell::Cell::get)
}

/// Record ids with an `edge` pointing at `to`, read from the backend that stores `source_table`.
async fn edge_sources(
    v: &Valence,
    source_table: &str,
    edge: &str,
    to: &RecordId,
) -> anyhow::Result<Vec<RecordId>> {
    note_reach_read();
    let backend = v
        .backend_for_table(source_table)
        .map_err(|e| anyhow::anyhow!("resolve {source_table} backend: {e}"))?;
    Ok(backend
        .get_edge_sources(to, edge)
        .await
        .map_err(|e| anyhow::anyhow!("read {edge} sources: {e}"))?
        .into_iter()
        .filter(|rid| rid.table() == source_table)
        .collect())
}

async fn load_row<T: serde::de::DeserializeOwned>(
    table: &str,
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<T>> {
    note_reach_read();
    match raw_get_json(table, id, v).await? {
        Some(row) => Ok(Some(
            serde_json::from_value(row).map_err(|e| anyhow::anyhow!("decode {table}: {e}"))?,
        )),
        None => Ok(None),
    }
}

/// The principal record standing for `group_id` on member, owner and allow-list edges.
pub fn group_principal_record(group_id: &str) -> RecordId {
    RecordId::new(
        "permission_group_principal",
        crate::service::helpers::group_principal_id(group_id),
    )
}

/// A group that holds a principal, and how.
#[derive(Clone, Debug)]
pub struct ReachedGroup {
    /// The group row.
    pub group: PermissionGroup,
    /// Bare group id.
    pub id: String,
    /// This group, then each nested group down to the one the principal sits in.
    pub chain: Vec<GroupRef>,
}

/// Everything a principal holds, found by walking edges backwards from it.
#[derive(Clone, Debug, Default)]
pub struct Reach {
    /// Groups the principal is directly a member (or, for users, owner) of.
    pub direct_groups: Vec<ReachedGroup>,
    /// Every group that holds the principal, direct ones first, then outward.
    pub groups: Vec<ReachedGroup>,
    /// Each permission the principal holds, with `None` for a direct grant or the index into
    /// [`Self::groups`] of the group it comes through. A permission can appear more than once.
    pub permissions: Vec<(Permission, Option<usize>)>,
}

/// Walk the grant graph backwards from `principal` (a user, service user or group principal
/// record).
///
/// Starts from the groups that list the principal as a member (and as an owner when
/// `owner_edges_count` is set: owner users hold what their group holds, service users are only
/// ever members), then the groups those groups are members or owners of, and so on. Then reads
/// the allow-list edges pointing at the principal and at each group it reached. Every read is
/// a backend edge or row read on `v`, so the cost follows what the principal holds, not the
/// size of the tables. Nothing switches to System.
///
/// # Errors
///
/// Backend read or decode failures.
pub async fn principal_reach(
    principal: &RecordId,
    owner_edges_count: bool,
    v: &Valence,
) -> anyhow::Result<Reach> {
    let mut reach = Reach::default();
    let mut queue = std::collections::VecDeque::new();
    let mut start = edge_sources(v, "permission_group", MEMBER_EDGE, principal).await?;
    if owner_edges_count {
        start.extend(edge_sources(v, "permission_group", OWNER_EDGE, principal).await?);
    }
    for rid in start {
        queue.push_back((rid.id().to_string(), Vec::new(), true));
    }

    let mut seen = std::collections::HashSet::new();
    while let Some((group_id, below, direct)) = queue.pop_front() {
        if !seen.insert(group_id.clone()) {
            continue;
        }
        let Some(group) = load_row::<PermissionGroup>("permission_group", &group_id, v).await?
        else {
            continue;
        };
        let mut chain = vec![GroupRef {
            id: group_id.clone(),
            name: group.name().clone(),
        }];
        chain.extend(below);
        let as_principal = group_principal_record(&group_id);
        let mut parents = edge_sources(v, "permission_group", MEMBER_EDGE, &as_principal).await?;
        parents.extend(edge_sources(v, "permission_group", OWNER_EDGE, &as_principal).await?);
        for parent in parents {
            queue.push_back((parent.id().to_string(), chain.clone(), false));
        }
        let reached = ReachedGroup {
            group,
            id: group_id,
            chain,
        };
        if direct {
            reach.direct_groups.push(reached.clone());
        }
        reach.groups.push(reached);
    }

    let mut cache: std::collections::HashMap<String, Option<Permission>> =
        std::collections::HashMap::new();
    let mut holders = vec![(principal.clone(), None)];
    holders.extend(
        reach
            .groups
            .iter()
            .enumerate()
            .map(|(index, g)| (group_principal_record(&g.id), Some(index))),
    );
    for (holder, via) in holders {
        for rid in edge_sources(v, "permission", ALLOWED_EDGE, &holder).await? {
            let id = rid.id().to_string();
            if !cache.contains_key(&id) {
                let row = load_row::<Permission>("permission", &id, v).await?;
                cache.insert(id.clone(), row);
            }
            if let Some(Some(permission)) = cache.get(&id) {
                reach.permissions.push((permission.clone(), via));
            }
        }
    }
    Ok(reach)
}

/// The record a service user's principal row has on member and allow-list edges.
pub fn service_user_principal_record(service_user: &ServiceUserId) -> RecordId {
    RecordId::new(
        SERVICE_USER_PRINCIPAL_TABLE,
        service_user_principal_id(service_user),
    )
}

/// Every group that holds `service_user`, sorted by name.
///
/// A group holds the service user when the service user is a member of it, of a group nested in
/// it, or of a group that owns it, the same rule that decides the service user's permissions.
/// The read walks edges backwards from the service user's principal, so its cost follows the
/// groups the service user is in, not how many groups exist.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotFound` when the caller can't see the service user
/// (not its owner and not a manage-any user) or it doesn't exist. An error when the caller isn't
/// a signed-in user. Valence failures otherwise.
pub async fn service_user_groups(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<Vec<ServiceUserGroupDto>> {
    require_visible_service_user(v, service_user).await?;
    let reach = principal_reach(&service_user_principal_record(service_user), false, v).await?;
    let mut out: Vec<ServiceUserGroupDto> =
        reach.groups.iter().map(|g| group_dto(&g.group)).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// Every permission `service_user` holds, each with the group it comes through, sorted by
/// permission name.
///
/// A permission granted to several groups the service user belongs to appears once per group.
/// `via_group` is the group the allow list names; for a nested membership that is the outer
/// group.
/// `via_group` is the group the permission is granted to; a grant made straight to the service
/// user (how an approved on-behalf-of request lands) has `via_group: None`. A service user that is
/// suspended or being deleted holds nothing, so the list is empty.
///
/// # Errors
///
/// As [`service_user_groups`].
pub async fn service_user_effective_permissions(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<Vec<ServiceUserPermissionDto>> {
    require_visible_service_user(v, service_user).await?;
    if !service_user_is_active(v, service_user).await? {
        return Ok(Vec::new());
    }
    let reach = principal_reach(&service_user_principal_record(service_user), false, v).await?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (permission, via) in &reach.permissions {
        let via_group = via.map(|index| group_dto(&reach.groups[index].group));
        let key = (
            model_pk_id(permission.id()),
            via_group.as_ref().map(|g| g.id.clone()),
        );
        if !seen.insert(key) {
            continue;
        }
        out.push(ServiceUserPermissionDto {
            name: permission.name().clone(),
            description: permission.description().cloned().unwrap_or_default(),
            via_group,
        });
    }
    out.sort_by(|a, b| {
        a.name.cmp(&b.name).then_with(|| {
            a.via_group
                .as_ref()
                .map(|g| &g.name)
                .cmp(&b.via_group.as_ref().map(|g| &g.name))
        })
    });
    Ok(out)
}
