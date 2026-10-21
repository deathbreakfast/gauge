//! Remove every member of a permission group in one call.

use lepton_identity::service_users::SERVICE_USER_PREFIX;
use valence::{RecordId, Valence};

use crate::generated::PermissionGroup;
use crate::super_user::SUPER_USER_GROUP_ID;
use crate::types::{HistoryDiffItemDto, PrincipalKind};

use super::helpers::{persist_history_entry, principal_kind_from_record, require_user_id};
use super::membership::group_for_member_edit;
use super::GaugeServiceError;

/// One member edge of a group, with the id an operator would recognise.
struct Member {
    kind: Option<PrincipalKind>,
    /// User id, group id or service user id; the principal row id when the kind is unknown.
    id: String,
    principal: RecordId,
}

/// Remove every member of `group_id` in one call, keeping its owners.
///
/// The caller must own the group (directly or through a group) or be a super user, the same
/// rule as [`remove_group_member_user`](super::remove_group_member_user). Users, nested
/// groups and service users are all removed. Owners are untouched, and so are the members
/// of any nested group. The Super User group is refused. Because an owner counts as holding
/// what the group holds, owners keep the group's grants after a clear.
///
/// Returns the number of member edges removed, one per principal. A group with no members
/// returns `0` and writes nothing.
///
/// One `clear_members` history entry records the removed ids, a diff item each for
/// `member_users`, `member_groups` and `member_service_users` (plus `member_principals` for
/// any member that isn't one of those kinds), so the audit trail shows who
/// lost access just as per-member removals would.
///
/// Removal isn't transactional. If one removal fails, the members already removed stay
/// removed and are recorded in history, and the removal error is returned. If that history
/// write fails too, the returned error carries the history failure as added context, so the
/// caller knows the audit entry is missing. Call the function again to remove the rest.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotAuthorized` when the caller isn't a signed-in
/// user, doesn't own the group, or isn't a super user; `NotFound` for a missing group;
/// `Validation` for the Super User group. Valence failures otherwise.
pub async fn clear_group_members(group_id: &str, v: &Valence) -> anyhow::Result<usize> {
    let actor_user_id = require_user_id(v)?;
    if group_id == SUPER_USER_GROUP_ID {
        return Err(GaugeServiceError::validation(
            "Cannot clear the members of the well-known Super User group",
        )
        .into());
    }
    let group = group_for_member_edit(group_id, &actor_user_id, v).await?;
    let members = collect_members(&group, v).await?;
    let (removed, failure) = unrelate_all(&group, members, v).await;
    let count = removed.len();
    let history = record_clear_history(group_id, &actor_user_id, &removed, v).await;
    match (failure, history) {
        (None, history) => history.map(|()| count),
        (Some(err), Ok(())) => Err(err),
        (Some(err), Err(history_err)) => {
            Err(err.context(format!("history write also failed: {history_err:#}")))
        }
    }
}

async fn collect_members(group: &PermissionGroup, v: &Valence) -> anyhow::Result<Vec<Member>> {
    let edges = group
        .get_members_record_ids(v, valence::use_!(r"When **all members of a permission group are cleared** in **Gauge**, we **read the group's member edges** so we know which users, groups and service users to remove and can list them in the group's history. People who can view the group's history see that list."))
        .await?;
    Ok(edges.into_iter().map(member_from_edge).collect())
}

fn member_from_edge(principal: RecordId) -> Member {
    let kind = principal_kind_from_record(&principal);
    let row_id = principal.id().to_string();
    let prefix = match kind {
        Some(PrincipalKind::User) => "user:",
        Some(PrincipalKind::Group) => "permission_group:",
        Some(PrincipalKind::ServiceUser) => SERVICE_USER_PREFIX,
        None => "",
    };
    let id = row_id.strip_prefix(prefix).unwrap_or(&row_id).to_string();
    Member {
        kind,
        id,
        principal,
    }
}

/// Unrelate members in order and stop at the first failure.
/// Returns the members removed so far and the failure, if any.
async fn unrelate_all(
    group: &PermissionGroup,
    members: Vec<Member>,
    v: &Valence,
) -> (Vec<Member>, Option<anyhow::Error>) {
    let mut removed = Vec::with_capacity(members.len());
    for member in members {
        if let Err(err) = group
            .unrelate_from_member_record(&member.principal, v, valence::use_!(r"When **all members of a permission group are cleared**, we **delete every member edge** so those users, groups and service users no longer inherit the group's grants. Operators see the empty member list on the group detail."))
            .await
        {
            return (removed, Some(err.into()));
        }
        removed.push(member);
    }
    (removed, None)
}

/// Write one history entry listing the removed ids per kind. Nothing is written when
/// nothing was removed.
async fn record_clear_history(
    group_id: &str,
    actor_user_id: &str,
    removed: &[Member],
    v: &Valence,
) -> anyhow::Result<()> {
    let ids_of = |kind: Option<PrincipalKind>| -> Vec<serde_json::Value> {
        removed
            .iter()
            .filter(|m| m.kind == kind)
            .map(|m| serde_json::Value::String(m.id.clone()))
            .collect()
    };
    let fields: Vec<HistoryDiffItemDto> = [
        ("member_users", ids_of(Some(PrincipalKind::User))),
        ("member_groups", ids_of(Some(PrincipalKind::Group))),
        (
            "member_service_users",
            ids_of(Some(PrincipalKind::ServiceUser)),
        ),
        ("member_principals", ids_of(None)),
    ]
    .into_iter()
    .filter(|(_, ids)| !ids.is_empty())
    .map(|(field, ids)| HistoryDiffItemDto {
        field: field.to_string(),
        old_value: serde_json::Value::Array(ids),
        new_value: serde_json::Value::Null,
    })
    .collect();
    if fields.is_empty() {
        return Ok(());
    }
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "clear_members",
        Some(actor_user_id.to_string()),
        fields,
    )
    .await
}
