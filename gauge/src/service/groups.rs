use chrono::Utc;
use valence::{Model, RecordId, Valence};

use crate::generated::PermissionGroup;
use crate::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
use crate::types::{HistoryDiffItemDto, PermissionGroupCreateInput};

use super::helpers::{
    ensure_group_principal, ensure_user_principal, get_group_raw, get_user_by_actor_id,
    group_has_member_principal, group_has_owner_principal, group_has_owner_user, groups_named,
    persist_history_entry, record_pk_id, require_model_id, require_user_id, user_id_candidates,
};

/// Which edges the creator gets on a group they create.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateMode {
    OwnerAndMember,
    OwnerOnly,
}

/// Create a new permission group, making the current actor its initial owner and member.
///
/// To own a group without belonging to it, use [`create_group_owner_only`].
///
/// # Errors
///
/// [`GaugeServiceError`](super::GaugeServiceError) (via `anyhow`): `Validation` for an
/// empty name, the reserved Super User group name, or a name that already exists. A caller
/// that isn't a signed-in user is refused. Valence failures otherwise.
pub async fn create_group(
    input: PermissionGroupCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    create_group_with(input, CreateMode::OwnerAndMember, v).await
}

/// Create a group the caller owns but does not belong to.
///
/// Use this when the caller wants to manage a group without inheriting what the group
/// holds, for example a host that creates a group on behalf of a team and later empties it
/// with [`clear_group_members`](super::clear_group_members) when the team is archived.
/// [`create_group`] also writes the member edge for the caller; this does not, so the new
/// group starts with the caller as its only owner and no members. The owner can still add
/// members. Gauge treats an owner as holding what the group holds, so the caller keeps the
/// group's grants; only the member listing differs.
///
/// ```ignore
/// let group = service::create_group_owner_only(input, &v).await?;
/// service::add_group_member_user(&id, "alice", &v).await?;
/// // Later, when the team is archived:
/// let removed = service::clear_group_members(&id, &v).await?;
/// ```
///
/// # Errors
///
/// [`GaugeServiceError`](super::GaugeServiceError) (via `anyhow`):
///
/// - `NotAuthorized`: the caller has no user record to own the group with (a service user,
///   say). Nothing is saved.
/// - `Validation`: an empty, reserved or already used name, as for [`create_group`].
/// - A caller that isn't a signed-in user is refused before anything is saved.
pub async fn create_group_owner_only(
    input: PermissionGroupCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    create_group_with(input, CreateMode::OwnerOnly, v).await
}

/// Resolve the creator's principal before anything is saved, so an owner-only create that
/// can't name an owner leaves no ownerless group behind. `None` only for
/// [`CreateMode::OwnerAndMember`], which keeps creating a group when the actor has no user row.
async fn resolve_creator_principal(
    actor_user_id: &str,
    mode: CreateMode,
    v: &Valence,
) -> anyhow::Result<Option<RecordId>> {
    match get_user_by_actor_id(actor_user_id, v).await? {
        // One principal for both owner + member relates. Re-fetching the principal
        // after the first trait-targeted relate can fail to deserialize trait
        // fields (`source_id`) under L0 in-memory/SQLite readback.
        Some(user) => {
            let principal = ensure_user_principal(&record_pk_id(user.id()), v).await?;
            Ok(Some(require_model_id(principal.id(), "principal")?))
        }
        None if mode == CreateMode::OwnerOnly => {
            Err(super::GaugeServiceError::not_authorized("create group as owner").into())
        }
        None => Ok(None),
    }
}

async fn create_group_with(
    input: PermissionGroupCreateInput,
    mode: CreateMode,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(super::GaugeServiceError::validation("Group name is required").into());
    }
    if name == SUPER_USER_GROUP_NAME {
        return Err(super::GaugeServiceError::validation(format!(
            "Group name '{SUPER_USER_GROUP_NAME}' is reserved for the well-known super-user group"
        ))
        .into());
    }
    if !groups_named(&name, system).await?.is_empty() {
        return Err(super::GaugeServiceError::validation(format!(
            "Permission group name already exists: {name}"
        ))
        .into());
    }

    let principal_id = resolve_creator_principal(&actor_user_id, mode, v).await?;

    let now = Utc::now();
    let group = PermissionGroup::new(
        name,
        if input.description.trim().is_empty() {
            None
        } else {
            Some(input.description)
        },
        now,
        now,
    )?;
    let created = PermissionGroup::create(group, system, valence::use_!(r"When a **permission group is created** in **Gauge**, we **save the group's name and description and when it was created** so it can own permissions and receive grants. Owners and operators see the group on its detail page in group management.")).await?;

    if let Some(principal_id) = principal_id {
        created
            .relate_to_owner_record(&principal_id, system, valence::use_!(r"When a **permission group is created** in **Gauge**, we **write an owner edge** from the new group to its creator so the creator can edit it and approve requests for it. Owners see themselves on the group detail."))
            .await?;
        if mode == CreateMode::OwnerAndMember {
            created
                .relate_to_member_record(&principal_id, system, valence::use_!(r"When a **permission group is created** with its creator as a member, we **write a member edge** from the new group to the creator so they inherit what the group holds. Members see the group on the group detail."))
                .await?;
        }
    }

    Ok(created)
}

/// Update a group's name/description (owner or super-user only) and record history
/// for any changed fields.
pub async fn update_group(
    id: &str,
    name: String,
    description: String,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let existing = get_group_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission group", id))?;
    if !group_has_owner_user(&existing, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group").into());
    }

    let next_name = name.trim().to_string();
    if next_name == SUPER_USER_GROUP_NAME && id != SUPER_USER_GROUP_ID {
        anyhow::bail!(
            "Group name '{SUPER_USER_GROUP_NAME}' is reserved for the well-known super-user group"
        );
    }
    if id == SUPER_USER_GROUP_ID && next_name != SUPER_USER_GROUP_NAME {
        anyhow::bail!(
            "Cannot rename the well-known super-user group away from '{SUPER_USER_GROUP_NAME}'"
        );
    }

    let desc = if description.trim().is_empty() {
        None
    } else {
        Some(description)
    };
    // get_mutable keeps record id for owner privacy policies (upsert of a new()
    // model without id fails GROUP_OWNER_RECURSIVE).
    let mut builder = existing
        .get_mutable(v, valence::use_!(r"In **Gauge permissions**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **Gauge permissions** use the updated data; this is not a public export of unrelated fields."))
        .set_name(next_name)?
        .set_updated_at(Utc::now())?;
    builder = match desc {
        Some(d) => builder.set_description(d)?,
        None => builder,
    };
    let saved = builder.commit().await?;
    // Field-level history is appended by PermissionHistoryWriter side effect.
    Ok(saved)
}

/// Delete a group (owner or super-user only).
pub async fn delete_group(id: &str, v: &Valence) -> anyhow::Result<()> {
    if id == SUPER_USER_GROUP_ID {
        return Err(super::GaugeServiceError::validation(
            "Cannot delete the well-known Super User group",
        )
        .into());
    }
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let existing = get_group_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission group", id))?;
    if !group_has_owner_user(&existing, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("delete group").into());
    }
    crate::side_effects::history_logger::delete_history_source("permission_group", id, v).await?;
    Ok(())
}

/// Add `user_id` as an owner of `group_id` (owner or super-user only) and record history.
pub async fn add_group_owner_user(
    group_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group ownership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    let principal_id = require_model_id(principal.id(), "principal")?;
    if group_has_owner_principal(&group, &principal_id, system).await? {
        return Ok(());
    }
    group
        .relate_to_owner_record(&principal_id, system, valence::use_!(r"When an operator **adds a group owner** in **Gauge**, we **write the owner edge** from the permission group to that principal so later checks know who can approve and edit. Operators see the updated owners on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "add_owner_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "owner_users".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(user_id.to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Remove `user_id` as an owner of `group_id` (owner or super-user only); fails if
/// it would remove the group's last owner. Records history.
pub async fn remove_group_owner_user(
    group_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group ownership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    let owner_ids = group
        .get_owners_record_ids(system, valence::use_!(r"When **Gauge** needs the **owners of a permission group**, we **follow the owner edges** so the product can show owners on the group detail or decide who may edit. Editors see that list; access checks use it only to allow or deny."))
        .await?
        .into_iter()
        .map(|rid| rid.id().to_string())
        .collect::<Vec<_>>();
    let target_principal_id =
        valence::extract_id_from_record(&require_model_id(principal.id(), "principal")?)
            .unwrap_or_default();
    let target_is_owner = owner_ids.iter().any(|id| id == &target_principal_id);
    if !target_is_owner {
        return Ok(());
    }
    if owner_ids.len() <= 1 {
        return Err(super::GaugeServiceError::validation(
            "Cannot remove the last owner from a group",
        )
        .into());
    }

    group
        .unrelate_from_owner_record(&require_model_id(principal.id(), "principal")?, system, valence::use_!(r"When an operator **removes a group owner** in **Gauge**, we **delete the owner edge** so that principal no longer counts as an owner for approvals and edits. Operators see the updated owners on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "remove_owner_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "owner_users".to_string(),
            old_value: serde_json::Value::String(user_id.to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}

/// Add `user_id` as a member of `group_id` (owner or super-user only) and record history.
pub async fn add_group_member_user(
    group_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group membership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    let principal_id = require_model_id(principal.id(), "principal")?;
    if group_has_member_principal(&group, &principal_id, system).await? {
        return Ok(());
    }
    group
        .relate_to_member_record(&principal_id, system, valence::use_!(r"When an operator **adds a group member** in **Gauge**, we **write the member edge** so that principal inherits the group's grants. Operators see the updated members on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "add_member_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_users".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(user_id.to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Remove `user_id` as a member of `group_id` (owner or super-user only) and record history.
pub async fn remove_group_member_user(
    group_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group membership").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    let principal_id = require_model_id(principal.id(), "principal")?;
    if !group_has_member_principal(&group, &principal_id, system).await? {
        return Ok(());
    }
    group
        .unrelate_from_member_record(&principal_id, system, valence::use_!(r"When an operator **removes a group member** in **Gauge**, we **delete the member edge** so that principal no longer inherits through this group. Operators see the updated members on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "remove_member_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_users".to_string(),
            old_value: serde_json::Value::String(user_id.to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}

/// Add `child_group_id` as a nested member group of `group_id` (owner or super-user
/// only); fails if `group_id == child_group_id`. Records history.
pub async fn add_group_member_group(
    group_id: &str,
    child_group_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    if group_id == SUPER_USER_GROUP_ID || child_group_id == SUPER_USER_GROUP_ID {
        return Err(super::GaugeServiceError::validation(
            "Cannot nest the well-known Super User group as a parent or child",
        )
        .into());
    }
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group membership").into());
    }
    if group_id == child_group_id {
        return Err(
            super::GaugeServiceError::validation("Group cannot be a member of itself").into(),
        );
    }

    let principal = ensure_group_principal(child_group_id, system).await?;
    let principal_id = require_model_id(principal.id(), "principal")?;
    if group_has_member_principal(&group, &principal_id, system).await? {
        return Ok(());
    }
    group
        .relate_to_member_record(&principal_id, system, valence::use_!(r"When an operator **adds a group member** in **Gauge**, we **write the member edge** so that principal inherits the group's grants. Operators see the updated members on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "add_member_group",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_groups".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(child_group_id.to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Remove `child_group_id` as a nested member group of `group_id` (owner or
/// super-user only). Records history.
pub async fn remove_group_member_group(
    group_id: &str,
    child_group_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    if group_id == SUPER_USER_GROUP_ID || child_group_id == SUPER_USER_GROUP_ID {
        return Err(super::GaugeServiceError::validation(
            "Cannot nest the well-known Super User group as a parent or child",
        )
        .into());
    }
    let actor_user_id = require_user_id(v)?;
    let actor_candidates = user_id_candidates(&actor_user_id);
    let system = v;
    let group = get_group_raw(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission group not found: {group_id}"))?;
    if !group_has_owner_user(&group, &actor_candidates, system).await?
        && !actor_is_super_user(v).await?
    {
        return Err(super::GaugeServiceError::not_authorized("edit group membership").into());
    }

    let principal = ensure_group_principal(child_group_id, system).await?;
    let principal_id = require_model_id(principal.id(), "principal")?;
    if !group_has_member_principal(&group, &principal_id, system).await? {
        return Ok(());
    }
    group
        .unrelate_from_member_record(&principal_id, system, valence::use_!(r"When an operator **removes a group member** in **Gauge**, we **delete the member edge** so that principal no longer inherits through this group. Operators see the updated members on the group detail."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "remove_member_group",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_groups".to_string(),
            old_value: serde_json::Value::String(child_group_id.to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}
