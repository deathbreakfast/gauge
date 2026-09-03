use chrono::Utc;
use valence::{Model, Valence};

use crate::generated::PermissionGroup;
use crate::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID, SUPER_USER_GROUP_NAME};
use crate::types::{HistoryDiffItemDto, PermissionGroupCreateInput};

use super::helpers::{
    ensure_group_principal, ensure_user_principal, get_group_raw, get_user_by_actor_id,
    group_has_owner_user, groups_named, persist_history_entry, record_pk_id, require_model_id,
    require_user_id, user_id_candidates,
};

/// Create a new permission group, making the current actor its initial owner and member.
pub async fn create_group(
    input: PermissionGroupCreateInput,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(super::GaugeServiceError::validation("Group name is required").into());
    }
    if name == SUPER_USER_GROUP_NAME {
        anyhow::bail!(
            "Group name '{SUPER_USER_GROUP_NAME}' is reserved for the well-known super-user group"
        );
    }
    if !groups_named(&name, system).await?.is_empty() {
        return Err(super::GaugeServiceError::validation(format!(
            "Permission group name already exists: {name}"
        ))
        .into());
    }

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
    let created = PermissionGroup::create(group, system).await?;

    let lookup = v;
    if let Some(user) = get_user_by_actor_id(&actor_user_id, lookup).await? {
        // One principal for both owner + member relates. Re-fetching the principal
        // after the first trait-targeted relate can fail to deserialize trait
        // fields (`source_id`) under L0 in-memory/SQLite readback.
        let principal = ensure_user_principal(&record_pk_id(user.id()), lookup).await?;
        let principal_id = require_model_id(principal.id(), "principal")?;
        created
            .relate_to_owner_record(&principal_id, lookup)
            .await?;
        created
            .relate_to_member_record(&principal_id, lookup)
            .await?;
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
        .get_mutable(v)
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
    group
        .relate_to_owner_record(&require_model_id(principal.id(), "principal")?, system)
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
        .get_owners_record_ids(system)
        .await?
        .into_iter()
        .map(|rid| rid.id().to_string())
        .collect::<Vec<_>>();
    let target_principal_id =
        valence::extract_id_from_record(&require_model_id(principal.id(), "principal")?)
            .unwrap_or_default();
    let target_is_owner = owner_ids.iter().any(|id| id == &target_principal_id);
    if target_is_owner && owner_ids.len() <= 1 {
        return Err(super::GaugeServiceError::validation(
            "Cannot remove the last owner from a group",
        )
        .into());
    }

    group
        .unrelate_from_owner_record(&require_model_id(principal.id(), "principal")?, system)
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
    group
        .relate_to_member_record(&require_model_id(principal.id(), "principal")?, system)
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
    group
        .unrelate_from_member_record(&require_model_id(principal.id(), "principal")?, system)
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
    group
        .relate_to_member_record(&require_model_id(principal.id(), "principal")?, system)
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
    group
        .unrelate_from_member_record(&require_model_id(principal.id(), "principal")?, system)
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
