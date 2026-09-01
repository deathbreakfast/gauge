use chrono::Utc;
use valence::{Model, RecordId, Valence};

use crate::generated::{Permission, PermissionGroup};
use crate::types::{
    HistoryDiffItemDto, PermissionCreateInput, PermissionDetailDto, PermissionGroupDetailDto,
};

use super::access::{can_edit_group, can_edit_permission, permission_allows_user};
use super::helpers::{
    current_user_id, ensure_group_principal, ensure_user_principal, get_domain_raw, get_group_raw,
    get_permission_raw, get_user_by_actor_id, group_has_user, permissions_named,
    persist_history_entry, principal_ref_from_record, record_pk_id, redact_user_principal_label,
    require_actor_controls_owner_group, require_model_id, require_raw_record, require_user_id,
    resolve_or_create_default_owner_group, user_id_candidates,
};

/// Create a new permission under the given domain and owners group (or the actor's
/// default owner group when `owners_group_id` is empty).
pub async fn create_permission(
    input: PermissionCreateInput,
    v: &Valence,
) -> anyhow::Result<Permission> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(super::GaugeServiceError::validation("Permission name is required").into());
    }
    if !permissions_named(&name, system).await?.is_empty() {
        return Err(super::GaugeServiceError::validation(format!(
            "Permission name already exists: {name}"
        ))
        .into());
    }

    let owner_group_id = if input.owners_group_id.trim().is_empty() {
        let group = resolve_or_create_default_owner_group(&actor_user_id, system).await?;
        record_pk_id(group.id())
    } else {
        let supplied = input.owners_group_id.trim().to_string();
        require_actor_controls_owner_group(&supplied, v).await?;
        supplied
    };
    // Prefer raw existence checks: typed `get` can fail to deserialize trait fields
    // (`name`) via the ownership/read-cache path even when the stored row is complete.
    require_raw_record("permission_group", &owner_group_id, system).await?;
    require_raw_record("permission_domain", input.domain_id.trim(), system).await?;

    let created_by = get_user_by_actor_id(&actor_user_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Actor user not found: {actor_user_id}"))?;

    let now = Utc::now();
    let permission = Permission::new(
        require_model_id(created_by.id(), "created_by")?,
        RecordId::new("permission_group", &owner_group_id),
        RecordId::new("permission_domain", input.domain_id.trim()),
        name,
        if input.description.trim().is_empty() {
            None
        } else {
            Some(input.description)
        },
        now,
        now,
    )?;

    let created = Permission::create(permission, system).await?;
    Ok(created)
}

/// Update a permission's name/description/owners group/domain (owner or super-user
/// only) and record history for any changed fields.
pub async fn update_permission(
    id: &str,
    name: String,
    description: String,
    owners_group_id: String,
    domain_id: String,
    v: &Valence,
) -> anyhow::Result<Permission> {
    let _actor_user_id = require_user_id(v)?;
    let system = v;
    let existing = get_permission_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission", id))?;
    if !can_edit_permission(&existing, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit permission").into());
    }

    require_actor_controls_owner_group(owners_group_id.trim(), v).await?;

    let next_owners_group = get_group_raw(owners_group_id.trim(), system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Owner group not found: {owners_group_id}"))?;
    let domain = get_domain_raw(&domain_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission domain not found: {domain_id}"))?;
    let next_owners_group_id = next_owners_group
        .id()
        .ok_or_else(|| anyhow::anyhow!("Owner group id missing: {owners_group_id}"))?
        .clone();
    let domain_record_id = domain
        .id()
        .ok_or_else(|| anyhow::anyhow!("Permission domain id missing: {domain_id}"))?
        .clone();

    let desc = if description.trim().is_empty() {
        String::new()
    } else {
        description
    };
    let saved = existing
        .get_mutable(v)
        .set_owners_group(next_owners_group_id)?
        .set_domain(domain_record_id)?
        .set_name(name)?
        .set_description(desc)?
        .set_updated_at(Utc::now())?
        .commit()
        .await?;
    // Field-level history is appended by PermissionHistoryWriter side effect.
    Ok(saved)
}

/// Delete a permission (owner or super-user only).
pub async fn delete_permission(id: &str, v: &Valence) -> anyhow::Result<()> {
    let _actor_user_id = require_user_id(v)?;
    let system = v;
    let existing = get_permission_raw(id, system)
        .await?
        .ok_or_else(|| super::GaugeServiceError::not_found("Permission", id))?;
    if !can_edit_permission(&existing, v).await? {
        return Err(super::GaugeServiceError::not_authorized("delete permission").into());
    }
    crate::side_effects::history_logger::delete_history_source("permission", id, v).await?;
    Ok(())
}

/// Grant `permission_id` directly to `user_id` (owner or super-user only). Records history.
pub async fn grant_permission_to_user(
    permission_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let permission = get_permission_raw(permission_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission not found: {permission_id}"))?;
    if !can_edit_permission(&permission, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit permission").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    permission
        .relate_to_allowed_principal_record(&require_model_id(principal.id(), "principal")?, system)
        .await?;
    persist_history_entry(
        v,
        "permission",
        permission_id.to_string(),
        "grant_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "granted_users".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(user_id.to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Revoke `permission_id` from `user_id` (owner or super-user only). Records history.
pub async fn revoke_permission_from_user(
    permission_id: &str,
    user_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let permission = get_permission_raw(permission_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission not found: {permission_id}"))?;
    if !can_edit_permission(&permission, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit permission").into());
    }

    let principal = ensure_user_principal(user_id, system).await?;
    permission
        .unrelate_from_allowed_principal_record(
            &require_model_id(principal.id(), "principal")?,
            system,
        )
        .await?;
    persist_history_entry(
        v,
        "permission",
        permission_id.to_string(),
        "revoke_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "granted_users".to_string(),
            old_value: serde_json::Value::String(user_id.to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}

/// Grant `permission_id` to every member of `group_id` (owner or super-user only).
/// Records history.
pub async fn grant_permission_to_group(
    permission_id: &str,
    group_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let permission = get_permission_raw(permission_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission not found: {permission_id}"))?;
    if !can_edit_permission(&permission, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit permission").into());
    }

    let principal = ensure_group_principal(group_id, system).await?;
    permission
        .relate_to_allowed_principal_record(&require_model_id(principal.id(), "principal")?, system)
        .await?;
    persist_history_entry(
        v,
        "permission",
        permission_id.to_string(),
        "grant_group",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "granted_groups".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(group_id.to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Revoke `permission_id` from `group_id` (owner or super-user only). Records history.
pub async fn revoke_permission_from_group(
    permission_id: &str,
    group_id: &str,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let system = v;
    let permission = get_permission_raw(permission_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission not found: {permission_id}"))?;
    if !can_edit_permission(&permission, v).await? {
        return Err(super::GaugeServiceError::not_authorized("edit permission").into());
    }

    let principal = ensure_group_principal(group_id, system).await?;
    permission
        .unrelate_from_allowed_principal_record(
            &require_model_id(principal.id(), "principal")?,
            system,
        )
        .await?;
    persist_history_entry(
        v,
        "permission",
        permission_id.to_string(),
        "revoke_group",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "granted_groups".to_string(),
            old_value: serde_json::Value::String(group_id.to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}

/// Load a single permission's detail view (allow-list, domain context, and whether
/// the current actor may request access), or `None` if it does not exist.
pub async fn get_permission_detail(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    let Some(permission) = get_permission_raw(id, v).await? else {
        return Ok(None);
    };

    let reveal_sensitive = can_edit_permission(&permission, v).await?;
    let system = v;

    // Grant graph is editor-only. Outsiders still see the permission row
    // (browsable for access requests) but not who already holds it.
    let mut allow_list = Vec::new();
    if reveal_sensitive {
        let mut seen = std::collections::HashSet::new();
        for principal in permission.get_allowed_principals_record_ids(v).await? {
            if let Some(reference) = principal_ref_from_record(&principal, v).await? {
                let key = format!("{:?}:{}", reference.kind, reference.id);
                if seen.insert(key) {
                    allow_list.push(redact_user_principal_label(reference, true));
                }
            }
        }
    }

    let can_request_access = if let Some(actor_user_id) = current_user_id(v) {
        !permission_allows_user(&permission, &user_id_candidates(&actor_user_id), system).await?
    } else {
        false
    };
    let domain_id = valence::extract_id_from_record(permission.domain()).unwrap_or_default();
    let domain = get_domain_raw(&domain_id, v)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Permission domain not found: {domain_id}"))?;

    Ok(Some(PermissionDetailDto {
        id: record_pk_id(permission.id()),
        name: permission.name().clone(),
        description: permission.description().cloned().unwrap_or_default(),
        created_by_user_id: valence::extract_id_from_record(permission.created_by())
            .unwrap_or_default(),
        owners_group_id: valence::extract_id_from_record(permission.owners_group())
            .unwrap_or_default(),
        domain_id: record_pk_id(domain.id()),
        domain_name: domain.name().clone(),
        allow_list,
        can_request_access,
    }))
}

/// Load a single group's detail view (owners, members, and whether the current
/// actor may request access), or `None` if it does not exist.
pub async fn get_group_detail(
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<PermissionGroupDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    let Some(group) = get_group_raw(id, v).await? else {
        return Ok(None);
    };

    let reveal_sensitive = can_edit_group(&group, v).await?;
    let system = v;

    // Owners and members are editor-only — same grant-graph posture as
    // `allow_list` on permissions.
    let mut owner_users = Vec::new();
    let mut members = Vec::new();
    if reveal_sensitive {
        let mut owner_seen = std::collections::HashSet::new();
        for owner in group.get_owners_record_ids(v).await? {
            if let Some(reference) = principal_ref_from_record(&owner, v).await? {
                let key = format!("{:?}:{}", reference.kind, reference.id);
                if owner_seen.insert(key) {
                    owner_users.push(redact_user_principal_label(reference, true));
                }
            }
        }

        let mut member_seen = std::collections::HashSet::new();
        for principal in group.get_members_record_ids(v).await? {
            if let Some(reference) = principal_ref_from_record(&principal, v).await? {
                let key = format!("{:?}:{}", reference.kind, reference.id);
                if member_seen.insert(key) {
                    members.push(redact_user_principal_label(reference, true));
                }
            }
        }
    }

    let can_request_access = if let Some(actor_user_id) = current_user_id(v) {
        !group_has_user(&group, &user_id_candidates(&actor_user_id), system).await?
    } else {
        false
    };

    Ok(Some(PermissionGroupDetailDto {
        id: record_pk_id(group.id()),
        name: group.name().clone(),
        description: group.description().cloned().unwrap_or_default(),
        owner_users,
        members,
        can_request_access,
    }))
}

/// List permission detail views, optionally filtered by a name/description-contains
/// `search` term (case-insensitive).
pub async fn list_permissions(
    v: &Valence,
    search: Option<String>,
) -> anyhow::Result<Vec<PermissionDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    // Post-filter like [`list_domains`] / [`list_groups`]: Valence `Contains` +
    // `union` against the in-memory engine can return empty for clear matches.
    let needle = search
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    let mut out = Vec::new();
    for permission in Permission::query(v).await? {
        if let Some(ref needle) = needle {
            let name = permission.name().to_lowercase();
            let description = permission
                .description()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();
            if !name.contains(needle) && !description.contains(needle) {
                continue;
            }
        }
        if let Some(detail) = get_permission_detail(&record_pk_id(permission.id()), v).await? {
            out.push(detail);
        }
    }
    Ok(out)
}

/// List group detail views, optionally filtered by a name/description-contains
/// `search` term (case-insensitive).
pub async fn list_groups(
    v: &Valence,
    search: Option<String>,
) -> anyhow::Result<Vec<PermissionGroupDetailDto>> {
    let _actor_user_id = require_user_id(v)?;
    // Post-filter like [`list_domains`]: Valence `Contains` + `union` against the
    // in-memory engine can return empty for groups that clearly match.
    let needle = search
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    let mut out = Vec::new();
    for group in PermissionGroup::query(v).await? {
        if let Some(ref needle) = needle {
            let name = group.name().to_lowercase();
            let description = group
                .description()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();
            if !name.contains(needle) && !description.contains(needle) {
                continue;
            }
        }
        if let Some(detail) = get_group_detail(&record_pk_id(group.id()), v).await? {
            out.push(detail);
        }
    }
    Ok(out)
}
