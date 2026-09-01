//! Privacy-safe permission checks for use inside Valence [`valence::PolicyEvaluator`]s.
//!
//! [`crate::service::actor_can`] is **not** safe to call from a privacy rule:
//! `permissions_named` uses typed `Permission::query`, which re-enters ORM
//! privacy, and [`crate::super_user::actor_is_super_user`] elevates to System.
//! Gauge's own rules already avoid that path — see the comment on
//! `group_has_recursive_member` in [`crate::privacy_policies`].
//!
//! # Caller obligation
//!
//! Use [`actor_can_raw`] (or [`user_can_raw`]) from [`valence::PolicyEvaluator`]s and other
//! contexts that already run under privacy evaluation. Prefer
//! [`crate::service::actor_can`] on ordinary request paths (it records Spectra
//! telemetry and uses the request permission cache).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use valence::{Actor, Valence};

use crate::generated::{
    Permission, PermissionGroup, PermissionGroupPrincipal, PermissionUserPrincipal,
};
use crate::super_user::SUPER_USER_GROUP_ID;

/// Counts [`raw_get_json`] + [`permissions_named_raw`] backend hits (integration tests).
static RAW_READ_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Reset the hidden raw-read counter used by TM-RP-09 bounded-walk tests.
#[doc(hidden)]
pub fn __test_reset_raw_read_count() {
    RAW_READ_COUNT.store(0, Ordering::Relaxed);
}

/// Current value of the hidden raw-read counter (TM-RP-09).
#[doc(hidden)]
pub fn __test_raw_read_count() -> usize {
    RAW_READ_COUNT.load(Ordering::Relaxed)
}

#[inline]
fn note_raw_read() {
    RAW_READ_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Returns `true` when the Valence actor holds `permission_name`, using only
/// raw backend reads and M2M edge walks (no typed ORM privacy re-entry, no
/// System elevate).
///
/// System actors always allow. Missing / anonymous actors deny.
///
/// # Errors
///
/// Propagates backend read / decode failures.
pub async fn actor_can_raw(v: &Valence, permission_name: &str) -> anyhow::Result<bool> {
    let actor = v.actor();
    if actor.is_system() {
        return Ok(true);
    }
    let Some(user_id) = actor.user_id() else {
        return Ok(false);
    };
    if actor_in_super_user_group_raw(actor, v).await? {
        return Ok(true);
    }
    user_can_raw(v, user_id, permission_name).await
}

/// Like [`actor_can_raw`] for an explicit user id (no Super User / System short-circuit
/// beyond what the grant graph itself confers).
///
/// # Errors
///
/// Propagates backend read / decode failures.
pub async fn user_can_raw(
    v: &Valence,
    user_id: &str,
    permission_name: &str,
) -> anyhow::Result<bool> {
    let permission_name = permission_name.trim();
    if permission_name.is_empty() {
        return Ok(false);
    }
    let user_ids = user_id_candidates(user_id);
    let permissions = permissions_named_raw(permission_name, v).await?;
    for permission in permissions {
        if permission_allows_user_raw(&permission, &user_ids, v).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn user_id_candidates(user_id: &str) -> Vec<String> {
    let mut out = vec![user_id.to_string()];
    if let Some((_, bare)) = user_id.split_once(':') {
        out.push(bare.to_string());
    }
    let bare = user_id.strip_prefix("user:").unwrap_or(user_id);
    if bare != user_id {
        out.push(bare.to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn model_pk_id(opt: Option<&valence::RecordId>) -> String {
    opt.and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default()
}

async fn raw_get_json(
    table: &str,
    id: &str,
    v: &Valence,
) -> anyhow::Result<Option<serde_json::Value>> {
    note_raw_read();
    let backend = v
        .backend_for_table(table)
        .map_err(|e| anyhow::anyhow!("resolve {table} backend: {e}"))?;
    backend
        .get_record(table, id)
        .await
        .map_err(|e| anyhow::anyhow!("read {table}: {e}"))
}

async fn permissions_named_raw(name: &str, v: &Valence) -> anyhow::Result<Vec<Permission>> {
    note_raw_read();
    let backend = v
        .backend_for_table("permission")
        .map_err(|e| anyhow::anyhow!("resolve permission backend: {e}"))?;
    let rows = backend
        .execute_compiled_query(&valence::__internal::CompiledQuery {
            query_string: "SELECT * FROM permission WHERE name = $name".to_string(),
            params: vec![("name".to_string(), serde_json::json!(name))],
        })
        .await
        .map_err(|e| anyhow::anyhow!("query permission by name (raw): {e}"))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(
            serde_json::from_value(row)
                .map_err(|e| anyhow::anyhow!("decode permission (raw): {e}"))?,
        );
    }
    Ok(out)
}

async fn permission_allows_user_raw(
    permission: &Permission,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    for principal_thing in permission.get_allowed_principals_record_ids(v).await? {
        let principal_id = principal_thing.id().to_string();
        match principal_thing.table() {
            "permission_user_principal" => {
                if let Some(row) =
                    raw_get_json("permission_user_principal", &principal_id, v).await?
                {
                    let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                    let allowed_user_id =
                        valence::extract_id_from_record(principal.user()).unwrap_or_default();
                    if user_ids.iter().any(|id| id == &allowed_user_id) {
                        return Ok(true);
                    }
                }
            }
            "permission_group_principal" => {
                if let Some(row) =
                    raw_get_json("permission_group_principal", &principal_id, v).await?
                {
                    let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                    let group_id =
                        valence::extract_id_from_record(principal.group()).unwrap_or_default();
                    if let Some(row) = raw_get_json("permission_group", &group_id, v).await? {
                        let group: PermissionGroup = serde_json::from_value(row)?;
                        if group_has_user_raw(&group, user_ids, v).await? {
                            return Ok(true);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

async fn group_has_user_raw(
    group: &PermissionGroup,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = HashSet::new();
    let mut queue = vec![group.clone()];

    while let Some(current) = queue.pop() {
        let current_id = model_pk_id(current.id());
        if !visited.insert(current_id) {
            continue;
        }

        for owner in current.get_owners_record_ids(v).await? {
            if principal_is_user_match(&owner, user_ids, v, &mut queue).await? {
                return Ok(true);
            }
        }
        for member in current.get_members_record_ids(v).await? {
            if principal_is_user_match(&member, user_ids, v, &mut queue).await? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn principal_is_user_match(
    principal_rid: &valence::RecordId,
    user_ids: &[String],
    v: &Valence,
    queue: &mut Vec<PermissionGroup>,
) -> anyhow::Result<bool> {
    let record_pk = principal_rid.id().to_string();
    match principal_rid.table() {
        "permission_user_principal" => {
            if let Some(row) = raw_get_json("permission_user_principal", &record_pk, v).await? {
                let principal: PermissionUserPrincipal = serde_json::from_value(row)?;
                let uid = valence::extract_id_from_record(principal.user()).unwrap_or_default();
                if user_ids.iter().any(|id| id == &uid) {
                    return Ok(true);
                }
            }
        }
        "permission_group_principal" => {
            if let Some(row) = raw_get_json("permission_group_principal", &record_pk, v).await? {
                let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
                let group_id =
                    valence::extract_id_from_record(principal.group()).unwrap_or_default();
                if let Some(row) = raw_get_json("permission_group", &group_id, v).await? {
                    queue.push(serde_json::from_value(row)?);
                }
            }
        }
        _ => {}
    }
    Ok(false)
}

async fn actor_in_super_user_group_raw(actor: &Actor, v: &Valence) -> anyhow::Result<bool> {
    let user_ids = match actor.user_id() {
        Some(uid) => user_id_candidates(uid),
        None => return Ok(false),
    };
    let Some(row) = raw_get_json("permission_group", SUPER_USER_GROUP_ID, v).await? else {
        return Ok(false);
    };
    let group: PermissionGroup = serde_json::from_value(row)?;
    group_has_user_raw(&group, &user_ids, v).await
}
