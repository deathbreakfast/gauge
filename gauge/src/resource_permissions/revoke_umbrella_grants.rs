//! Revoke standing umbrella group grants for every permission of a resource kind.
//!
//! After [`super::UmbrellaPolicy::None`], new bundles no longer attach kind-wide groups
//! to per-resource permissions. Deployments seeded under the old policy still carry those
//! edges. This helper removes them without touching creators, catalog Create*, other kinds,
//! or per-user grants.

use anyhow::Context;
use log::info;
use valence::{Actor, Model, Valence};

use crate::generated::{Permission, PermissionGroupPrincipal};

use super::ResourceKindDescriptor;

/// Revoke umbrella group grants from every permission whose name starts with `{kind.prefix}.`.
///
/// Idempotent. Safe to re-run.
///
/// # Errors
///
/// Valence / Gauge failures bubble as [`anyhow::Error`].
pub async fn revoke_umbrella_grants(
    v: &Valence,
    kind: impl Into<ResourceKindDescriptor>,
    group_ids: &[&str],
) -> anyhow::Result<usize> {
    let kind = kind.into();
    let system = v.with_actor(Actor::System {
        operation: format!("revoke_umbrella_grants:{}", kind.prefix),
    });

    let prefix = format!("{}.", kind.prefix);
    let permissions = Permission::query(&system).await?;
    let mut revoked = 0usize;

    for permission in permissions {
        let name = permission.name().clone();
        if !name.starts_with(&prefix) {
            continue;
        }
        let Some(perm_id) = permission
            .id()
            .and_then(|r| valence::extract_id_from_record(r).ok())
        else {
            continue;
        };

        for group_id in group_ids {
            if revoke_group_from_permission(&system, &perm_id, group_id).await? {
                revoked += 1;
                info!("[permission] revoked umbrella grant group={group_id} permission={name}");
            }
        }
    }

    info!(
        "[permission] revoke_umbrella_grants kind={} revoked={revoked}",
        kind.prefix
    );
    Ok(revoked)
}

async fn revoke_group_from_permission(
    system: &Valence,
    permission_id: &str,
    group_id: &str,
) -> anyhow::Result<bool> {
    let Some(permission) = Permission::get(permission_id, system).await? else {
        return Ok(false);
    };
    let principal_id = format!("permission_group:{group_id}");
    let Some(principal) = PermissionGroupPrincipal::get(&principal_id, system).await? else {
        return Ok(false);
    };
    let Some(group_principal_rid) = principal.id().cloned() else {
        return Ok(false);
    };

    let allowed = permission.get_allowed_principals_record_ids(system).await?;
    if !allowed.iter().any(|r| r == &group_principal_rid) {
        return Ok(false);
    }

    permission
        .unrelate_from_allowed_principal_record(&group_principal_rid, system)
        .await
        .with_context(|| format!("unrelate {group_id} from permission {permission_id}"))?;
    Ok(true)
}
