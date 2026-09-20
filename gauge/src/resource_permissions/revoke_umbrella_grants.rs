//! Revoke standing umbrella group grants for every permission of a resource kind.
//!
//! After [`super::UmbrellaPolicy::None`], new bundles no longer attach kind-wide groups
//! to per-resource permissions. Deployments seeded under the old policy still carry those
//! edges. This helper removes them without touching creators, catalog Create*, other kinds,
//! or per-user grants.
//!
//! Callers must already be `Actor::System` (Chronon / bootstrap). This helper does **not**
//! elevate a session Valence to System.

use anyhow::{bail, Context};
use log::info;
use valence::Model;

use crate::generated::{Permission, PermissionGroupPrincipal};

use super::ResourceKindDescriptor;

/// Revoke umbrella group grants from every permission whose name starts with `{kind.prefix}.`.
///
/// Idempotent. Safe to re-run. Requires a System Valence actor (no mid-request elevate).
///
/// # Errors
///
/// Returns an error when the caller is not System, or when Valence / Gauge fails.
pub async fn revoke_umbrella_grants(
    v: &valence::Valence,
    kind: impl Into<ResourceKindDescriptor>,
    group_ids: &[&str],
) -> anyhow::Result<usize> {
    if !v.actor().is_system() {
        bail!("revoke_umbrella_grants requires System actor (Chronon/bootstrap)");
    }
    let kind = kind.into();

    let prefix = format!("{}.", kind.prefix);
    let permissions = Permission::query_used(v, valence::use_!(r"In **Gauge permissions**, we **list Permission** so the product can show or process the matching set for this workflow. Callers allowed for **Gauge permissions** use the list; it is not a public dump of every field to anonymous visitors.")).await?;
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
            if revoke_group_from_permission(v, &perm_id, group_id).await? {
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
    system: &valence::Valence,
    permission_id: &str,
    group_id: &str,
) -> anyhow::Result<bool> {
    let Some(permission) = Permission::get_used(permission_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await? else {
        return Ok(false);
    };
    let principal_id = format!("permission_group:{group_id}");
    let Some(principal) = PermissionGroupPrincipal::get_used(&principal_id, system, valence::use_!(r"In **Gauge permissions**, we **load Permission Group Principal** so the application can decide what to do next in this workflow. The result is used by **Gauge permissions** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await? else {
        return Ok(false);
    };
    let Some(group_principal_rid) = principal.id().cloned() else {
        return Ok(false);
    };

    let allowed = permission.get_allowed_principals_record_ids_used(system, valence::use_!(r#"When **Gauge** checks or shows **who holds a permission**, we **follow the allowed-principal edges** so the product can build the allow list or decide whether you already have access. Editors see that list; permission checks use it only to allow or deny."#)).await?;
    if !allowed.iter().any(|r| r == &group_principal_rid) {
        return Ok(false);
    }

    permission
        .unrelate_from_allowed_principal_record_used(&group_principal_rid, system, valence::use_!(r#"When an operator **revokes a permission** in **Gauge**, we **delete the allowed-principal edge** so that user or group no longer holds the grant. Operators see the updated allow list on the permission detail."#))
        .await
        .with_context(|| format!("unrelate {group_id} from permission {permission_id}"))?;
    Ok(true)
}
