//! One-shot revoke of NeutrinoSecret umbrella grant edges.
//!
//! After [`crate::resource_permissions::UmbrellaPolicy::None`] for
//! `NeutrinoSecret`, new bundles no longer grant `neutrino.secret.viewers` /
//! `.operators`. Existing deployments still have those edges from earlier
//! ensures. This script removes them without touching creators, catalog
//! Create*, other kinds, or per-user grants.

use anyhow::Context;
use log::info;
use valence::{Actor, Model, Valence};

use crate::generated::{Permission, PermissionGroupPrincipal};
use crate::resource_permissions::ResourceKind;

const VIEWERS: &str = "neutrino.secret.viewers";
const OPERATORS: &str = "neutrino.secret.operators";

/// Revoke umbrella group grants from every `neutrino_secret.*` permission.
///
/// Idempotent. Safe to re-run.
///
/// # Errors
///
/// Valence / Gauge failures bubble as `anyhow::Error`.
pub async fn revoke_neutrino_secret_umbrella_grants(v: &Valence) -> anyhow::Result<usize> {
    let system = v.with_actor(Actor::System {
        operation: "revoke_neutrino_secret_umbrella_grants".to_string(),
    });

    let prefix = format!("{}.", ResourceKind::NeutrinoSecret.prefix());
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

        for group_id in [VIEWERS, OPERATORS] {
            if revoke_group_from_permission(&system, &perm_id, group_id).await? {
                revoked += 1;
                info!("[permission] revoked umbrella grant group={group_id} permission={name}");
            }
        }
    }

    info!("[permission] revoke_neutrino_secret_umbrella_grants done revoked={revoked}");
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

/// Chronon script entry that runs [`revoke_neutrino_secret_umbrella_grants`].
#[chronon_coordinator_macros::script(
    name = "revoke_neutrino_secret_umbrella_grants",
    default_job(job = "revoke-neutrino-secret-umbrella-grants", run_once)
)]
pub async fn revoke_neutrino_secret_umbrella_grants_script(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    revoke_neutrino_secret_umbrella_grants(&valence)
        .await
        .context("failed revoking NeutrinoSecret umbrella grants")?;
    Ok(())
}
