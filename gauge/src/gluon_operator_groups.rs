//! Default Gluon **operational** permission groups (registry, cloud, control plane, builds).
//!
//! [`crate::manifest_sync::sync_permission_manifests`] creates the `gluon` domain, permission
//! rows, and `manifest_gluon_owners` for record ownership only. This module adds stable groups
//! operators can assign users to, and grants the relevant Gluon permission names to each group.
//!
//! Idempotent: safe to call after every manifest sync.

use chrono::Utc;
use valence::{Actor, Model, StringPredicate, Valence};

use crate::generated::{Permission, PermissionGroup, PermissionGroupPrincipal};

fn as_system(v: &Valence, operation: &str) -> Valence {
    v.with_actor(Actor::System {
        operation: operation.to_string(),
    })
}

async fn ensure_standalone_group(
    group_id: &str,
    display_name: &str,
    description: &str,
    system: &Valence,
) -> anyhow::Result<()> {
    if PermissionGroup::get(group_id, system).await?.is_some() {
        return Ok(());
    }
    let now = Utc::now();
    let group = PermissionGroup::new(
        display_name.to_string(),
        Some(description.to_string()),
        now,
        now,
    )?;
    PermissionGroup::upsert(group_id, group, system).await?;
    log::info!("[permission] Seeded Gluon operator group {group_id} ({display_name})");
    Ok(())
}

async fn ensure_group_principal(
    group_id: &str,
    system: &Valence,
) -> anyhow::Result<PermissionGroupPrincipal> {
    let group = PermissionGroup::get(group_id, system)
        .await?
        .ok_or_else(|| anyhow::anyhow!("permission group {group_id} not found"))?;
    let group_thing = group
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group id missing after persist"))?;
    let principal_id = format!("permission_group:{group_id}");
    if let Some(p) = PermissionGroupPrincipal::get(&principal_id, system).await? {
        return Ok(p);
    }
    let principal = PermissionGroupPrincipal::new(group_thing, group_id.to_string())?;
    PermissionGroupPrincipal::upsert(&principal_id, principal, system)
        .await
        .map_err(|e| anyhow::anyhow!("upsert permission_group_principal {principal_id}: {e}"))
}

async fn grant_named_permission_to_group(
    system: &Valence,
    group_id: &str,
    permission_name: &str,
) -> anyhow::Result<()> {
    let Some(perm) = Permission::query(system)
        .where_name(StringPredicate::Equals(permission_name.to_string()))
        .limit(1)
        .first()
        .await?
    else {
        log::warn!(
            "[permission] Gluon group seed: skip grant — permission {permission_name:?} not in database (manifest sync not run yet?)"
        );
        return Ok(());
    };

    let principal = ensure_group_principal(group_id, system).await?;
    let pid = principal
        .id()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("principal id missing after persist"))?;

    match perm.relate_to_allowed_principal_record(&pid, system).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate") || msg.contains("unique") || msg.contains("already") {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "grant {permission_name} to group {group_id}: {msg}"
                ))
            }
        }
    }
}

/// Stable operator groups and their Gluon permission names (must match `GluonPermission::as_str()`).
const GLUON_OPERATOR_GROUP_DEFS: &[(&str, &str, &str, &[&str])] = &[
    (
        "gluon_registry_operator",
        "Gluon registry operator",
        "Registry sources, image sync, and related secret material for push workflows",
        &[
            "ManageGluonRegistries",
            "SyncGluonImages",
            "ManageCloudSecrets",
        ],
    ),
    (
        "gluon_cloud_operator",
        "Gluon cloud operator",
        "Provider accounts, quotes/reservations, and cloud secrets",
        &[
            "ManageCloudProviderAccounts",
            "OperateCloudResources",
            "ManageCloudSecrets",
        ],
    ),
    (
        "pion_control_plane_operator",
        "Pion control plane operator",
        "Pools, cells, local image deploy, and authority handoff",
        &[
            "ManageControlPlanePools",
            "ManageControlPlaneAuthorityHandoff",
            "DeployLocalImages",
        ],
    ),
    (
        "gluon_build_operator",
        "Gluon build operator",
        "Split-build and related build orchestration",
        &["ManageGluonBuilds"],
    ),
];

/// Ensures default Gluon operator groups exist and have grants for the catalog permission rows.
pub async fn ensure_gluon_default_operator_groups(v: &Valence) -> anyhow::Result<()> {
    let system = as_system(v, "ensure_gluon_default_operator_groups");

    for (id, title, blurb, perms) in GLUON_OPERATOR_GROUP_DEFS {
        ensure_standalone_group(id, title, blurb, &system).await?;
        for pname in *perms {
            grant_named_permission_to_group(&system, id, pname).await?;
        }
    }

    Ok(())
}
