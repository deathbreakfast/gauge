//! Boot seed for the service user permissions and the "Service user creators" group.

use valence::Valence;

use super::{
    LEPTON_SERVICE_USER_CREATE, LEPTON_SERVICE_USER_MANAGE_ANY, SERVICE_USER_CREATORS_GROUP_ID,
    SERVICE_USER_CREATORS_GROUP_NAME,
};
use crate::manifest_sync::{
    sync_permission_manifests, PermissionDomainInput, PermissionInput, PermissionManifestInput,
};
use crate::resource_permissions::ensure_group_granted_permission;
use crate::service::GaugeServiceError;

/// What [`seed_service_user_permissions`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
pub struct ServiceUserSeedStats {
    /// Service user permissions created by this run (0 when they already existed).
    pub permissions_created: usize,
}

fn manifest() -> PermissionManifestInput {
    PermissionManifestInput {
        app_id: "lepton-service-users".to_string(),
        domains: vec![PermissionDomainInput {
            key: "lepton".to_string(),
            name: "Lepton".to_string(),
            description: "Sign-in, accounts, and service users".to_string(),
            permissions: vec![
                PermissionInput {
                    name: LEPTON_SERVICE_USER_CREATE.to_string(),
                    description: "Create service users owned by yourself".to_string(),
                },
                PermissionInput {
                    name: LEPTON_SERVICE_USER_MANAGE_ANY.to_string(),
                    description:
                        "View, suspend, and delete every service user, and mint tokens for them"
                            .to_string(),
                },
            ],
        }],
    }
}

/// Create the service user permissions and the "Service user creators" group, and grant the
/// group `lepton.service_user.create`.
///
/// Runs at host boot on the System Valence, after table sync and after the
/// host's own manifest sync. Safe to run on every boot: existing rows are kept
/// and nothing is granted twice. `lepton.service_user.manage_any` is granted to no
/// group; super users hold it through the Super User group.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] when `system` is not a System Valence,
/// and Valence failures from manifest sync or the group grant.
pub async fn seed_service_user_permissions(
    system: &Valence,
) -> anyhow::Result<ServiceUserSeedStats> {
    if !system.actor().is_system() {
        return Err(GaugeServiceError::not_authorized("seed_service_user_permissions").into());
    }
    let synced = sync_permission_manifests(system, &[manifest()]).await?;
    ensure_group_granted_permission(
        system,
        SERVICE_USER_CREATORS_GROUP_ID,
        SERVICE_USER_CREATORS_GROUP_NAME,
        "People who may create service users for themselves",
        LEPTON_SERVICE_USER_CREATE,
        &[],
    )
    .await
    .map_err(|e| anyhow::Error::new(e).context(format!("seed {SERVICE_USER_CREATORS_GROUP_ID}")))?;
    let stats = ServiceUserSeedStats {
        permissions_created: synced.permissions_created,
    };
    log::info!(
        target: "gauge.service_user_seed",
        "service user permissions seeded permissions_created={}",
        stats.permissions_created
    );
    Ok(stats)
}
