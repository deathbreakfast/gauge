//! Boot seed for the bot permissions and the "Bot creators" group.

use valence::Valence;

use super::{
    BOT_CREATORS_GROUP_ID, BOT_CREATORS_GROUP_NAME, LEPTON_BOT_CREATE, LEPTON_BOT_MANAGE_ANY,
};
use crate::manifest_sync::{
    sync_permission_manifests, PermissionDomainInput, PermissionInput, PermissionManifestInput,
};
use crate::resource_permissions::ensure_group_granted_permission;
use crate::service::GaugeServiceError;

/// What [`seed_bot_permissions`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
pub struct BotSeedStats {
    /// Bot permissions created by this run (0 when they already existed).
    pub permissions_created: usize,
}

fn manifest() -> PermissionManifestInput {
    PermissionManifestInput {
        app_id: "lepton-bots".to_string(),
        domains: vec![PermissionDomainInput {
            key: "lepton".to_string(),
            name: "Lepton".to_string(),
            description: "Sign-in, accounts, and bot accounts".to_string(),
            permissions: vec![
                PermissionInput {
                    name: LEPTON_BOT_CREATE.to_string(),
                    description: "Create bot accounts owned by yourself".to_string(),
                },
                PermissionInput {
                    name: LEPTON_BOT_MANAGE_ANY.to_string(),
                    description:
                        "View, suspend, and delete every bot account, and mint tokens for them"
                            .to_string(),
                },
            ],
        }],
    }
}

/// Create the bot permissions and the "Bot creators" group, and grant the
/// group `lepton.bot.create`.
///
/// Runs at host boot on the System Valence, after table sync and after the
/// host's own manifest sync. Safe to run on every boot: existing rows are kept
/// and nothing is granted twice. `lepton.bot.manage_any` is granted to no
/// group; super users hold it through the Super User group.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] when `system` is not a System Valence,
/// and Valence failures from manifest sync or the group grant.
pub async fn seed_bot_permissions(system: &Valence) -> anyhow::Result<BotSeedStats> {
    if !system.actor().is_system() {
        return Err(GaugeServiceError::not_authorized("seed_bot_permissions").into());
    }
    let synced = sync_permission_manifests(system, &[manifest()]).await?;
    ensure_group_granted_permission(
        system,
        BOT_CREATORS_GROUP_ID,
        BOT_CREATORS_GROUP_NAME,
        "People who may create bot accounts for themselves",
        LEPTON_BOT_CREATE,
        &[],
    )
    .await
    .map_err(|e| anyhow::Error::new(e).context(format!("seed {BOT_CREATORS_GROUP_ID}")))?;
    let stats = BotSeedStats {
        permissions_created: synced.permissions_created,
    };
    log::info!(
        target: "gauge.bot_seed",
        "bot permissions seeded permissions_created={}",
        stats.permissions_created
    );
    Ok(stats)
}
