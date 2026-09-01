use anyhow::Context;
use valence::Actor;

use crate::super_user::resync_eligible_super_user_group_members;

/// Periodically align Super User group membership with `owner` / `super_admin` account roles.
///
/// Valence model `side_effects` cannot be registered on `account_membership` from this crate
/// without a dependency cycle (`orbital-ssr` ↔ `gauge`); this Chronon job provides the same
/// reactive outcome at the product boundary.
///
/// The script binds `Actor::System` from the Chronon identity factory (job starts as System —
/// not a mid-request elevate from a user session). Lepton hosts must authorize who may assign
/// `owner` / `super_admin`; gauge only syncs those roles into the pinned `super_user_group`.
#[chronon_coordinator_macros::script(
    name = "sync_super_user_membership_roles",
    default_job(job = "sync-super-user-membership-roles", cron = "0 */6 * * *")
)]
pub async fn sync_super_user_membership_roles_script(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    let system = valence.with_actor(Actor::System {
        operation: "sync_super_user_membership_roles_script".to_string(),
    });
    resync_eligible_super_user_group_members(&system)
        .await
        .context("failed syncing owner/super_admin members into Super User group")?;
    Ok(())
}
