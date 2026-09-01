use anyhow::Context;
use valence::Actor;

use crate::super_user::ensure_super_user_group;

/// Chronon script (run-once) that ensures the Super User permission group exists.
#[chronon_coordinator_macros::script(
    name = "ensure_super_user_group",
    default_job(job = "ensure-super-user-group", run_once)
)]
pub async fn ensure_super_user_group_script(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    let system = valence.with_actor(Actor::System {
        operation: "ensure_super_user_group_script".to_string(),
    });
    ensure_super_user_group(&system)
        .await
        .context("failed ensuring Super User group")?;
    Ok(())
}
