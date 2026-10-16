//! Lepton's bot gate, answered from Gauge permissions.

use std::sync::Arc;

use async_trait::async_trait;
use lepton_identity::bots::{install_bot_gate, BotGate, BotGateAlreadyInstalled, BotGateError};
use valence::Valence;

use super::{LEPTON_BOT_CREATE, LEPTON_BOT_MANAGE_ANY};
use crate::actor_can_raw::actor_can_raw;

/// [`BotGate`] that asks Gauge: `may_create_bot` is [`LEPTON_BOT_CREATE`] and
/// `may_manage_any_bot` is [`LEPTON_BOT_MANAGE_ANY`].
///
/// Both answers come from [`actor_can_raw`] on the Valence the privacy rule
/// passes in. That is a raw walk with no actor change, as `BotGate` requires.
/// Super users pass both checks. A failed lookup is reported as a
/// [`BotGateError`] with `reason_class = "gauge_lookup"`, which Lepton treats
/// as a refusal.
#[derive(Debug, Default, Clone, Copy)]
pub struct GaugeBotGate;

async fn decide(
    v: &Valence,
    permission: &'static str,
    decision: &str,
) -> Result<bool, BotGateError> {
    actor_can_raw(v, permission).await.map_err(|_| {
        log::warn!(
            target: "gauge.bot_gate",
            "bot gate lookup failed decision={decision} reason_class=gauge_lookup"
        );
        BotGateError {
            reason_class: "gauge_lookup",
        }
    })
}

#[async_trait]
impl BotGate for GaugeBotGate {
    async fn may_create_bot(&self, valence: &Valence) -> Result<bool, BotGateError> {
        decide(valence, LEPTON_BOT_CREATE, "create").await
    }

    async fn may_manage_any_bot(&self, valence: &Valence) -> Result<bool, BotGateError> {
        decide(valence, LEPTON_BOT_MANAGE_ANY, "manage_any").await
    }
}

/// Install [`GaugeBotGate`] as the process's Lepton bot gate.
///
/// Call once at host boot, after [`super::seed_bot_permissions`] and before the
/// server takes requests.
///
/// # Errors
///
/// [`BotGateAlreadyInstalled`] when a gate is already installed in this process;
/// the first gate stays.
pub fn install_gauge_bot_gate() -> Result<(), BotGateAlreadyInstalled> {
    install_bot_gate(Arc::new(GaugeBotGate))
}
