//! Privacy rule letting a bot's manager delete its Gauge principal row.

use std::any::Any;

use async_trait::async_trait;
use lepton_identity::bots::installed_bot_gate;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Valence};

use crate::actor_can_raw::raw_get_json;
use crate::generated::PermissionBotPrincipal;

/// Allows **delete** of a `permission_bot_principal` row by the bot's owner, or
/// by a user the installed Lepton bot gate lets manage every bot.
///
/// Deleting a bot cascades to its principal row (and from there to its group
/// memberships), and that delete runs as whoever deleted the bot. Without this
/// rule only System and super users could delete a bot that belongs to a group.
/// Reads are raw, and the caller's actor is never changed.
#[derive(Debug, Clone, Copy)]
pub struct BotPrincipalBotManager;

/// Rule instance for `permission_bot_principal` delete policies.
pub const BOT_PRINCIPAL_BOT_MANAGER: BotPrincipalBotManager = BotPrincipalBotManager;

#[async_trait]
impl PolicyEvaluator for BotPrincipalBotManager {
    fn name(&self) -> &'static str {
        "perm::BOT_PRINCIPAL_BOT_MANAGER"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Allow bot principal delete for the bot's owner or a manage-any user")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        if !matches!(op, PrivacyOperation::Delete) {
            return Ok(false);
        }
        let actor: Actor = serde_json::from_value(actor.actor_json().clone())
            .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))?;
        let Some(user_id) = actor.user_id() else {
            return Ok(false);
        };
        let principal: PermissionBotPrincipal = serde_json::from_value(record.clone())
            .map_err(|e| Error::Privacy(format!("bot principal decode failed: {e}")))?;
        let bot_id = valence::extract_id_from_record(principal.bot()).unwrap_or_default();
        let bot_row = raw_get_json("bot", &bot_id, v)
            .await
            .map_err(|e| Error::Privacy(format!("bot lookup failed: {e}")))?;
        if let Some(row) = bot_row {
            let bot: lepton::generated::Bot = serde_json::from_value(row)
                .map_err(|e| Error::Privacy(format!("bot decode failed: {e}")))?;
            let owner = bot
                .user()
                .and_then(|r| valence::extract_id_from_record(r).ok())
                .unwrap_or_default();
            let caller = user_id.split_once(':').map_or(user_id, |(_, bare)| bare);
            if !owner.is_empty() && owner == caller {
                return Ok(true);
            }
        }
        match installed_bot_gate() {
            Some(gate) => Ok(gate.may_manage_any_bot(v).await.unwrap_or(false)),
            None => Ok(false),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
