//! Bot accounts in Gauge: group membership for bots, and the Lepton bot gate.
//!
//! A Lepton bot acts as its own Valence actor (`Actor::ServiceUser` named
//! `bot:<uuid>`). Gauge gives such an actor permissions only through groups:
//! add the bot with [`crate::service::add_group_member_bot`], and
//! [`crate::service::actor_can`] / [`crate::actor_can_raw::actor_can_raw`] then
//! allow it whatever the group holds, while the bot is active. A bot is never a
//! super user, never owns a group, domain, or permission, and cannot write
//! anything in Gauge. Other service users still get nothing.
//!
//! The same module answers Lepton's bot gate. [`seed_bot_permissions`] creates
//! [`LEPTON_BOT_CREATE`] and [`LEPTON_BOT_MANAGE_ANY`] plus the "Bot creators"
//! group, and [`install_gauge_bot_gate`] makes Lepton ask Gauge who may create
//! bots and who may manage everyone's bots. The crate root walks through both:
//! [Give a bot permissions through a group](crate#give-a-bot-permissions-through-a-group)
//! and [Back Lepton bot creation with Gauge](crate#back-lepton-bot-creation-with-gauge).

pub(crate) mod access;
mod gate;
mod policy;
mod seed;

use lepton_identity::bots::BotId;

pub use gate::{install_gauge_bot_gate, GaugeBotGate};
pub use policy::{BotPrincipalBotManager, BOT_PRINCIPAL_BOT_MANAGER};
pub use seed::{seed_bot_permissions, BotSeedStats};

/// Permission that lets a user create bots they own.
pub const LEPTON_BOT_CREATE: &str = "lepton.bot.create";
/// Permission that lets a user view and manage every bot. Held by super users.
pub const LEPTON_BOT_MANAGE_ANY: &str = "lepton.bot.manage_any";
/// Id of the seeded group whose members hold [`LEPTON_BOT_CREATE`].
pub const BOT_CREATORS_GROUP_ID: &str = "bot_creators";
/// Display name of [`BOT_CREATORS_GROUP_ID`].
pub const BOT_CREATORS_GROUP_NAME: &str = "Bot creators";

/// Valence table holding bot principals.
pub(crate) const BOT_PRINCIPAL_TABLE: &str = "permission_bot_principal";

/// Record id of a bot's principal row: `bot:<uuid>`.
pub(crate) fn bot_principal_id(bot: &BotId) -> String {
    format!("bot:{}", bot.as_str())
}
