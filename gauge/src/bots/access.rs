//! Permission checks for bot actors: group membership only, raw reads only.
//!
//! A bot gets a permission when a group that holds it (directly, or through
//! nested groups) lists the bot as a member, and the bot is active. Direct
//! grants to a bot are ignored, and a bot is never a super user. Every read is
//! a raw backend read, so this is safe inside privacy evaluation.

use std::collections::HashSet;

use lepton::generated::{Bot, BotStatus};
use lepton_identity::bots::BotId;
use valence::ownership::OwnershipService;
use valence::{RecordId, Valence};

use super::{bot_principal_id, BOT_PRINCIPAL_TABLE};
use crate::actor_can_raw::{model_pk_id, permissions_named_raw, raw_get_json};
use crate::generated::{PermissionGroup, PermissionGroupPrincipal};

/// Why a bot check came out the way it did. Logged, never shown to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotDecision {
    /// A group holding the permission lists the bot.
    Member,
    /// No group holding the permission lists the bot.
    NotMember,
    /// The bot is missing, suspended, or being deleted.
    Inactive,
}

impl BotDecision {
    pub const fn allowed(self) -> bool {
        matches!(self, Self::Member)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::NotMember => "not_member",
            Self::Inactive => "bot_inactive",
        }
    }
}

/// Decide whether `bot` holds `permission_name`.
///
/// # Errors
///
/// Backend read or decode failures. Callers treat an error as a refusal.
pub async fn bot_decision(
    v: &Valence,
    bot: &BotId,
    permission_name: &str,
) -> anyhow::Result<BotDecision> {
    let permission_name = permission_name.trim();
    if permission_name.is_empty() {
        return Ok(BotDecision::NotMember);
    }
    if !bot_is_active_raw(v, bot).await? {
        return Ok(BotDecision::Inactive);
    }
    let principal_id = bot_principal_id(bot);
    for permission in permissions_named_raw(permission_name, v).await? {
        for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When a **bot account** calls an API that needs a **Gauge permission**, we **follow the permission's allowed-principal edges** to find the groups that hold it. Used only to allow or deny the bot's request; nothing is shown.")).await? {
            let Some(group) = group_behind_principal(&principal, v).await? else {
                continue;
            };
            if group_has_bot_raw(&group, &principal_id, v).await? {
                return Ok(BotDecision::Member);
            }
        }
    }
    Ok(BotDecision::NotMember)
}

/// Log a decision at the bot-check boundary.
pub fn log_decision(permission_name: &str, decision: &anyhow::Result<BotDecision>) {
    match decision {
        Ok(d) => log::debug!(
            target: "gauge.bot_access",
            "bot permission check permission={permission_name} outcome={} reason={}",
            if d.allowed() { "allow" } else { "deny" },
            d.as_str()
        ),
        Err(_) => log::warn!(
            target: "gauge.bot_access",
            "bot permission check failed permission={permission_name} outcome=error"
        ),
    }
}

/// The bot row exists, is `active`, and is not waiting on deletion.
async fn bot_is_active_raw(v: &Valence, bot: &BotId) -> anyhow::Result<bool> {
    let Some(row) = raw_get_json("bot", bot.as_str(), v).await? else {
        return Ok(false);
    };
    let bot_row: Bot = serde_json::from_value(row)?;
    if bot_row.status() != &BotStatus::Active {
        return Ok(false);
    }
    match OwnershipService::pending_deletion_gate("bot", bot.as_str(), v).await {
        Ok(()) => Ok(true),
        Err(valence::Error::PendingDeletion(_)) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("bot pending-deletion check: {e}")),
    }
}

/// The group a `permission_group_principal` points at; `None` for any other principal.
async fn group_behind_principal(
    principal: &RecordId,
    v: &Valence,
) -> anyhow::Result<Option<PermissionGroup>> {
    if principal.table() != "permission_group_principal" {
        return Ok(None);
    }
    let Some(row) = raw_get_json("permission_group_principal", principal.id(), v).await? else {
        return Ok(None);
    };
    let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
    let group_id = valence::extract_id_from_record(principal.group()).unwrap_or_default();
    match raw_get_json("permission_group", &group_id, v).await? {
        Some(row) => Ok(Some(serde_json::from_value(row)?)),
        None => Ok(None),
    }
}

/// Walk `group`, the groups nested in it, and groups that own it (owners count as
/// holders, the same as for users), looking for the bot's principal among members.
async fn group_has_bot_raw(
    group: &PermissionGroup,
    bot_principal_id: &str,
    v: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = HashSet::new();
    let mut queue = vec![group.clone()];
    while let Some(current) = queue.pop() {
        if !visited.insert(model_pk_id(current.id())) {
            continue;
        }
        let owners = current.get_owners_record_ids(v, valence::use_!(r"When a **bot account** needs a **Gauge permission**, we **follow a group's owner edges** to find owner groups the bot might belong to. Used only to allow or deny the bot's request; nothing is shown.")).await?;
        let members = current.get_members_record_ids(v, valence::use_!(r"When a **bot account** needs a **Gauge permission**, we **follow a group's member edges** to see whether the bot, or a group it belongs to, is a member. Used only to allow or deny the bot's request; nothing is shown.")).await?;
        for principal in owners.iter().chain(members.iter()) {
            if principal.table() == BOT_PRINCIPAL_TABLE {
                // Bots are only ever members; an owner edge to a bot would be a forged row.
                if principal.id() == bot_principal_id && members.iter().any(|m| m == principal) {
                    return Ok(true);
                }
            } else if let Some(child) = group_behind_principal(principal, v).await? {
                queue.push(child);
            }
        }
    }
    Ok(false)
}
