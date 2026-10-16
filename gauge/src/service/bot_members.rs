//! Add and remove Lepton bots as permission group members.

use lepton_identity::bots::BotId;
use valence::{Model, RecordId, Valence};

use crate::bots::{bot_principal_id, BOT_PRINCIPAL_TABLE};
use crate::generated::{PermissionBotPrincipal, PermissionGroup};
use crate::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID};
use crate::types::HistoryDiffItemDto;

use super::helpers::{
    get_group_raw, group_has_owner_user, persist_history_entry, require_model_id, require_user_id,
    user_id_candidates,
};
use super::GaugeServiceError;

/// Load the group and check the caller owns it (directly or through a group) or is a super user.
async fn group_for_member_edit(
    group_id: &str,
    actor_user_id: &str,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let group = get_group_raw(group_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("permission_group", group_id))?;
    if !group_has_owner_user(&group, &user_id_candidates(actor_user_id), v).await?
        && !actor_is_super_user(v).await?
    {
        return Err(GaugeServiceError::not_authorized("edit group membership").into());
    }
    Ok(group)
}

async fn get_bot_principal_raw(
    bot: &BotId,
    v: &Valence,
) -> anyhow::Result<Option<PermissionBotPrincipal>> {
    match crate::actor_can_raw::raw_get_json(BOT_PRINCIPAL_TABLE, &bot_principal_id(bot), v).await?
    {
        Some(row) => Ok(Some(serde_json::from_value(row)?)),
        None => Ok(None),
    }
}

/// Whether the caller may add bots to `group_id` with [`add_group_member_bot`].
///
/// True when the caller is a signed-in user who owns the group (directly or
/// through a group) or is a super user, and the group isn't the Super User
/// group. Use it to decide whether a UI offers the group as a choice; the add
/// itself checks again, and also checks that the caller can see the bot.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotFound` when the group doesn't
/// exist. Valence failures otherwise. A caller that isn't a signed-in user gets
/// `Ok(false)`.
pub async fn can_add_group_member_bot(group_id: &str, v: &Valence) -> anyhow::Result<bool> {
    let Ok(actor_user_id) = require_user_id(v) else {
        return Ok(false);
    };
    if group_id == SUPER_USER_GROUP_ID {
        return Ok(false);
    }
    let group = get_group_raw(group_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("permission_group", group_id))?;
    Ok(
        group_has_owner_user(&group, &user_id_candidates(&actor_user_id), v).await?
            || actor_is_super_user(v).await?,
    )
}

/// Add `bot` as a member of `group_id`, so it holds everything the group holds.
///
/// The caller must own the group (or be a super user) **and** be able to see the
/// bot under their own Valence: its owner, or a user who manages every bot. A
/// group owner can't pull in a bot they can't see, and a bot owner can't put
/// their bot in a group they don't own. Bots never join the Super User group.
/// Adding a bot that is already a member changes nothing.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotAuthorized` when the caller isn't a
/// signed-in user, doesn't own the group, or isn't a super user; `NotFound` for a
/// missing group or a bot the caller can't see; `Validation` for the Super User
/// group. Valence failures otherwise.
pub async fn add_group_member_bot(group_id: &str, bot: &BotId, v: &Valence) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    if group_id == SUPER_USER_GROUP_ID {
        return Err(GaugeServiceError::validation("Bots cannot join the Super User group").into());
    }
    let group = group_for_member_edit(group_id, &actor_user_id, v).await?;
    let visible = lepton::generated::Bot::get(bot.as_str(), v, valence::use_!(r"When an operator **adds a bot account to a permission group**, we **check that they can see the bot**, meaning they own it or manage every bot. Nothing about the bot is shown here; the check only decides whether the add may go ahead."))
        .await?
        .is_some();
    if !visible {
        return Err(GaugeServiceError::not_found("bot", bot.as_str()).into());
    }

    let principal_id = bot_principal_id(bot);
    if get_bot_principal_raw(bot, v).await?.is_none() {
        let row = PermissionBotPrincipal::new(
            RecordId::new("bot", bot.as_str()),
            bot.as_str().to_string(),
        )?;
        PermissionBotPrincipal::upsert(&principal_id, row, v, valence::use_!(r"When an operator **adds a bot account to a permission group**, we **save a principal row for the bot** that points at the bot's id. Group member lists show the bot's handle, and permission checks use the row to tell whether the bot belongs to the group."))
            .await?;
    }
    let principal = get_bot_principal_raw(bot, v)
        .await?
        .ok_or_else(|| GaugeServiceError::invariant("bot principal missing after save"))?;
    group
        .relate_to_member_record(&require_model_id(principal.id(), "principal")?, v, valence::use_!(r"When an operator **adds a bot account to a permission group**, we **write the member edge** so the bot holds the group's permissions while it is active. Operators see the bot in the group's member list."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "add_member_bot",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_bots".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(bot.as_str().to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Remove `bot` from `group_id`. The bot loses what the group granted at once.
///
/// The caller must own the group or be a super user. Seeing the bot isn't
/// required, so a group owner can always remove a bot someone else added.
/// Removing a bot that isn't a member changes nothing.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotAuthorized` or `NotFound` for the
/// group, as for [`add_group_member_bot`]. Valence failures otherwise.
pub async fn remove_group_member_bot(
    group_id: &str,
    bot: &BotId,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let group = group_for_member_edit(group_id, &actor_user_id, v).await?;
    let Some(principal) = get_bot_principal_raw(bot, v).await? else {
        return Ok(());
    };
    group
        .unrelate_from_member_record(&require_model_id(principal.id(), "principal")?, v, valence::use_!(r"When an operator **removes a bot account from a permission group**, we **delete the member edge** so the bot stops holding the group's permissions. Operators see the updated member list."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "remove_member_bot",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_bots".to_string(),
            old_value: serde_json::Value::String(bot.as_str().to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}
