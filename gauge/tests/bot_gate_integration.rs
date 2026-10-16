//! Gauge-backed Lepton bot gate and its boot seed (B3 K13–K15).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/bots.rs"]
mod bots_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use bots_fixtures::{create_bot, raw_count, world};
use gauge::bots::{
    seed_bot_permissions, GaugeBotGate, BOT_CREATORS_GROUP_ID, LEPTON_BOT_CREATE,
    LEPTON_BOT_MANAGE_ANY,
};
use gauge::generated::{Permission, PermissionBotPrincipal};
use gauge::service::{add_group_member_bot, add_group_member_user, GaugeServiceError};
use lepton::generated::Bot;
use lepton_identity::bots::{BotGate, BotId};
use valence::{Actor, Model, StringPredicate};

#[tokio::test]
async fn tm_gate_creator_may_create_happy() {
    let w = world().await;
    let alice = w.as_user("alice");
    assert!(GaugeBotGate.may_create_bot(&alice).await.expect("gate"));
    assert!(!GaugeBotGate.may_manage_any_bot(&alice).await.expect("gate"));
    // The privacy rule accepts the create too.
    let bot = create_bot(&w, "alice", "made-bot").await;
    assert!(Bot::get(bot.as_str(), &alice, valence::use_!(r"**Test:** Fixture **bot account** load in gauge gate tests to confirm the owner sees the bot they created. CI and developers running the suite only.")).await.expect("get").is_some());
}

#[tokio::test]
async fn tm_gate_super_user_may_create_and_manage_happy() {
    let w = world().await;
    let carol = w.as_user("carol");
    assert!(GaugeBotGate.may_create_bot(&carol).await.expect("gate"));
    assert!(GaugeBotGate.may_manage_any_bot(&carol).await.expect("gate"));
    // Manage-any reaches someone else's bot through Lepton's rule.
    let bot = create_bot(&w, "alice", "managed-bot").await;
    assert!(Bot::get(bot.as_str(), &carol, valence::use_!(r"**Test:** Fixture **bot account** load in gauge gate tests to confirm a super user can see any bot. CI and developers running the suite only.")).await.expect("get").is_some());
}

#[tokio::test]
async fn tm_gate_plain_user_denied_sad() {
    let w = world().await;
    let bob = w.as_user("bob");
    assert!(!GaugeBotGate.may_create_bot(&bob).await.expect("gate"));
    assert!(!GaugeBotGate.may_manage_any_bot(&bob).await.expect("gate"));
    let before = raw_count(&w.system, "bot").await;
    let row = Bot::new(
        Some(valence::RecordId::new("user", "bob")),
        lepton::generated::BotOwnerKind::User,
        Some(valence::RecordId::new("user", "bob")),
        "denied-bot".into(),
        "deniedbot".into(),
        "Denied".into(),
        None,
        lepton::generated::BotStatus::Active,
        None,
        chrono::Utc::now(),
        chrono::Utc::now(),
    )
    .expect("row");
    let err = Bot::upsert(BotId::new_v4().as_str(), row, &bob, valence::use_!(r"**Test:** Fixture **bot account** save attempt in gauge gate tests that the gate must refuse. CI and developers running the suite only."))
        .await
        .expect_err("bob is not a bot creator");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(raw_count(&w.system, "bot").await, before);
}

#[tokio::test]
async fn tm_gate_creator_cannot_manage_any_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "private-bot").await;
    // dave becomes a bot creator too; that doesn't let him see alice's bot.
    add_group_member_user(BOT_CREATORS_GROUP_ID, "dave", &w.as_user("carol"))
        .await
        .expect("add dave");
    let dave = w.as_user("dave");
    assert!(GaugeBotGate.may_create_bot(&dave).await.expect("gate"));
    assert!(!GaugeBotGate.may_manage_any_bot(&dave).await.expect("gate"));
    assert!(Bot::get(bot.as_str(), &dave, valence::use_!(r"**Test:** Fixture **bot account** load in gauge gate tests that must find nothing for another creator. CI and developers running the suite only.")).await.expect("get").is_none());
}

#[tokio::test]
async fn tm_gate_bot_valence_denied_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "creator-bot").await;
    // Even a bot placed in Bot creators gets no gate answer: Lepton's rules
    // refuse non-user callers before asking, and the bot holds nothing else.
    add_group_member_bot(BOT_CREATORS_GROUP_ID, &bot, &w.as_user("carol"))
        .await
        .expect("add bot");
    let bot_v = w.as_bot(&bot);
    assert!(!GaugeBotGate.may_manage_any_bot(&bot_v).await.expect("gate"));
    let before = raw_count(&w.system, "bot").await;
    let row = Bot::new(
        None,
        lepton::generated::BotOwnerKind::User,
        None,
        "child-bot".into(),
        "childbot".into(),
        "Child".into(),
        None,
        lepton::generated::BotStatus::Active,
        None,
        chrono::Utc::now(),
        chrono::Utc::now(),
    )
    .expect("row");
    assert!(Bot::upsert(BotId::new_v4().as_str(), row, &bot_v, valence::use_!(r"**Test:** Fixture **bot account** save attempt by a bot in gauge gate tests that must be refused. CI and developers running the suite only.")).await.is_err());
    assert_eq!(raw_count(&w.system, "bot").await, before);
}

#[tokio::test]
async fn tm_bot_principal_delete_by_stranger_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "kept-bot").await;
    add_group_member_bot("test_readers", &bot, &w.as_user("carol"))
        .await
        .expect("add");
    let principal_id = format!("bot:{}", bot.as_str());
    let err = PermissionBotPrincipal::delete(&principal_id, &w.as_user("bob"), valence::use_!(r"**Test:** Fixture **bot principal** delete attempt by a stranger in gauge gate tests that must be refused. CI and developers running the suite only."))
        .await
        .expect_err("bob neither owns the bot nor manages every bot");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 1);
}

#[tokio::test]
async fn tm_seed_bot_permissions_idempotent_happy() {
    let w = world().await; // first seed ran inside `world`
    let again = seed_bot_permissions(&w.system).await.expect("second seed");
    assert_eq!(again.permissions_created, 0);
    for name in [LEPTON_BOT_CREATE, LEPTON_BOT_MANAGE_ANY] {
        let perms = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to confirm the boot seed made each bot permission once. CI and developers running the suite only."))
            .where_name(StringPredicate::Equals(name.into()))
            .await
            .expect("query");
        assert_eq!(perms.len(), 1, "{name}");
    }
    let create = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to count who holds bot creation. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(LEPTON_BOT_CREATE.into()))
        .first()
        .await
        .expect("query")
        .expect("exists");
    let holders = create
        .get_allowed_principals_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in gauge gate tests to confirm Bot creators is granted bot creation exactly once. CI and developers running the suite only."))
        .await
        .expect("edges");
    assert_eq!(holders.len(), 1, "only Bot creators, once: {holders:?}");
    let manage = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to confirm manage-any is granted to no group. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(LEPTON_BOT_MANAGE_ANY.into()))
        .first()
        .await
        .expect("query")
        .expect("exists");
    assert!(manage
        .get_allowed_principals_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in gauge gate tests to confirm manage-any has no group grant. CI and developers running the suite only."))
        .await
        .expect("edges")
        .is_empty());
}

#[tokio::test]
async fn tm_seed_bot_permissions_not_system_sad() {
    let w = world().await;
    for v in [
        w.as_user("carol"),
        w.as_actor(Actor::Anonymous),
        w.as_actor(Actor::ServiceUser {
            service_name: "spectra-ingest".into(),
        }),
    ] {
        let err = seed_bot_permissions(&v).await.expect_err("System only");
        assert!(
            matches!(
                err.downcast_ref::<GaugeServiceError>(),
                Some(GaugeServiceError::NotAuthorized { .. })
            ),
            "{err:#}"
        );
    }
}
