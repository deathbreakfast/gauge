//! Bots hold Gauge permissions only through group membership (B3 K2–K10).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/bots.rs"]
mod bots_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use bots_fixtures::{create_bot, raw_count, set_bot_status, world, READ, READERS};
use gauge::actor_can_raw::actor_can_raw;
use gauge::bots::BOT_CREATORS_GROUP_ID;
use gauge::service::{
    actor_can, add_group_member_bot, add_group_member_group, add_group_member_user,
    can_add_group_member_bot, get_group_detail, remove_group_member_bot, GaugeServiceError,
};
use gauge::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID};
use lepton::generated::BotStatus;
use lepton_identity::bots::BotId;
use valence::{Actor, Model};

async fn bot_holds(world: &bots_fixtures::World, bot: &BotId, permission: &str) -> (bool, bool) {
    let v = world.as_bot(bot);
    let typed = actor_can(&v, permission).await.expect("actor_can");
    let raw = actor_can_raw(&v, permission).await.expect("actor_can_raw");
    (typed, raw)
}

/// The group's member edges include the bot's principal row.
async fn bot_is_member(world: &bots_fixtures::World, group_id: &str, bot: &BotId) -> bool {
    let group = gauge::generated::PermissionGroup::get(group_id, &world.system, valence::use_!(r"**Test:** Fixture **permission group** load in gauge bot tests to check its member edges. CI and developers running the suite only."))
        .await
        .expect("group")
        .expect("group exists");
    let principal =
        valence::RecordId::new("permission_bot_principal", format!("bot:{}", bot.as_str()));
    group
        .get_members_record_ids(&world.system, valence::use_!(r"**Test:** Fixture member-edge read in gauge bot tests to check whether a bot is a member. CI and developers running the suite only."))
        .await
        .expect("members")
        .contains(&principal)
}

fn service_error(err: &anyhow::Error) -> &GaugeServiceError {
    err.downcast_ref::<GaugeServiceError>()
        .unwrap_or_else(|| panic!("expected GaugeServiceError, got {err:#}"))
}

#[tokio::test]
async fn tm_bot_member_gets_group_permission_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "reader-bot").await;
    assert_eq!(
        bot_holds(&w, &bot, READ).await,
        (false, false),
        "nothing before joining"
    );

    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("super user adds bot");

    assert_eq!(bot_holds(&w, &bot, READ).await, (true, true));
    assert!(bot_is_member(&w, READERS, &bot).await);
    // Group screens list users and groups only; a bot member is never shown as a user.
    let detail = get_group_detail(READERS, &w.as_user("carol"))
        .await
        .expect("detail")
        .expect("group exists");
    assert!(detail.members.iter().all(|m| m.id != bot.as_str()));
}

#[tokio::test]
async fn tm_bot_not_member_denied_sad() {
    let w = world().await;
    let member = create_bot(&w, "alice", "member-bot").await;
    let outsider = create_bot(&w, "alice", "outsider-bot").await;
    add_group_member_bot(READERS, &member, &w.as_user("carol"))
        .await
        .expect("add member");

    assert_eq!(
        bot_holds(&w, &member, READ).await,
        (true, true),
        "same fixture grants a member"
    );
    assert_eq!(bot_holds(&w, &outsider, READ).await, (false, false));
    assert_eq!(
        bot_holds(&w, &member, "test.records.write").await,
        (false, false)
    );
}

#[tokio::test]
async fn tm_bot_nested_group_membership_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "nested-bot").await;
    let carol = w.as_user("carol");
    let child = gauge::service::create_group(
        gauge::types::PermissionGroupCreateInput {
            name: "Agents".into(),
            description: String::new(),
        },
        &carol,
    )
    .await
    .expect("child group");
    let child_id = common::record_pk_id(child.id());
    add_group_member_group(READERS, &child_id, &carol)
        .await
        .expect("nest");
    add_group_member_bot(&child_id, &bot, &carol)
        .await
        .expect("add to child");

    assert_eq!(bot_holds(&w, &bot, READ).await, (true, true));
}

#[tokio::test]
async fn tm_bot_suspended_member_denied_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "paused-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("add");

    set_bot_status(&w, "alice", &bot, BotStatus::Suspended).await;
    assert_eq!(bot_holds(&w, &bot, READ).await, (false, false));

    set_bot_status(&w, "alice", &bot, BotStatus::Active).await;
    assert_eq!(
        bot_holds(&w, &bot, READ).await,
        (true, true),
        "resume restores access"
    );
}

#[tokio::test]
async fn tm_bot_pending_deletion_member_denied_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "doomed-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("add");

    lepton::generated::Bot::delete(bot.as_str(), &w.as_user("alice"), valence::use_!(r"**Test:** Fixture **bot account** delete for gauge bot tests so the suite can check a bot being deleted loses access. CI and developers running the suite only."))
        .await
        .expect("queue delete");

    assert_eq!(bot_holds(&w, &bot, READ).await, (false, false));
}

#[tokio::test]
async fn tm_infra_service_user_denied_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "real-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("add");

    for name in [
        "spectra-ingest".to_string(),
        format!("bot:bot:{}", bot.as_str()),
        "bot:not-a-uuid".to_string(),
        bot.as_str().to_string(),
        bot.as_str().to_uppercase(),
        String::new(),
    ] {
        let v = w.as_actor(Actor::ServiceUser {
            service_name: name.clone(),
        });
        assert!(!actor_can(&v, READ).await.expect("actor_can"), "{name}");
        assert!(
            !actor_can_raw(&v, READ).await.expect("actor_can_raw"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn tm_bot_and_user_same_uuid_isolated_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "twin-bot").await;
    // A user whose id is the bot's uuid, in the readers group.
    common::seed_user(bot.as_str(), "twin@example.test", &w.system).await;
    add_group_member_user(READERS, bot.as_str(), &w.as_user("carol"))
        .await
        .expect("add user");

    assert_eq!(
        bot_holds(&w, &bot, READ).await,
        (false, false),
        "user grant must not reach the bot"
    );

    // And the other way round: a member bot does not grant a user with its uuid.
    let other = create_bot(&w, "alice", "other-twin-bot").await;
    common::seed_user(other.as_str(), "twin2@example.test", &w.system).await;
    add_group_member_bot(READERS, &other, &w.as_user("carol"))
        .await
        .expect("add bot");
    let user = w.as_user(other.as_str());
    assert!(!actor_can(&user, READ).await.expect("actor_can"));
}

#[tokio::test]
async fn tm_bot_never_super_user_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "ambitious-bot").await;
    let carol = w.as_user("carol");

    let err = add_group_member_bot(SUPER_USER_GROUP_ID, &bot, &carol)
        .await
        .expect_err("bots never join the Super User group");
    assert!(
        matches!(service_error(&err), GaugeServiceError::Validation { .. }),
        "{err:#}"
    );

    // Even through a group nested under the Super User group.
    add_group_member_group(SUPER_USER_GROUP_ID, READERS, &carol)
        .await
        .ok();
    add_group_member_bot(READERS, &bot, &carol)
        .await
        .expect("add to readers");
    let v = w.as_bot(&bot);
    assert!(!actor_is_super_user(&v).await.expect("super user check"));
    assert!(!actor_can(&v, "lepton.bot.manage_any")
        .await
        .expect("manage any"));
}

#[tokio::test]
async fn tm_bot_delete_removes_principal_and_membership_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "gone-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("add");
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 1);

    valence::delete_entity_now("bot", bot.as_str(), &w.system)
        .await
        .expect("purge bot");

    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 0);
    // Valence leaves the group's member edge pointing at the deleted principal
    // (incoming many-to-many edges are only removed for `SetNull` connections).
    // It names no row that still exists and grants nothing.
    assert_eq!(bot_holds(&w, &bot, READ).await, (false, false));
    let detail = get_group_detail(READERS, &w.as_user("carol"))
        .await
        .expect("detail")
        .expect("group exists");
    assert!(
        detail.members.iter().all(|m| m.id != bot.as_str()),
        "a deleted bot is never listed"
    );
}

#[tokio::test]
async fn tm_owner_erasure_removes_bot_membership_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "orphan-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("add");

    // Bot creators membership holds a Restrict edge to alice's user principal;
    // drop it first, as the account-erasure flow does.
    gauge::service::remove_group_member_user(BOT_CREATORS_GROUP_ID, "alice", &w.as_user("carol"))
        .await
        .expect("leave Bot creators");
    valence::delete_entity_now("user", "alice", &w.system)
        .await
        .ok();
    valence::delete_entity_now("bot", bot.as_str(), &w.system)
        .await
        .ok();

    assert_eq!(
        raw_count(&w.system, "bot").await,
        0,
        "owner erasure removes the bot"
    );
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 0);
}

#[tokio::test]
async fn tm_add_bot_by_group_owner_who_owns_bot_happy() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "alice_team", "alice").await;
    let bot = create_bot(&w, "alice", "team-bot").await;

    add_group_member_bot("alice_team", &bot, &w.as_user("alice"))
        .await
        .expect("group owner who owns the bot");

    assert!(bot_is_member(&w, "alice_team", &bot).await);
}

#[tokio::test]
async fn tm_add_bot_by_super_user_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "any-bot").await;
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("super user may add any bot");
    // Adding twice is a no-op.
    add_group_member_bot(READERS, &bot, &w.as_user("carol"))
        .await
        .expect("idempotent");
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 1);
}

#[tokio::test]
async fn tm_add_bot_by_group_owner_stranger_bot_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "bob_team", "bob").await;
    let bot = create_bot(&w, "alice", "someone-elses-bot").await;

    let err = add_group_member_bot("bob_team", &bot, &w.as_user("bob"))
        .await
        .expect_err("bob can't see alice's bot");

    assert!(
        matches!(service_error(&err), GaugeServiceError::NotFound { .. }),
        "{err:#}"
    );
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 0);
}

#[tokio::test]
async fn tm_add_bot_by_bot_owner_not_group_owner_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "pushy-bot").await;

    let err = add_group_member_bot(READERS, &bot, &w.as_user("alice"))
        .await
        .expect_err("alice doesn't own the readers group");

    assert!(
        matches!(service_error(&err), GaugeServiceError::NotAuthorized { .. }),
        "{err:#}"
    );
    assert_eq!(bot_holds(&w, &bot, READ).await, (false, false));
}

#[tokio::test]
async fn tm_add_bot_refused_for_bot_and_anonymous_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "self-adding-bot").await;
    for v in [w.as_bot(&bot), w.as_actor(Actor::Anonymous)] {
        assert!(add_group_member_bot(READERS, &bot, &v).await.is_err());
        assert!(remove_group_member_bot(READERS, &bot, &v).await.is_err());
    }
    assert_eq!(raw_count(&w.system, "permission_bot_principal").await, 0);
}

#[tokio::test]
async fn tm_remove_bot_member_happy() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "leaving-bot").await;
    let carol = w.as_user("carol");
    add_group_member_bot(READERS, &bot, &carol)
        .await
        .expect("add");
    assert_eq!(bot_holds(&w, &bot, READ).await, (true, true));

    remove_group_member_bot(READERS, &bot, &carol)
        .await
        .expect("remove");

    assert_eq!(bot_holds(&w, &bot, READ).await, (false, false));
    // Removing again is a no-op.
    remove_group_member_bot(READERS, &bot, &carol)
        .await
        .expect("idempotent remove");
}

#[tokio::test]
async fn tm_can_add_bot_group_owner_and_super_user_happy() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "alice_team", "alice").await;

    assert!(can_add_group_member_bot("alice_team", &w.as_user("alice"))
        .await
        .expect("owner check"));
    assert!(can_add_group_member_bot(READERS, &w.as_user("carol"))
        .await
        .expect("super user check"));
    // The answer matches what the add does.
    let bot = create_bot(&w, "alice", "checked-bot").await;
    add_group_member_bot("alice_team", &bot, &w.as_user("alice"))
        .await
        .expect("owner adds after a true check");
}

#[tokio::test]
async fn tm_can_add_bot_non_owner_and_super_user_group_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "hopeful-bot").await;

    assert!(!can_add_group_member_bot(READERS, &w.as_user("alice"))
        .await
        .expect("non-owner check"));
    assert!(add_group_member_bot(READERS, &bot, &w.as_user("alice"))
        .await
        .is_err());
    // Not even a super user may put a bot in the Super User group.
    assert!(
        !can_add_group_member_bot(SUPER_USER_GROUP_ID, &w.as_user("carol"))
            .await
            .expect("super user group check")
    );
}

#[tokio::test]
async fn tm_can_add_bot_refused_for_bot_and_anonymous_sad() {
    let w = world().await;
    let bot = create_bot(&w, "alice", "curious-bot").await;
    for v in [w.as_bot(&bot), w.as_actor(Actor::Anonymous)] {
        assert!(!can_add_group_member_bot(READERS, &v)
            .await
            .expect("non-user callers get false"));
    }
}

#[tokio::test]
async fn tm_can_add_bot_missing_group_sad() {
    let w = world().await;
    let err = can_add_group_member_bot("no_such_group", &w.as_user("carol"))
        .await
        .expect_err("missing group");
    assert!(
        matches!(service_error(&err), GaugeServiceError::NotFound { .. }),
        "{err:#}"
    );
}
