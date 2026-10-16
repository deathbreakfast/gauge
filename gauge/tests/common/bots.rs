//! Bot fixtures for gauge integration tests: the real Gauge bot gate, the boot
//! seed, a bot owner in "Bot creators", and bots created through Lepton's own
//! privacy rules.

#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Once;

use chrono::Utc;
use gauge::bots::{install_gauge_bot_gate, seed_bot_permissions, BOT_CREATORS_GROUP_ID};
use gauge::manifest_sync::{
    sync_permission_manifests, PermissionDomainInput, PermissionInput, PermissionManifestInput,
};
use gauge::resource_permissions::ensure_group_granted_permission;
use lepton::generated::{Bot, BotOwnerKind, BotStatus};
use lepton_identity::bots::BotId;
use valence::{Actor, Model, RecordId, Valence};

use crate::common::{mem_router, seed_super_user_group_with_member, seed_user, valence_for};

/// Permission the test group holds.
pub const READ: &str = "test.records.read";
/// Group that holds [`READ`]; it has no owners, so only super users edit it.
pub const READERS: &str = "test_readers";

pub struct World {
    pub system: Valence,
    router: std::sync::Arc<valence::DatabaseRouter>,
}

impl World {
    pub fn as_user(&self, id: &str) -> Valence {
        valence_for(
            self.router.clone(),
            Actor::User {
                user_id: id.to_string(),
            },
        )
    }

    pub fn as_bot(&self, bot: &BotId) -> Valence {
        valence_for(self.router.clone(), bot.actor())
    }

    pub fn as_actor(&self, actor: Actor) -> Valence {
        valence_for(self.router.clone(), actor)
    }
}

/// Install the Gauge gate once per test binary.
pub fn install_gate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        install_gauge_bot_gate().expect("first gate install in this binary");
    });
}

/// **Test:** seeded world: boot seed, a super user `carol`, a bot owner `alice`
/// in "Bot creators", and the [`READERS`] group holding [`READ`].
pub async fn world() -> World {
    install_gate();
    let router = mem_router();
    let system = valence_for(
        router.clone(),
        Actor::System {
            operation: "test_seed".into(),
        },
    );
    let _stats = seed_bot_permissions(&system)
        .await
        .expect("seed bot permissions");
    seed_user("carol", "carol@example.test", &system).await;
    seed_super_user_group_with_member(&system, "carol").await;
    for id in ["alice", "bob", "dave"] {
        seed_user(id, &format!("{id}@example.test"), &system).await;
    }
    let world = World { system, router };
    gauge::service::add_group_member_user(BOT_CREATORS_GROUP_ID, "alice", &world.as_user("carol"))
        .await
        .expect("alice joins Bot creators");
    sync_permission_manifests(
        &world.system,
        &[PermissionManifestInput {
            app_id: "test-records".into(),
            domains: vec![PermissionDomainInput {
                key: "test_records".into(),
                name: "Test records".into(),
                description: "Fixture domain".into(),
                permissions: vec![PermissionInput {
                    name: READ.into(),
                    description: "Read fixture records".into(),
                }],
            }],
        }],
    )
    .await
    .expect("sync fixture manifest");
    ensure_group_granted_permission(
        &world.system,
        READERS,
        "Test readers",
        "Fixture readers",
        READ,
        &[],
    )
    .await
    .expect("readers group");
    world
}

/// **Test:** create a bot owned by `owner` through Lepton's privacy rules (the
/// owner must be allowed by the installed Gauge gate).
pub async fn create_bot(world: &World, owner: &str, handle: &str) -> BotId {
    let v = world.as_user(owner);
    let id = BotId::new_v4();
    let owner_ref = RecordId::new("user", owner);
    let now = Utc::now();
    let row = Bot::new(
        Some(owner_ref.clone()),
        BotOwnerKind::User,
        Some(owner_ref),
        handle.to_string(),
        handle.replace('-', ""),
        "Fixture bot".to_string(),
        None,
        BotStatus::Active,
        None,
        now,
        now,
    )
    .expect("bot row");
    Bot::upsert(id.as_str(), row, &v, valence::use_!(r"**Test:** Fixture **bot account** save for gauge bot tests so the suite can grant and check bot permissions. CI and developers running the suite only."))
        .await
        .expect("owner creates bot");
    id
}

/// **Test:** set a bot's status as its owner.
pub async fn set_bot_status(world: &World, owner: &str, bot: &BotId, status: BotStatus) {
    let v = world.as_user(owner);
    let row = Bot::get(bot.as_str(), &v, valence::use_!(r"**Test:** Fixture **bot account** load for gauge bot tests before changing its status. CI and developers running the suite only."))
        .await
        .expect("load bot")
        .expect("bot exists");
    row.get_mutable(&v, valence::use_!(r"**Test:** Fixture **bot account** status change for gauge bot tests. CI and developers running the suite only."))
        .set_status(status)
        .expect("status")
        .commit()
        .await
        .expect("commit status");
}

/// Count rows in a gauge table with a raw read (System fixture view).
pub async fn raw_count(system: &Valence, table: &str) -> usize {
    let backend = system.backend_for_table(table).expect("backend");
    backend
        .execute_compiled_query(&valence::__internal::CompiledQuery {
            query_string: format!("SELECT * FROM {table}"),
            params: vec![],
        })
        .await
        .map_or(0, |rows| rows.len())
}
