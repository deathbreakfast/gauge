//! Shared in-memory Valence helpers for gauge integration tests.
//!
//! Gauge schemas use [`valence::MEM_ENGINE_ID`]; lepton `User` schemas still declare
//! [`valence::SQLITE_ENGINE_ID`]. The harness registers one [`InMemoryBackend`] under
//! both engine ids so cross-crate FK hops share storage.

#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chrono::Utc;
use gauge::super_user::SUPER_USER_GROUP_NAME;
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    InMemoryBackend, Model, RecordId, RegisterBackendLogicalNamesOptions, Valence, MEM_ENGINE_ID,
    SQLITE_ENGINE_ID,
};

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();

    // SAFETY: test harness only; OnceLock reads this before first ownership get.
    unsafe {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

/// Fresh [`InMemoryBackend`] registered under gauge + lepton logical/engine keys.
pub fn mem_router() -> Arc<DatabaseRouter> {
    prepare_test_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        Arc::clone(&backend),
        gauge::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions {
            // Lepton identity schemas still route via SQLITE_ENGINE_ID.
            register_alias_engine_id: Some(SQLITE_ENGINE_ID),
        },
    );
    // Also ensure explicit sqlite:default even if logical-name list is empty.
    router.register(
        router_key(gauge::embedded_surreal::LOGICAL_NAME, SQLITE_ENGINE_ID),
        backend,
    );
    Arc::new(router)
}

pub fn valence_for(router: Arc<DatabaseRouter>, actor: Actor) -> Valence {
    Valence::builder()
        .database_router(router)
        .default_backend_key(router_key(
            gauge::embedded_surreal::LOGICAL_NAME,
            MEM_ENGINE_ID,
        ))
        .with_actor(actor)
        .build()
        .expect("valence build")
}

pub async fn test_valence(actor: Actor) -> Valence {
    valence_for(mem_router(), actor)
}

pub async fn seed_user(id: &str, email: &str, valence: &Valence) {
    seed_user_with(id, email, true, valence).await;
}

pub async fn seed_user_with(id: &str, email: &str, email_verified: bool, valence: &Valence) {
    let _ = email; // retained for call-site readability; email lives on AccountEmail upstream
    let now = Utc::now();
    let confirmed_at = email_verified.then_some(now);
    let user = lepton::generated::User::new(
        Some(lepton::generated::UserUserType::Person),
        Some("test-password-hash".to_string()),
        Some(lepton::generated::UserStatus::Active),
        None,
        None,
        confirmed_at,
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    lepton::generated::User::upsert(id, user, valence)
        .await
        .expect("upsert user");
}

pub fn record_pk_id(rid: Option<&valence::RecordId>) -> String {
    rid.and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default()
}

/// Upsert the Super User group and attach `member_user_id` as owner + member principal.
pub async fn seed_super_user_group_with_member(system: &Valence, member_user_id: &str) {
    let super_group = gauge::generated::PermissionGroup::new(
        SUPER_USER_GROUP_NAME.to_string(),
        Some("super users".to_string()),
        Utc::now(),
        Utc::now(),
    )
    .expect("build super user group");
    let created =
        gauge::generated::PermissionGroup::upsert("super_user_group", super_group, system)
            .await
            .expect("upsert super user group");

    let member = lepton::generated::User::get(member_user_id, system)
        .await
        .expect("query member user")
        .expect("member user exists");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{member_user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            member.id().expect("member id exists").clone(),
            member_user_id.to_string(),
        )
        .expect("new user principal"),
        system,
    )
    .await
    .expect("upsert user principal");
    created
        .relate_to_owner_record(principal.id().expect("principal id exists"), system)
        .await
        .expect("relate super user owner");
    created
        .relate_to_member_record(principal.id().expect("principal id exists"), system)
        .await
        .expect("relate super user member");
}

/// Upsert a permission group and attach `owner_user_id` as owner principal.
pub async fn seed_group_with_owner(
    system: &Valence,
    group_id: &str,
    owner_user_id: &str,
) -> gauge::generated::PermissionGroup {
    seed_user(
        owner_user_id,
        &format!("{owner_user_id}@example.test"),
        system,
    )
    .await;

    let group = gauge::generated::PermissionGroup::new(
        format!("group-{group_id}"),
        Some("group for privacy tests".to_string()),
        Utc::now(),
        Utc::now(),
    )
    .expect("build group");
    let created = gauge::generated::PermissionGroup::upsert(group_id, group, system)
        .await
        .expect("upsert group");

    let owner = lepton::generated::User::get(owner_user_id, system)
        .await
        .expect("query owner")
        .expect("owner exists");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{owner_user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            owner.id().expect("owner id").clone(),
            owner_user_id.to_string(),
        )
        .expect("new principal"),
        system,
    )
    .await
    .expect("upsert principal");
    created
        .relate_to_owner_record(principal.id().expect("principal id"), system)
        .await
        .expect("relate owner");
    created
}

/// Seed an account + membership row used by Super User sync scripts.
pub async fn seed_membership(
    id: &str,
    account_id: &str,
    user_id: &str,
    role: lepton::generated::AccountMembershipRole,
    v: &Valence,
) {
    let account = lepton::generated::Account::new(
        "Test Account".to_string(),
        RecordId::new("user", user_id),
        Some(lepton::generated::AccountPlan::Free),
        Some(lepton::generated::AccountStatus::Active),
        None,
        None,
        Utc::now(),
        Utc::now(),
    )
    .expect("build account");
    lepton::generated::Account::upsert(account_id, account, v)
        .await
        .expect("upsert account");

    let membership = lepton::generated::AccountMembership::new(
        RecordId::new("account", account_id),
        RecordId::new("user", user_id),
        role,
        Utc::now(),
        Utc::now(),
    )
    .expect("build membership");
    lepton::generated::AccountMembership::upsert(id, membership, v)
        .await
        .expect("upsert membership");
}
