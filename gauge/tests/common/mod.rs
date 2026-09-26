//! Shared in-memory Valence helpers for gauge integration tests.
//!
//! Gauge schemas use [`valence::MEM_ENGINE_ID`]; lepton `User` schemas still declare
//! [`valence::SQLITE_ENGINE_ID`]. The harness registers one tolerant mem backend under
//! both engine ids so cross-crate FK hops share storage. Unique-index DDL is treated as
//! success (same as lepton-auth `TolerantMemBackend`) so `AccountEmail` seeds work.

#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use gauge::super_user::SUPER_USER_GROUP_NAME;
use valence::{
    register_backend_logical_names, router_key, Actor, CompiledQuery, DatabaseBackend,
    DatabaseRouter, InMemoryBackend, Model, RecordId, RegisterBackendLogicalNamesOptions, Result,
    Valence, MEM_ENGINE_ID, SQLITE_ENGINE_ID,
};

/// Wraps [`InMemoryBackend`] and treats unsupported unique-index DDL as success.
#[derive(Debug)]
struct TolerantMemBackend {
    inner: InMemoryBackend,
}

impl TolerantMemBackend {
    fn new() -> Self {
        Self {
            inner: InMemoryBackend::new(),
        }
    }
}

#[async_trait]
impl DatabaseBackend for TolerantMemBackend {
    fn engine_id(&self) -> &'static str {
        self.inner.engine_id()
    }

    fn capabilities(&self) -> valence::BackendCapabilities {
        self.inner.capabilities()
    }

    async fn use_namespace(&self, ns: &str, db_name: &str) -> Result<()> {
        self.inner.use_namespace(ns, db_name).await
    }

    async fn execute_compiled_query(
        &self,
        compiled: &CompiledQuery,
    ) -> Result<Vec<serde_json::Value>> {
        self.inner.execute_compiled_query(compiled).await
    }

    async fn ensure_schemaless_table(&self, table: &str) -> Result<()> {
        self.inner.ensure_schemaless_table(table).await
    }

    async fn get_record(&self, table: &str, id: &str) -> Result<Option<serde_json::Value>> {
        self.inner.get_record(table, id).await
    }

    async fn create_record(
        &self,
        table: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.create_record(table, content).await
    }

    async fn update_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.update_record(table, id, content).await
    }

    async fn merge_record(
        &self,
        table: &str,
        id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.merge_record(table, id, patch).await
    }

    async fn upsert_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.upsert_record(table, id, content).await
    }

    async fn delete_record(&self, table: &str, id: &str) -> Result<()> {
        self.inner.delete_record(table, id).await
    }

    async fn relate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.relate_edge(from, edge_table, to).await
    }

    async fn unrelate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.unrelate_edge(from, edge_table, to).await
    }

    async fn get_edge_targets(&self, from: &RecordId, edge_table: &str) -> Result<Vec<RecordId>> {
        self.inner.get_edge_targets(from, edge_table).await
    }

    async fn define_unique_index(&self, table: &str, field: &str) -> Result<()> {
        match self.inner.define_unique_index(table, field).await {
            Ok(()) => Ok(()),
            Err(valence::Error::Internal(msg))
                if msg.contains("define_unique_index")
                    || msg.contains("unique indexes not supported") =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn ttl_capability(&self) -> valence::ttl::BackendTtlCapability {
        self.inner.ttl_capability()
    }

    async fn apply_ttl_policy(
        &self,
        table: &str,
        policy: &valence::ttl::SchemaTtlPolicy,
    ) -> Result<()> {
        self.inner.apply_ttl_policy(table, policy).await
    }
}

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();

    // SAFETY: test harness only; OnceLock reads this before first ownership get.
    unsafe {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

/// Fresh tolerant mem backend registered under gauge + lepton logical/engine keys.
pub fn mem_router() -> Arc<DatabaseRouter> {
    prepare_test_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(TolerantMemBackend::new());
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
    let user_created = lepton::generated::User::upsert(id, user, valence, valence::use_!(r"**Test:** Fixture **User** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert user");

    // Wire AccountEmail + primary_email so `seed_super_user_member_by_email` can resolve.
    let account_id = format!("acct_{id}");
    let account = lepton::generated::Account::new(
        "Test Account".to_string(),
        RecordId::new("user", id),
        Some(lepton::generated::AccountPlan::Free),
        Some(lepton::generated::AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("build account");
    let account_created = lepton::generated::Account::upsert(&account_id, account, valence, valence::use_!(r"**Test:** Fixture **Account** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert account");
    let account_thing = account_created.id().cloned().expect("account id");

    let email_row = lepton::generated::AccountEmail::new(
        account_thing,
        email.to_string(),
        confirmed_at,
        now,
        now,
    )
    .expect("build email");
    let email_id_key = format!("email_{id}");
    let email_created =
        lepton::generated::AccountEmail::upsert(&email_id_key, email_row, valence, valence::use_!(r"**Test:** Fixture **Account Email** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .await
            .expect("upsert email");
    let email_thing = email_created.id().cloned().expect("email id");

    user_created
        .get_mutable(valence, valence::use_!(r"**Test:** Fixture **this data** access in `mod` so the suite can arrange and assert persistence. CI and developers running the suite only."))
        .set_primary_email(email_thing)
        .expect("set user primary email")
        .set_updated_at(now)
        .expect("user updated_at")
        .commit()
        .await
        .expect("commit user primary email");
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
        gauge::generated::PermissionGroup::upsert("super_user_group", super_group, system, valence::use_!(r"**Test:** Fixture **Permission Group** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .await
            .expect("upsert super user group");

    let member = lepton::generated::User::get(member_user_id, system, valence::use_!(r"**Test:** Fixture **User** load for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
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
        valence::use_!(r"**Test:** Fixture **Permission User Principal** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert user principal");
    created
        .relate_to_owner_record(principal.id().expect("principal id exists"), system, valence::use_!(r"**Test:** Fixture owner-edge relate for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("relate super user owner");
    created
        .relate_to_member_record(principal.id().expect("principal id exists"), system, valence::use_!(r"**Test:** Fixture member-edge relate for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
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
    let created = gauge::generated::PermissionGroup::upsert(group_id, group, system, valence::use_!(r"**Test:** Fixture **Permission Group** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert group");

    let owner = lepton::generated::User::get(owner_user_id, system, valence::use_!(r"**Test:** Fixture **User** load for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
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
        valence::use_!(r"**Test:** Fixture **Permission User Principal** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert principal");
    created
        .relate_to_owner_record(principal.id().expect("principal id"), system, valence::use_!(r"**Test:** Fixture owner-edge relate for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
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
    lepton::generated::Account::upsert(account_id, account, v, valence::use_!(r"**Test:** Fixture **Account** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
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
    lepton::generated::AccountMembership::upsert(id, membership, v, valence::use_!(r"**Test:** Fixture **Account Membership** save for `common` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert membership");
}
