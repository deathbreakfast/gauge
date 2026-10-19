//! Gauge-backed Lepton service user gate and its boot seed (B3 K13–K15).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::generated::{Permission, PermissionServiceUserPrincipal};
use gauge::service::{add_group_member_service_user, add_group_member_user, GaugeServiceError};
use gauge::service_users::{
    seed_service_user_permissions, GaugeServiceUserGate, LEPTON_SERVICE_USER_CREATE,
    LEPTON_SERVICE_USER_MANAGE_ANY, SERVICE_USER_CREATORS_GROUP_ID,
};
use lepton::generated::ServiceUserAccount;
use lepton_identity::service_users::{ServiceUserGate, ServiceUserId};
use service_users_fixtures::{create_service_user, raw_count, world};
use valence::{Actor, Model, StringPredicate};

#[tokio::test]
async fn tm_gate_creator_may_create_happy() {
    let w = world().await;
    let alice = w.as_user("alice");
    assert!(GaugeServiceUserGate
        .may_create_service_user(&alice)
        .await
        .expect("gate"));
    assert!(!GaugeServiceUserGate
        .may_manage_any_service_user(&alice)
        .await
        .expect("gate"));
    // The privacy rule accepts the create too.
    let service_user = create_service_user(&w, "alice", "made").await;
    assert!(ServiceUserAccount::get(service_user.as_str(), &alice, valence::use_!(r"**Test:** Fixture **service user** load in gauge gate tests to confirm the owner sees the service user they created. CI and developers running the suite only.")).await.expect("get").is_some());
}

#[tokio::test]
async fn tm_gate_super_user_may_create_and_manage_happy() {
    let w = world().await;
    let carol = w.as_user("carol");
    assert!(GaugeServiceUserGate
        .may_create_service_user(&carol)
        .await
        .expect("gate"));
    assert!(GaugeServiceUserGate
        .may_manage_any_service_user(&carol)
        .await
        .expect("gate"));
    // Manage-any reaches someone else's service user through Lepton's rule.
    let service_user = create_service_user(&w, "alice", "managed").await;
    assert!(ServiceUserAccount::get(service_user.as_str(), &carol, valence::use_!(r"**Test:** Fixture **service user** load in gauge gate tests to confirm a super user can see any service user. CI and developers running the suite only.")).await.expect("get").is_some());
}

#[tokio::test]
async fn tm_gate_plain_user_denied_sad() {
    let w = world().await;
    let bob = w.as_user("bob");
    assert!(!GaugeServiceUserGate
        .may_create_service_user(&bob)
        .await
        .expect("gate"));
    assert!(!GaugeServiceUserGate
        .may_manage_any_service_user(&bob)
        .await
        .expect("gate"));
    let before = raw_count(&w.system, "service_user_account").await;
    let row = ServiceUserAccount::new(
        Some(valence::RecordId::new("user", "bob")),
        lepton::generated::ServiceUserAccountOwnerKind::User,
        Some(valence::RecordId::new("user", "bob")),
        "denied".into(),
        "deniedbot".into(),
        "Denied".into(),
        None,
        lepton::generated::ServiceUserAccountStatus::Active,
        None,
        chrono::Utc::now(),
        chrono::Utc::now(),
    )
    .expect("row");
    let err = ServiceUserAccount::upsert(ServiceUserId::new_v4().as_str(), row, &bob, valence::use_!(r"**Test:** Fixture **service user** save attempt in gauge gate tests that the gate must refuse. CI and developers running the suite only."))
        .await
        .expect_err("bob is not a service user creator");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(raw_count(&w.system, "service_user_account").await, before);
}

#[tokio::test]
async fn tm_gate_creator_cannot_manage_any_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "private").await;
    // dave becomes a service user creator too; that doesn't let him see alice's service user.
    add_group_member_user(SERVICE_USER_CREATORS_GROUP_ID, "dave", &w.as_user("carol"))
        .await
        .expect("add dave");
    let dave = w.as_user("dave");
    assert!(GaugeServiceUserGate
        .may_create_service_user(&dave)
        .await
        .expect("gate"));
    assert!(!GaugeServiceUserGate
        .may_manage_any_service_user(&dave)
        .await
        .expect("gate"));
    assert!(ServiceUserAccount::get(service_user.as_str(), &dave, valence::use_!(r"**Test:** Fixture **service user** load in gauge gate tests that must find nothing for another creator. CI and developers running the suite only.")).await.expect("get").is_none());
}

#[tokio::test]
async fn tm_gate_service_user_valence_denied_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "creator").await;
    // Even a service user placed in Service user creators gets no gate answer: Lepton's rules
    // refuse non-user callers before asking, and the service user holds nothing else.
    add_group_member_service_user(
        SERVICE_USER_CREATORS_GROUP_ID,
        &service_user,
        &w.as_user("carol"),
    )
    .await
    .expect("add service user");
    let service_user_v = w.as_service_user(&service_user);
    assert!(!GaugeServiceUserGate
        .may_manage_any_service_user(&service_user_v)
        .await
        .expect("gate"));
    let before = raw_count(&w.system, "service_user_account").await;
    let row = ServiceUserAccount::new(
        None,
        lepton::generated::ServiceUserAccountOwnerKind::User,
        None,
        "child".into(),
        "childbot".into(),
        "Child".into(),
        None,
        lepton::generated::ServiceUserAccountStatus::Active,
        None,
        chrono::Utc::now(),
        chrono::Utc::now(),
    )
    .expect("row");
    assert!(ServiceUserAccount::upsert(ServiceUserId::new_v4().as_str(), row, &service_user_v, valence::use_!(r"**Test:** Fixture **service user** save attempt by a service user in gauge gate tests that must be refused. CI and developers running the suite only.")).await.is_err());
    assert_eq!(raw_count(&w.system, "service_user_account").await, before);
}

#[tokio::test]
async fn tm_service_user_principal_delete_by_stranger_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "kept").await;
    add_group_member_service_user("test_readers", &service_user, &w.as_user("carol"))
        .await
        .expect("add");
    let principal_id = format!("svc:{}", service_user.as_str());
    let err = PermissionServiceUserPrincipal::delete(&principal_id, &w.as_user("bob"), valence::use_!(r"**Test:** Fixture **service user principal** delete attempt by a stranger in gauge gate tests that must be refused. CI and developers running the suite only."))
        .await
        .expect_err("bob neither owns the service user nor manages every service user");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        1
    );
}

#[tokio::test]
async fn tm_seed_service_user_permissions_idempotent_happy() {
    let w = world().await; // first seed ran inside `world`
    let again = seed_service_user_permissions(&w.system)
        .await
        .expect("second seed");
    assert_eq!(again.permissions_created, 0);
    for name in [LEPTON_SERVICE_USER_CREATE, LEPTON_SERVICE_USER_MANAGE_ANY] {
        let perms = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to confirm the boot seed made each service user permission once. CI and developers running the suite only."))
            .where_name(StringPredicate::Equals(name.into()))
            .await
            .expect("query");
        assert_eq!(perms.len(), 1, "{name}");
    }
    let create = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to count who holds service user creation. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(LEPTON_SERVICE_USER_CREATE.into()))
        .first()
        .await
        .expect("query")
        .expect("exists");
    let holders = create
        .get_allowed_principals_record_ids(&w.system, valence::use_!(r"**Test:** Fixture edge read in gauge gate tests to confirm Service user creators is granted service user creation exactly once. CI and developers running the suite only."))
        .await
        .expect("edges");
    assert_eq!(
        holders.len(),
        1,
        "only Service user creators, once: {holders:?}"
    );
    let manage = Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in gauge gate tests to confirm manage-any is granted to no group. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(LEPTON_SERVICE_USER_MANAGE_ANY.into()))
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
async fn tm_seed_service_user_permissions_not_system_sad() {
    let w = world().await;
    for v in [
        w.as_user("carol"),
        w.as_actor(Actor::Anonymous),
        w.as_actor(Actor::ServiceUser {
            service_name: "spectra-ingest".into(),
        }),
    ] {
        let err = seed_service_user_permissions(&v)
            .await
            .expect_err("System only");
        assert!(
            matches!(
                err.downcast_ref::<GaugeServiceError>(),
                Some(GaugeServiceError::NotAuthorized { .. })
            ),
            "{err:#}"
        );
    }
}
