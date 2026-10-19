//! Service users hold Gauge permissions only through group membership (B3 K2–K10).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::actor_can_raw::actor_can_raw;
use gauge::service::{
    actor_can, add_group_member_group, add_group_member_service_user, add_group_member_user,
    can_add_group_member_service_user, get_group_detail, remove_group_member_service_user,
    GaugeServiceError,
};
use gauge::service_users::SERVICE_USER_CREATORS_GROUP_ID;
use gauge::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID};
use lepton::generated::ServiceUserAccountStatus;
use lepton_identity::service_users::ServiceUserId;
use service_users_fixtures::{
    create_service_user, raw_count, set_service_user_status, world, READ, READERS,
};
use valence::{Actor, Model};

async fn service_user_holds(
    world: &service_users_fixtures::World,
    service_user: &ServiceUserId,
    permission: &str,
) -> (bool, bool) {
    let v = world.as_service_user(service_user);
    let typed = actor_can(&v, permission).await.expect("actor_can");
    let raw = actor_can_raw(&v, permission).await.expect("actor_can_raw");
    (typed, raw)
}

/// The group's member edges include the service user's principal row.
async fn service_user_is_member(
    world: &service_users_fixtures::World,
    group_id: &str,
    service_user: &ServiceUserId,
) -> bool {
    let group = gauge::generated::PermissionGroup::get(group_id, &world.system, valence::use_!(r"**Test:** Fixture **permission group** load in gauge service user tests to check its member edges. CI and developers running the suite only."))
        .await
        .expect("group")
        .expect("group exists");
    let principal = valence::RecordId::new(
        "permission_service_user_principal",
        format!("svc:{}", service_user.as_str()),
    );
    group
        .get_members_record_ids(&world.system, valence::use_!(r"**Test:** Fixture member-edge read in gauge service user tests to check whether a service user is a member. CI and developers running the suite only."))
        .await
        .expect("members")
        .contains(&principal)
}

fn service_error(err: &anyhow::Error) -> &GaugeServiceError {
    err.downcast_ref::<GaugeServiceError>()
        .unwrap_or_else(|| panic!("expected GaugeServiceError, got {err:#}"))
}

#[tokio::test]
async fn tm_service_user_member_gets_group_permission_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader").await;
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false),
        "nothing before joining"
    );

    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("super user adds service user");

    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (true, true)
    );
    assert!(service_user_is_member(&w, READERS, &service_user).await);
    // Group screens list users and groups only; a service user member is never shown as a user.
    let detail = get_group_detail(READERS, &w.as_user("carol"))
        .await
        .expect("detail")
        .expect("group exists");
    assert!(detail.members.iter().all(|m| m.id != service_user.as_str()));
}

#[tokio::test]
async fn tm_service_user_not_member_denied_sad() {
    let w = world().await;
    let member = create_service_user(&w, "alice", "member").await;
    let outsider = create_service_user(&w, "alice", "outsider").await;
    add_group_member_service_user(READERS, &member, &w.as_user("carol"))
        .await
        .expect("add member");

    assert_eq!(
        service_user_holds(&w, &member, READ).await,
        (true, true),
        "same fixture grants a member"
    );
    assert_eq!(
        service_user_holds(&w, &outsider, READ).await,
        (false, false)
    );
    assert_eq!(
        service_user_holds(&w, &member, "test.records.write").await,
        (false, false)
    );
}

#[tokio::test]
async fn tm_service_user_nested_group_membership_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "nested").await;
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
    add_group_member_service_user(&child_id, &service_user, &carol)
        .await
        .expect("add to child");

    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (true, true)
    );
}

#[tokio::test]
async fn tm_service_user_suspended_member_denied_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "paused").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    set_service_user_status(
        &w,
        "alice",
        &service_user,
        ServiceUserAccountStatus::Suspended,
    )
    .await;
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false)
    );

    set_service_user_status(&w, "alice", &service_user, ServiceUserAccountStatus::Active).await;
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (true, true),
        "resume restores access"
    );
}

#[tokio::test]
async fn tm_service_user_pending_deletion_member_denied_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "doomed").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    lepton::generated::ServiceUserAccount::delete(service_user.as_str(), &w.as_user("alice"), valence::use_!(r"**Test:** Fixture **service user** delete for gauge service user tests so the suite can check a service user being deleted loses access. CI and developers running the suite only."))
        .await
        .expect("queue delete");

    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false)
    );
}

#[tokio::test]
async fn tm_infra_service_user_denied_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "real").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    for name in [
        "spectra-ingest".to_string(),
        format!("svc:svc:{}", service_user.as_str()),
        "svc:not-a-uuid".to_string(),
        service_user.as_str().to_string(),
        service_user.as_str().to_uppercase(),
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

/// The retired `bot:<uuid>` actor name gets nothing, even when a registered
/// service user with that uuid exists, is active, and sits in the group.
#[tokio::test]
async fn tm_legacy_bot_actor_denied_even_with_row_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "legacy").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (true, true)
    );

    let legacy = w.as_actor(Actor::ServiceUser {
        service_name: format!("bot:{}", service_user.as_str()),
    });
    assert!(!actor_can(&legacy, READ).await.expect("actor_can"));
    assert!(!actor_can_raw(&legacy, READ).await.expect("actor_can_raw"));
    assert!(
        add_group_member_service_user(READERS, &service_user, &legacy)
            .await
            .is_err()
    );
    assert!(
        remove_group_member_service_user(READERS, &service_user, &legacy)
            .await
            .is_err()
    );
    // The registered service user keeps its membership.
    assert!(service_user_is_member(&w, READERS, &service_user).await);
}

#[tokio::test]
async fn tm_service_user_and_user_same_uuid_isolated_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "twin").await;
    // A user whose id is the service user's uuid, in the readers group.
    common::seed_user(service_user.as_str(), "twin@example.test", &w.system).await;
    add_group_member_user(READERS, service_user.as_str(), &w.as_user("carol"))
        .await
        .expect("add user");

    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false),
        "user grant must not reach the service user"
    );

    // And the other way round: a member service user does not grant a user with its uuid.
    let other = create_service_user(&w, "alice", "other-twin").await;
    common::seed_user(other.as_str(), "twin2@example.test", &w.system).await;
    add_group_member_service_user(READERS, &other, &w.as_user("carol"))
        .await
        .expect("add service user");
    let user = w.as_user(other.as_str());
    assert!(!actor_can(&user, READ).await.expect("actor_can"));
}

#[tokio::test]
async fn tm_service_user_never_super_user_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "ambitious").await;
    let carol = w.as_user("carol");

    let err = add_group_member_service_user(SUPER_USER_GROUP_ID, &service_user, &carol)
        .await
        .expect_err("service users never join the Super User group");
    assert!(
        matches!(service_error(&err), GaugeServiceError::Validation { .. }),
        "{err:#}"
    );

    // Even through a group nested under the Super User group.
    add_group_member_group(SUPER_USER_GROUP_ID, READERS, &carol)
        .await
        .ok();
    add_group_member_service_user(READERS, &service_user, &carol)
        .await
        .expect("add to readers");
    let v = w.as_service_user(&service_user);
    assert!(!actor_is_super_user(&v).await.expect("super user check"));
    assert!(!actor_can(&v, "lepton.service_user.manage_any")
        .await
        .expect("manage any"));
}

#[tokio::test]
async fn tm_service_user_delete_removes_principal_and_membership_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "gone").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        1
    );

    valence::delete_entity_now("service_user_account", service_user.as_str(), &w.system)
        .await
        .expect("purge service user");

    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        0
    );
    // Valence leaves the group's member edge pointing at the deleted principal
    // (incoming many-to-many edges are only removed for `SetNull` connections).
    // It names no row that still exists and grants nothing.
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false)
    );
    let detail = get_group_detail(READERS, &w.as_user("carol"))
        .await
        .expect("detail")
        .expect("group exists");
    assert!(
        detail.members.iter().all(|m| m.id != service_user.as_str()),
        "a deleted service user is never listed"
    );
}

#[tokio::test]
async fn tm_owner_erasure_removes_service_user_membership_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "orphan").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    // Service user creators membership holds a Restrict edge to alice's user principal;
    // drop it first, as the account-erasure flow does.
    gauge::service::remove_group_member_user(
        SERVICE_USER_CREATORS_GROUP_ID,
        "alice",
        &w.as_user("carol"),
    )
    .await
    .expect("leave Service user creators");
    valence::delete_entity_now("user", "alice", &w.system)
        .await
        .ok();
    valence::delete_entity_now("service_user_account", service_user.as_str(), &w.system)
        .await
        .ok();

    assert_eq!(
        raw_count(&w.system, "service_user_account").await,
        0,
        "owner erasure removes the service user"
    );
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        0
    );
}

#[tokio::test]
async fn tm_add_service_user_by_group_owner_who_owns_service_user_happy() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "alice_team", "alice").await;
    let service_user = create_service_user(&w, "alice", "team-agent").await;

    add_group_member_service_user("alice_team", &service_user, &w.as_user("alice"))
        .await
        .expect("group owner who owns the service user");

    assert!(service_user_is_member(&w, "alice_team", &service_user).await);
}

#[tokio::test]
async fn tm_add_service_user_by_super_user_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "any").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("super user may add any service user");
    // Adding twice is a no-op.
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("idempotent");
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        1
    );
}

#[tokio::test]
async fn tm_add_service_user_by_group_owner_stranger_service_user_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "bob_team", "bob").await;
    let service_user = create_service_user(&w, "alice", "someone-elses").await;

    let err = add_group_member_service_user("bob_team", &service_user, &w.as_user("bob"))
        .await
        .expect_err("bob can't see alice's service user");

    assert!(
        matches!(service_error(&err), GaugeServiceError::NotFound { .. }),
        "{err:#}"
    );
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        0
    );
}

#[tokio::test]
async fn tm_add_service_user_by_service_user_owner_not_group_owner_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "pushy").await;

    let err = add_group_member_service_user(READERS, &service_user, &w.as_user("alice"))
        .await
        .expect_err("alice doesn't own the readers group");

    assert!(
        matches!(service_error(&err), GaugeServiceError::NotAuthorized { .. }),
        "{err:#}"
    );
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false)
    );
}

#[tokio::test]
async fn tm_add_service_user_refused_for_service_user_and_anonymous_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "self-adding").await;
    for v in [
        w.as_service_user(&service_user),
        w.as_actor(Actor::Anonymous),
    ] {
        assert!(add_group_member_service_user(READERS, &service_user, &v)
            .await
            .is_err());
        assert!(remove_group_member_service_user(READERS, &service_user, &v)
            .await
            .is_err());
    }
    assert_eq!(
        raw_count(&w.system, "permission_service_user_principal").await,
        0
    );
}

#[tokio::test]
async fn tm_remove_service_user_member_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "leaving").await;
    let carol = w.as_user("carol");
    add_group_member_service_user(READERS, &service_user, &carol)
        .await
        .expect("add");
    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (true, true)
    );

    remove_group_member_service_user(READERS, &service_user, &carol)
        .await
        .expect("remove");

    assert_eq!(
        service_user_holds(&w, &service_user, READ).await,
        (false, false)
    );
    // Removing again is a no-op.
    remove_group_member_service_user(READERS, &service_user, &carol)
        .await
        .expect("idempotent remove");
}

#[tokio::test]
async fn tm_can_add_service_user_group_owner_and_super_user_happy() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, "alice_team", "alice").await;

    assert!(
        can_add_group_member_service_user("alice_team", &w.as_user("alice"))
            .await
            .expect("owner check")
    );
    assert!(
        can_add_group_member_service_user(READERS, &w.as_user("carol"))
            .await
            .expect("super user check")
    );
    // The answer matches what the add does.
    let service_user = create_service_user(&w, "alice", "checked").await;
    add_group_member_service_user("alice_team", &service_user, &w.as_user("alice"))
        .await
        .expect("owner adds after a true check");
}

#[tokio::test]
async fn tm_can_add_service_user_non_owner_and_super_user_group_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "hopeful").await;

    assert!(
        !can_add_group_member_service_user(READERS, &w.as_user("alice"))
            .await
            .expect("non-owner check")
    );
    assert!(
        add_group_member_service_user(READERS, &service_user, &w.as_user("alice"))
            .await
            .is_err()
    );
    // Not even a super user may put a service user in the Super User group.
    assert!(
        !can_add_group_member_service_user(SUPER_USER_GROUP_ID, &w.as_user("carol"))
            .await
            .expect("super user group check")
    );
}

#[tokio::test]
async fn tm_can_add_service_user_refused_for_service_user_and_anonymous_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "curious").await;
    for v in [
        w.as_service_user(&service_user),
        w.as_actor(Actor::Anonymous),
    ] {
        assert!(!can_add_group_member_service_user(READERS, &v)
            .await
            .expect("non-user callers get false"));
    }
}

#[tokio::test]
async fn tm_can_add_service_user_missing_group_sad() {
    let w = world().await;
    let err = can_add_group_member_service_user("no_such_group", &w.as_user("carol"))
        .await
        .expect_err("missing group");
    assert!(
        matches!(service_error(&err), GaugeServiceError::NotFound { .. }),
        "{err:#}"
    );
}
