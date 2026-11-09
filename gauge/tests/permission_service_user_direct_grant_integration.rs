//! Direct grant and revoke of a permission to a service user: the caller must edit the permission,
//! and a grant also needs the caller to see the service user.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::actor_can_raw::actor_can_raw;
use gauge::generated::Permission;
use gauge::service::{
    add_group_member_user, add_group_owner_user, grant_permission_to_service_user_checked,
    list_history, revoke_permission_from_service_user, GaugeServiceError,
};
use gauge::service_users::SERVICE_USER_CREATORS_GROUP_ID;
use gauge::super_user::SUPER_USER_GROUP_ID;
use lepton_identity::service_users::ServiceUserId;
use service_users_fixtures::{create_service_user, raw_count, world, World, READ};
use valence::StringPredicate;

const PRINCIPALS: &str = "permission_service_user_principal";

/// `alice` is a super user (so she edits every permission) and owns the service users she makes.
async fn world_with_super_alice() -> World {
    let w = world().await;
    add_group_member_user(SUPER_USER_GROUP_ID, "alice", &w.as_user("carol"))
        .await
        .expect("alice becomes a super user");
    add_group_member_user(SERVICE_USER_CREATORS_GROUP_ID, "bob", &w.as_user("carol"))
        .await
        .expect("bob may create service users");
    w
}

async fn read_permission(w: &World) -> Permission {
    Permission::query(&w.system, valence::use_!(r"**Test:** Fixture **permission** lookup in the direct service user grant tests to find the readers permission id. CI and developers running the suite only."))
        .where_name(StringPredicate::Equals(READ.into()))
        .first()
        .await
        .unwrap()
        .unwrap()
}

async fn read_permission_id(w: &World) -> String {
    read_permission(w)
        .await
        .id()
        .and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap()
}

async fn holds(w: &World, service_user: &ServiceUserId) -> bool {
    actor_can_raw(&w.as_service_user(service_user), READ)
        .await
        .expect("actor_can_raw")
}

/// Grant/revoke history for the permission, sorted (history timestamps can tie): `"grant"` or `"revoke"` per row.
async fn actions(w: &World, permission_id: &str) -> Vec<&'static str> {
    let rows = list_history(
        &w.as_user("alice"),
        Some("permission".to_string()),
        Some(permission_id.to_string()),
    )
    .await
    .expect("history");
    let mut out: Vec<&'static str> = rows
        .into_iter()
        .flat_map(|r| r.diffs)
        .filter(|d| d.field == "granted_service_users")
        .map(|d| {
            if d.new_value.is_null() {
                "revoke"
            } else {
                "grant"
            }
        })
        .collect();
    out.sort_unstable();
    out
}

#[tokio::test]
async fn owner_grants_then_revokes_visible_service_user_happy() {
    let w = world_with_super_alice().await;
    let id = read_permission_id(&w).await;
    let su = create_service_user(&w, "alice", "direct-bot").await;
    assert!(!holds(&w, &su).await);

    grant_permission_to_service_user_checked(&id, &su, &w.as_user("alice"))
        .await
        .expect("grant");
    assert!(holds(&w, &su).await);
    // Granting again changes nothing.
    grant_permission_to_service_user_checked(&id, &su, &w.as_user("alice"))
        .await
        .expect("second grant");

    revoke_permission_from_service_user(&id, &su, &w.as_user("alice"))
        .await
        .expect("revoke");
    assert!(!holds(&w, &su).await);

    assert_eq!(actions(&w, &id).await, vec!["grant", "revoke"]);
}

#[tokio::test]
async fn grant_to_service_user_caller_cannot_see_is_not_found_sad() {
    let w = world_with_super_alice().await;
    let id = read_permission_id(&w).await;
    // dave owns the permission's owners group but isn't a super user, so he can edit the
    // permission without seeing bob's service user.
    let owners = valence::extract_id_from_record(read_permission(&w).await.owners_group()).unwrap();
    add_group_owner_user(&owners, "dave", &w.as_user("carol"))
        .await
        .expect("dave owns the permission");
    let su = create_service_user(&w, "bob", "bobs-bot").await;
    let principals = raw_count(&w.system, PRINCIPALS).await;

    let err = grant_permission_to_service_user_checked(&id, &su, &w.as_user("dave"))
        .await
        .expect_err("dave can't see bob's service user");

    assert!(matches!(
        err.downcast_ref::<GaugeServiceError>(),
        Some(GaugeServiceError::NotFound { .. })
    ));
    assert!(!holds(&w, &su).await);
    assert_eq!(raw_count(&w.system, PRINCIPALS).await, principals);
    assert!(actions(&w, &id).await.is_empty());
}

#[tokio::test]
async fn caller_who_cannot_edit_permission_is_not_authorized_sad() {
    let w = world_with_super_alice().await;
    let id = read_permission_id(&w).await;
    let mine = create_service_user(&w, "alice", "mine").await;
    grant_permission_to_service_user_checked(&id, &mine, &w.as_user("alice"))
        .await
        .expect("grant");

    // bob owns a service user but can't edit the permission.
    let bobs = create_service_user(&w, "bob", "bobs-other-bot").await;
    for err in [
        grant_permission_to_service_user_checked(&id, &bobs, &w.as_user("bob"))
            .await
            .expect_err("grant"),
        revoke_permission_from_service_user(&id, &mine, &w.as_user("bob"))
            .await
            .expect_err("revoke"),
    ] {
        assert!(matches!(
            err.downcast_ref::<GaugeServiceError>(),
            Some(GaugeServiceError::NotAuthorized { .. })
        ));
    }
    assert!(!holds(&w, &bobs).await);
    assert!(holds(&w, &mine).await);
    assert_eq!(actions(&w, &id).await, vec!["grant"]);
}

#[tokio::test]
async fn revoking_a_grant_the_service_user_does_not_hold_is_a_noop() {
    let w = world_with_super_alice().await;
    let id = read_permission_id(&w).await;
    let su = create_service_user(&w, "alice", "idle-bot").await;
    let principals = raw_count(&w.system, PRINCIPALS).await;

    revoke_permission_from_service_user(&id, &su, &w.as_user("alice"))
        .await
        .expect("no-op revoke");

    assert_eq!(raw_count(&w.system, PRINCIPALS).await, principals);
    assert!(actions(&w, &id).await.is_empty());
}
