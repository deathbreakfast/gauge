//! A service user's groups and held permissions, as its owner or a super user sees them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::service::{
    actor_can, add_group_member_group, add_group_member_service_user, create_group,
    list_service_user_groups, list_service_user_permissions, remove_group_member_service_user,
    GaugeServiceError,
};
use gauge::types::PermissionGroupCreateInput;
use lepton::generated::ServiceUserAccountStatus;
use lepton_identity::service_users::ServiceUserId;
use service_users_fixtures::{create_service_user, set_service_user_status, world, READ, READERS};

fn is_not_found(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<GaugeServiceError>(),
        Some(GaugeServiceError::NotFound { .. })
    )
}

#[tokio::test]
async fn owner_sees_groups_and_permissions_happy() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .expect("add");

    let groups = list_service_user_groups(&su, &w.as_user("alice"))
        .await
        .expect("groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, READERS);
    let permissions = list_service_user_permissions(&su, &w.as_user("alice"))
        .await
        .expect("permissions");
    assert!(permissions.iter().any(|p| p.name == READ));
    assert!(actor_can(&w.as_service_user(&su), READ).await.unwrap());
}

#[tokio::test]
async fn super_user_sees_the_same_view_happy() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .expect("add");
    let groups = list_service_user_groups(&su, &w.as_user("carol"))
        .await
        .expect("groups");
    assert_eq!(groups.len(), 1);
}

#[tokio::test]
async fn nested_group_membership_counts_happy() {
    let w = world().await;
    let carol = w.as_user("carol");
    let su = create_service_user(&w, "alice", "reader-bot").await;
    let child = create_group(
        PermissionGroupCreateInput {
            name: "Agents".into(),
            description: String::new(),
        },
        &carol,
    )
    .await
    .expect("child group");
    let child_id = child.id().map(|r| r.id().to_string()).expect("child id");
    add_group_member_group(READERS, &child_id, &carol)
        .await
        .expect("nest");
    add_group_member_service_user(&child_id, &su, &carol)
        .await
        .expect("add");

    let groups = list_service_user_groups(&su, &w.as_user("alice"))
        .await
        .expect("groups");
    assert!(groups.iter().any(|g| g.id == child_id));
    assert!(groups.iter().any(|g| g.id == READERS));
    let permissions = list_service_user_permissions(&su, &w.as_user("alice"))
        .await
        .expect("permissions");
    assert!(permissions.iter().any(|p| p.name == READ));
}

#[tokio::test]
async fn removed_service_user_has_empty_lists_happy() {
    let w = world().await;
    let carol = w.as_user("carol");
    let su = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &su, &carol)
        .await
        .expect("add");
    remove_group_member_service_user(READERS, &su, &carol)
        .await
        .expect("remove");
    let alice = w.as_user("alice");
    assert!(list_service_user_groups(&su, &alice)
        .await
        .unwrap()
        .is_empty());
    assert!(list_service_user_permissions(&su, &alice)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn suspended_service_user_has_empty_lists_sad() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .expect("add");
    set_service_user_status(&w, "alice", &su, ServiceUserAccountStatus::Suspended).await;
    let alice = w.as_user("alice");
    assert!(list_service_user_groups(&su, &alice)
        .await
        .unwrap()
        .is_empty());
    assert!(list_service_user_permissions(&su, &alice)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn other_user_gets_not_found_sad() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader-bot").await;
    let bob = w.as_user("bob");
    let err = list_service_user_groups(&su, &bob).await.unwrap_err();
    assert!(is_not_found(&err), "{err}");
    let err = list_service_user_permissions(&su, &bob).await.unwrap_err();
    assert!(is_not_found(&err), "{err}");
}

#[tokio::test]
async fn unknown_service_user_gets_not_found_sad() {
    let w = world().await;
    let missing = ServiceUserId::new_v4();
    let err = list_service_user_groups(&missing, &w.as_user("carol"))
        .await
        .unwrap_err();
    assert!(is_not_found(&err), "{err}");
}

#[tokio::test]
async fn service_user_and_anonymous_callers_are_refused_sad() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .expect("add");
    assert!(list_service_user_groups(&su, &w.as_service_user(&su))
        .await
        .is_err());
    assert!(
        list_service_user_permissions(&su, &w.as_actor(valence::Actor::Anonymous))
            .await
            .is_err()
    );
}
