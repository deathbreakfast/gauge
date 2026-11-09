//! A service user's groups and effective permissions, read under the owner's own Valence.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::service::{
    actor_can, add_group_member_group, add_group_member_service_user, create_group,
    GaugeServiceError,
};
use gauge::service_users::{service_user_effective_permissions, service_user_groups};
use gauge::types::PermissionGroupCreateInput;
use lepton::generated::ServiceUserAccountStatus;
use lepton_identity::service_users::ServiceUserId;
use service_users_fixtures::{create_service_user, set_service_user_status, world, READ, READERS};

fn assert_not_found(err: &anyhow::Error) {
    assert!(
        matches!(
            err.downcast_ref::<GaugeServiceError>(),
            Some(GaugeServiceError::NotFound { .. })
        ),
        "expected NotFound, got {err:#}"
    );
}

fn ids(groups: Vec<gauge::types::ServiceUserGroupDto>) -> Vec<String> {
    groups.into_iter().map(|g| g.id).collect()
}

#[tokio::test]
async fn owner_lists_groups_and_permissions_happy() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .expect("add");

    let alice = w.as_user("alice");
    let groups = service_user_groups(&alice, &su).await.expect("groups");
    assert_eq!(ids(groups), vec![READERS.to_string()]);

    let perms = service_user_effective_permissions(&alice, &su)
        .await
        .expect("perms");
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].name, READ);
    assert_eq!(perms[0].via_group.as_ref().expect("via").id, READERS);
    // Agrees with the service user's own check.
    assert!(actor_can(&w.as_service_user(&su), READ).await.unwrap());
}

#[tokio::test]
async fn nested_groups_are_followed_happy() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "nested").await;
    let carol = w.as_user("carol");
    let child = create_group(
        PermissionGroupCreateInput {
            name: "Agents".into(),
            description: "Child".into(),
        },
        &carol,
    )
    .await
    .expect("child");
    let child_id = common::record_pk_id(child.id());
    add_group_member_group(READERS, &child_id, &carol)
        .await
        .expect("nest");
    add_group_member_service_user(&child_id, &su, &carol)
        .await
        .expect("add");

    let alice = w.as_user("alice");
    let mut groups = ids(service_user_groups(&alice, &su).await.unwrap());
    groups.sort();
    let mut expected = vec![READERS.to_string(), child_id];
    expected.sort();
    assert_eq!(groups, expected);

    let perms = service_user_effective_permissions(&alice, &su)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].via_group.as_ref().unwrap().id, READERS);
}

#[tokio::test]
async fn manage_any_user_can_read_happy() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .unwrap();
    let carol = w.as_user("carol");
    assert_eq!(service_user_groups(&carol, &su).await.unwrap().len(), 1);
    assert_eq!(
        service_user_effective_permissions(&carol, &su)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn non_owner_is_refused_sad() {
    let w = world().await;
    let su = create_service_user(&w, "alice", "reader").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .unwrap();
    for who in ["bob", "dave"] {
        let v = w.as_user(who);
        assert_not_found(&service_user_groups(&v, &su).await.unwrap_err());
        assert_not_found(
            &service_user_effective_permissions(&v, &su)
                .await
                .unwrap_err(),
        );
    }
    let missing = ServiceUserId::new_v4();
    assert_not_found(
        &service_user_groups(&w.as_user("alice"), &missing)
            .await
            .unwrap_err(),
    );
    // A service user cannot read its own access through these calls.
    assert!(service_user_groups(&w.as_service_user(&su), &su)
        .await
        .is_err());
}

#[tokio::test]
async fn outsider_and_suspended_service_users_sad() {
    let w = world().await;
    let outsider = create_service_user(&w, "alice", "outsider").await;
    let alice = w.as_user("alice");
    assert!(service_user_groups(&alice, &outsider)
        .await
        .unwrap()
        .is_empty());
    assert!(service_user_effective_permissions(&alice, &outsider)
        .await
        .unwrap()
        .is_empty());

    let su = create_service_user(&w, "alice", "paused").await;
    add_group_member_service_user(READERS, &su, &w.as_user("carol"))
        .await
        .unwrap();
    set_service_user_status(&w, "alice", &su, ServiceUserAccountStatus::Suspended).await;
    assert_eq!(service_user_groups(&alice, &su).await.unwrap().len(), 1);
    assert!(service_user_effective_permissions(&alice, &su)
        .await
        .unwrap()
        .is_empty());
}
