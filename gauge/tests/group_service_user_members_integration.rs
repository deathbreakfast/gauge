//! Group detail lists service user members with a label and owner next to users and groups.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "common/service_users.rs"]
mod service_users_fixtures;
// `common::test_valence` is async for the suites that await it; these don't.
#[allow(clippy::unused_async)]
mod common;

use gauge::service::{
    add_group_member_service_user, add_group_member_user, get_group_detail,
    remove_group_member_service_user,
};
use gauge::types::{PrincipalKind, PrincipalRefDto};
use service_users_fixtures::{create_service_user, world, READERS};

async fn members(w: &service_users_fixtures::World, actor: &str) -> Vec<PrincipalRefDto> {
    get_group_detail(READERS, &w.as_user(actor))
        .await
        .expect("detail")
        .expect("group exists")
        .members
}

#[tokio::test]
async fn group_lists_user_and_service_user_members_happy() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_user(READERS, "bob", &w.as_user("carol"))
        .await
        .expect("add user");
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add service user");

    let listed = members(&w, "carol").await;

    let user = listed.iter().find(|m| m.id == "bob").expect("user listed");
    assert_eq!(user.kind, PrincipalKind::User);
    assert_eq!(user.owner_label, None);
    let svc = listed
        .iter()
        .find(|m| m.id == service_user.as_str())
        .expect("service user listed");
    assert_eq!(svc.kind, PrincipalKind::ServiceUser);
    assert_eq!(svc.label, "reader-bot");
    let owner = svc.owner_label.as_deref().expect("owner label");
    assert!(owner.contains("alice"), "owner label names alice: {owner}");
}

#[tokio::test]
async fn removed_service_user_is_not_listed_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");
    remove_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("remove");

    assert!(members(&w, "carol")
        .await
        .iter()
        .all(|m| m.id != service_user.as_str()));
}

#[tokio::test]
async fn non_editor_sees_no_members_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    assert!(members(&w, "bob").await.is_empty());
}

#[tokio::test]
async fn deleted_service_user_is_skipped_sad() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");
    valence::delete_entity_now("service_user_account", service_user.as_str(), &w.system)
        .await
        .expect("purge service user");

    assert!(members(&w, "carol")
        .await
        .iter()
        .all(|m| m.id != service_user.as_str()));
}
