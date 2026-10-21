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

#[tokio::test]
async fn clear_members_removes_service_user_and_keeps_its_principal_happy() {
    use gauge::service::{
        add_group_member_group, add_group_owner_user, clear_group_members, create_group_owner_only,
    };
    use gauge::types::PermissionGroupCreateInput;

    let w = world().await;
    let carol = w.as_user("carol");
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    let svc_ctx = w.as_service_user(&service_user);
    let make = |name: &str| PermissionGroupCreateInput {
        name: name.to_string(),
        description: String::new(),
    };
    let nested = create_group_owner_only(make("Nested bots"), &carol)
        .await
        .expect("nested");
    let nested_id = common::record_pk_id(nested.id());
    add_group_member_user(&nested_id, "dave", &carol)
        .await
        .expect("nested member");

    // READERS grants READ and has no owners; carol is a super user.
    add_group_member_user(READERS, "bob", &carol).await.unwrap();
    add_group_member_user(READERS, "dave", &carol)
        .await
        .unwrap();
    add_group_member_service_user(READERS, &service_user, &carol)
        .await
        .unwrap();
    add_group_member_group(READERS, &nested_id, &carol)
        .await
        .unwrap();
    add_group_owner_user(READERS, "alice", &carol)
        .await
        .unwrap();
    assert!(
        gauge::service::actor_can(&svc_ctx, service_users_fixtures::READ)
            .await
            .unwrap()
    );

    let removed = clear_group_members(READERS, &carol).await.expect("clear");
    assert_eq!(removed, 4);

    let detail = get_group_detail(READERS, &carol).await.unwrap().unwrap();
    assert!(detail.members.is_empty(), "{:?}", detail.members);
    assert_eq!(
        detail
            .owner_users
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        ["alice"]
    );
    let nested_detail = get_group_detail(&nested_id, &carol).await.unwrap().unwrap();
    assert_eq!(
        nested_detail
            .members
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        ["dave"]
    );
    assert!(
        !gauge::service::actor_can(&svc_ctx, service_users_fixtures::READ)
            .await
            .unwrap()
    );
    assert!(
        !gauge::service::actor_can(&w.as_user("bob"), service_users_fixtures::READ)
            .await
            .unwrap()
    );

    // The service user's principal row survives, so it can be added again.
    add_group_member_service_user(READERS, &service_user, &carol)
        .await
        .expect("re-add");
    assert!(members(&w, "carol")
        .await
        .iter()
        .any(|m| m.id == service_user.as_str()));
}
