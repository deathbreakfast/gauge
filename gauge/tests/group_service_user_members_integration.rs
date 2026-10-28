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
use service_users_fixtures::{create_service_user, raw_count, world, READERS};

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
async fn plain_owner_sees_service_user_members_happy() {
    use gauge::service::create_group_owner_only;
    use gauge::types::PermissionGroupCreateInput;

    let w = world().await;
    // alice is a plain user (not a super user); carol is the only super user.
    let alice = w.as_user("alice");
    let group = create_group_owner_only(
        PermissionGroupCreateInput {
            name: "Alice bots".to_string(),
            description: String::new(),
        },
        &alice,
    )
    .await
    .expect("alice creates and owns group");
    let gid = common::record_pk_id(group.id());
    let service_user = create_service_user(&w, "alice", "alice-bot").await;
    add_group_member_service_user(&gid, &service_user, &alice)
        .await
        .expect("owner adds its service user");

    let detail = get_group_detail(&gid, &alice)
        .await
        .expect("detail")
        .expect("group exists");
    let svc = detail
        .members
        .iter()
        .find(|m| m.id == service_user.as_str())
        .expect("plain owner sees the service user member");
    assert_eq!(svc.kind, PrincipalKind::ServiceUser);
    assert_eq!(svc.label, "alice-bot");

    // A non-owner still sees nothing.
    assert!(get_group_detail(&gid, &w.as_user("bob"))
        .await
        .expect("detail")
        .expect("group exists")
        .members
        .is_empty());
}

#[tokio::test]
async fn forged_service_user_principal_refused_sad() {
    use gauge::generated::PermissionServiceUserPrincipal;
    use valence::{Model, RecordId};

    let w = world().await;
    // alice owns the service user; bob neither owns it nor manages every service user.
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    let principal_row = || {
        PermissionServiceUserPrincipal::new(
            RecordId::new("service_user_account", service_user.as_str()),
            service_user.as_str().to_string(),
        )
        .expect("principal row")
    };

    let outsider = PermissionServiceUserPrincipal::create(principal_row(), &w.as_user("bob"), valence::use_!(r"**Test:** an outsider tries to forge a service user principal row to check the create policy refuses it. CI and developers running the suite only.")).await;
    assert!(
        outsider.is_err(),
        "a caller who can't see the service user must not create its principal row"
    );

    // The service user's owner may create it.
    PermissionServiceUserPrincipal::create(principal_row(), &w.as_user("alice"), valence::use_!(r"**Test:** the service user's owner creates its principal row to check the create policy allows the add-member path. CI and developers running the suite only.")).await.expect("owner creates principal");
}

#[tokio::test]
async fn no_op_service_user_add_writes_no_history() {
    let w = world().await;
    let service_user = create_service_user(&w, "alice", "reader-bot").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("add");

    let before = raw_count(&w.system, "permission_history").await;
    add_group_member_service_user(READERS, &service_user, &w.as_user("carol"))
        .await
        .expect("re-add is a no-op");
    let after = raw_count(&w.system, "permission_history").await;

    assert_eq!(
        before, after,
        "re-adding an existing member must not write history"
    );
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
