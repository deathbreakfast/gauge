#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_super_user_group_with_member, seed_user, test_valence};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput, PrincipalKind,
};
use valence::Actor;

fn assert_err_contains(result: Result<(), impl std::fmt::Display>, needle: &str) {
    let err = result.expect_err("expected error");
    let msg = err.to_string();
    assert!(
        msg.contains(needle),
        "expected `{needle}` in error, got `{msg}`"
    );
}

#[allow(clippy::needless_pass_by_value)]
fn principal_ids(
    detail: &gauge::types::PermissionGroupDetailDto,
    kind: PrincipalKind,
) -> Vec<&str> {
    detail
        .members
        .iter()
        .chain(detail.owner_users.iter())
        .filter(|p| p.kind == kind)
        .map(|p| p.id.as_str())
        .collect()
}

#[tokio::test]
async fn non_owner_cannot_edit_permission() {
    let system = test_valence(Actor::System {
        operation: "permission_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let other_ctx = system.with_actor(Actor::User {
        user_id: "other".to_string(),
    });

    let owner_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Owners".to_string(),
            description: "owner group".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let owner_group_id = record_pk_id(owner_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Security".to_string(),
            description: "security permissions".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "AuthPerm".to_string(),
            description: "auth".to_string(),
            owners_group_id: owner_group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &owner_ctx,
    )
    .await
    .expect("create permission");

    let permission_id = record_pk_id(permission.id());

    let denied = service::update_permission(
        &permission_id,
        "New Name".to_string(),
        "Changed".to_string(),
        owner_group_id,
        domain_id,
        &other_ctx,
    )
    .await;
    let msg = denied.expect_err("non-owner update").to_string();
    assert!(
        msg.contains("Not authorized to edit permission"),
        "got {msg}"
    );

    let detail = service::get_permission_detail(&permission_id, &owner_ctx)
        .await
        .expect("detail")
        .expect("permission still exists");
    assert_eq!(detail.name, "AuthPerm", "denied update must not commit");
}

#[tokio::test]
async fn group_member_cannot_edit_group_or_membership() {
    let system = test_valence(Actor::System {
        operation: "group_owner_auth_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("member", "member@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let member_ctx = system.with_actor(Actor::User {
        user_id: "member".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Owners".to_string(),
            description: "owner group".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let group_id = record_pk_id(group.id());

    service::add_group_member_user(&group_id, "member", &owner_ctx)
        .await
        .expect("owner adds member");

    let denied_update = service::update_group(
        &group_id,
        "Owners Renamed".to_string(),
        "member attempted update".to_string(),
        &member_ctx,
    )
    .await;
    let update_msg = denied_update.expect_err("member update").to_string();
    assert!(
        update_msg.contains("Not authorized to edit group"),
        "got {update_msg}"
    );

    let denied_membership_edit =
        service::add_group_member_user(&group_id, "other", &member_ctx).await;
    assert_err_contains(
        denied_membership_edit,
        "Not authorized to edit group membership",
    );

    let detail = service::get_group_detail(&group_id, &owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    assert_eq!(detail.name, "Owners", "denied rename must not commit");
    let member_ids = principal_ids(&detail, PrincipalKind::User);
    assert!(
        member_ids.contains(&"member"),
        "member should remain: {member_ids:?}"
    );
    assert!(
        !member_ids.contains(&"other"),
        "denied add must not add other: {member_ids:?}"
    );
}

#[tokio::test]
async fn owner_can_delegate_group_ownership() {
    let system = test_valence(Actor::System {
        operation: "group_owner_delegate_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("delegate", "delegate@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let delegate_ctx = system.with_actor(Actor::User {
        user_id: "delegate".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Delegation Group".to_string(),
            description: "owner delegation".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let group_id = record_pk_id(group.id());

    service::add_group_owner_user(&group_id, "delegate", &owner_ctx)
        .await
        .expect("delegate owner");

    service::add_group_member_user(&group_id, "other", &delegate_ctx)
        .await
        .expect("delegated owner manages membership");

    let detail = service::get_group_detail(&group_id, &owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    let owner_ids: Vec<&str> = detail
        .owner_users
        .iter()
        .filter(|p| p.kind == PrincipalKind::User)
        .map(|p| p.id.as_str())
        .collect();
    assert!(
        owner_ids.contains(&"delegate"),
        "delegate must appear in owners: {owner_ids:?}"
    );
    let member_ids = principal_ids(&detail, PrincipalKind::User);
    assert!(
        member_ids.contains(&"other"),
        "other must be a member after delegate add: {member_ids:?}"
    );
}

#[tokio::test]
async fn owner_can_remove_delegated_group_owner() {
    let system = test_valence(Actor::System {
        operation: "group_owner_remove_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("delegate", "delegate@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let delegate_ctx = system.with_actor(Actor::User {
        user_id: "delegate".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Owner Remove Group".to_string(),
            description: "owner remove flow".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");

    let group_id = record_pk_id(group.id());

    service::add_group_owner_user(&group_id, "delegate", &owner_ctx)
        .await
        .expect("add delegated owner");

    service::remove_group_owner_user(&group_id, "delegate", &owner_ctx)
        .await
        .expect("remove delegated owner");

    let denied = service::add_group_member_user(&group_id, "other", &delegate_ctx).await;
    assert_err_contains(denied, "Not authorized to edit group membership");

    let detail = service::get_group_detail(&group_id, &owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    let owner_ids: Vec<&str> = detail
        .owner_users
        .iter()
        .filter(|p| p.kind == PrincipalKind::User)
        .map(|p| p.id.as_str())
        .collect();
    assert!(
        !owner_ids.contains(&"delegate"),
        "removed delegate must not remain owner: {owner_ids:?}"
    );
}

#[tokio::test]
async fn super_user_can_edit_membership_without_group_ownership() {
    let system = test_valence(Actor::System {
        operation: "super_user_group_membership_test_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("super", "super@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;
    seed_super_user_group_with_member(&system, "super").await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let super_ctx = system.with_actor(Actor::User {
        user_id: "super".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Regular Group".to_string(),
            description: "owned by owner user".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create regular group");
    let group_id = record_pk_id(group.id());

    service::add_group_member_user(&group_id, "other", &super_ctx)
        .await
        .expect("super user membership edit");

    let detail = service::get_group_detail(&group_id, &owner_ctx)
        .await
        .expect("detail")
        .expect("group");
    let member_ids = principal_ids(&detail, PrincipalKind::User);
    assert!(
        member_ids.contains(&"other"),
        "super user add must persist: {member_ids:?}"
    );
}

#[tokio::test]
async fn super_user_can_modify_super_user_group_membership() {
    let system = test_valence(Actor::System {
        operation: "super_user_self_group_membership_test_setup".to_string(),
    })
    .await;

    seed_user("super", "super@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;
    seed_super_user_group_with_member(&system, "super").await;

    let super_ctx = system.with_actor(Actor::User {
        user_id: "super".to_string(),
    });

    service::add_group_member_user("super_user_group", "other", &super_ctx)
        .await
        .expect("add super user group member");

    let after_add = service::get_group_detail("super_user_group", &super_ctx)
        .await
        .expect("detail")
        .expect("super user group");
    let member_ids = principal_ids(&after_add, PrincipalKind::User);
    assert!(
        member_ids.contains(&"other"),
        "other must be member after add: {member_ids:?}"
    );

    service::remove_group_member_user("super_user_group", "other", &super_ctx)
        .await
        .expect("remove super user group member");

    let after_remove = service::get_group_detail("super_user_group", &super_ctx)
        .await
        .expect("detail")
        .expect("super user group");
    let member_ids = principal_ids(&after_remove, PrincipalKind::User);
    assert!(
        !member_ids.contains(&"other"),
        "other must be gone after remove: {member_ids:?}"
    );
}

#[tokio::test]
async fn super_user_can_modify_super_user_group_membership_with_prefixed_actor_id() {
    let system = test_valence(Actor::System {
        operation: "super_user_prefixed_actor_test_setup".to_string(),
    })
    .await;

    seed_user("super", "super@example.com", &system).await;
    seed_user("other", "other@example.com", &system).await;
    seed_super_user_group_with_member(&system, "super").await;

    let super_ctx = system.with_actor(Actor::User {
        user_id: "user:super".to_string(),
    });

    service::add_group_member_user("super_user_group", "other", &super_ctx)
        .await
        .expect("prefixed actor add");

    let detail = service::get_group_detail("super_user_group", &super_ctx)
        .await
        .expect("detail")
        .expect("super user group");
    let member_ids = principal_ids(&detail, PrincipalKind::User);
    assert!(
        member_ids.contains(&"other"),
        "prefixed actor id must still authorize: {member_ids:?}"
    );
}
