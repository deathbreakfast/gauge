#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_user, test_valence};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use valence::Actor;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn create_and_mutate_permission_flows_happy_path() {
    let system = test_valence(Actor::System {
        operation: "permission_test_setup".to_string(),
    })
    .await;

    seed_user("u1", "owner@example.com", &system).await;
    seed_user("u2", "member@example.com", &system).await;

    let user_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });
    let member_ctx = system.with_actor(Actor::User {
        user_id: "u2".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "Group A".to_string(),
            description: "Owners group".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create group");

    let group_id = record_pk_id(group.id());
    service::add_group_member_user(&group_id, "u2", &user_ctx)
        .await
        .expect("add group member user");

    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Infrastructure".to_string(),
            description: "infra permissions".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: "CanDeploy".to_string(),
            description: "Allow deployments".to_string(),
            owners_group_id: group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &user_ctx,
    )
    .await
    .expect("create permission");

    let permission_id = record_pk_id(permission.id());

    let can_before_grants = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can before grants");
    assert!(
        !can_before_grants,
        "member should not have permission before grants"
    );

    service::grant_permission_to_user(&permission_id, "u2", &user_ctx)
        .await
        .expect("grant user");

    let can_via_direct_grant = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after direct grant");
    assert!(
        can_via_direct_grant,
        "member should have permission after direct user grant"
    );

    let can_via_user_api = service::user_can(&user_ctx, "u2", "CanDeploy")
        .await
        .expect("check user_can after direct grant");
    assert!(
        can_via_user_api,
        "user_can should resolve direct user grant"
    );

    service::revoke_permission_from_user(&permission_id, "u2", &user_ctx)
        .await
        .expect("revoke user");

    let can_after_revoke_direct = service::has_permission(&member_ctx, "CanDeploy")
        .await
        .expect("check has_permission after direct revoke");
    assert!(
        !can_after_revoke_direct,
        "member should lose direct user grant"
    );

    service::grant_permission_to_group(&permission_id, &group_id, &user_ctx)
        .await
        .expect("grant group");

    let can_via_group_grant = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after group grant");
    assert!(
        can_via_group_grant,
        "member should inherit permission through allowed group membership"
    );

    service::revoke_permission_from_group(&permission_id, &group_id, &user_ctx)
        .await
        .expect("revoke group");

    let can_after_revoke_group = service::actor_can(&member_ctx, "CanDeploy")
        .await
        .expect("check actor_can after group revoke");
    assert!(
        !can_after_revoke_group,
        "member should lose permission after group revoke"
    );

    let detail = service::get_permission_detail(&permission_id, &user_ctx)
        .await
        .expect("detail query")
        .expect("permission detail");
    assert_eq!(detail.name, "CanDeploy");
}

#[tokio::test]
async fn duplicate_permission_and_group_names_are_rejected_sad() {
    let system = test_valence(Actor::System {
        operation: "permission_unique_name_test_setup".to_string(),
    })
    .await;

    seed_user("u1", "owner@example.com", &system).await;
    let user_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });

    let first_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &user_ctx,
    )
    .await
    .expect("first group should create");

    let duplicate_group = service::create_group(
        PermissionGroupCreateInput {
            name: "Unique Group Name".to_string(),
            description: String::new(),
        },
        &user_ctx,
    )
    .await;
    let dup_group_msg = duplicate_group
        .expect_err("duplicate group name")
        .to_string();
    assert!(
        dup_group_msg.contains("already exists"),
        "got {dup_group_msg}"
    );

    let owners_group_id = record_pk_id(first_group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "Platform".to_string(),
            description: "platform permissions".to_string(),
        },
        &user_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let first_permission = service::create_permission(
        PermissionCreateInput {
            name: "Unique Permission Name".to_string(),
            description: String::new(),
            owners_group_id: owners_group_id.clone(),
            domain_id: domain_id.clone(),
        },
        &user_ctx,
    )
    .await;
    assert!(first_permission.is_ok(), "first permission should create");

    let duplicate_permission = service::create_permission(
        PermissionCreateInput {
            name: "Unique Permission Name".to_string(),
            description: String::new(),
            owners_group_id,
            domain_id,
        },
        &user_ctx,
    )
    .await;
    let dup_perm_msg = duplicate_permission
        .expect_err("duplicate permission name")
        .to_string();
    assert!(
        dup_perm_msg.contains("already exists"),
        "got {dup_perm_msg}"
    );
}
