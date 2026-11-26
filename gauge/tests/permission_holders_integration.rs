//! `list_permission_holders`: every user holding a permission, and who may ask.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::service::{
    add_group_member_group, add_group_member_service_user, add_group_member_user, create_domain,
    create_group, create_permission, grant_permission_to_group, grant_permission_to_user,
    list_permission_holders, GaugeServiceError,
};
use gauge::service_users::{
    seed_service_user_permissions, GAUGE_LIST_PERMISSION_HOLDERS,
    PERMISSION_HOLDER_READERS_GROUP_ID,
};
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use lepton::generated::ServiceUserAccountStatus;
use valence::{Actor, Valence};

use service_users_fixtures::{create_service_user, set_service_user_status, world, World};

const DEPLOY: &str = "test.deploy";

async fn group(name: &str, v: &Valence) -> String {
    let g = create_group(
        PermissionGroupCreateInput {
            name: name.into(),
            description: "Fixture group".into(),
        },
        v,
    )
    .await
    .expect("create group");
    common::record_pk_id(g.id())
}

/// `dave` edits [`DEPLOY`] and owns both holder groups. `bob` holds it directly; `alice`
/// through `Inner`, nested in `Outer`, which holds it. `Inner` and `Outer` form a cycle, and a
/// service user sits in `Inner`.
async fn deploy_world() -> World {
    let w = world().await;
    let dave = w.as_user("dave");
    let owners = group("Deploy owners", &dave).await;
    let domain = create_domain(
        PermissionDomainCreateInput {
            name: "Deploys".into(),
            description: "Fixture domain".into(),
        },
        &dave,
    )
    .await
    .expect("domain");
    let permission = create_permission(
        PermissionCreateInput {
            display_name: String::new(),
            name: DEPLOY.into(),
            description: "Deploy".into(),
            owners_group_id: owners,
            domain_id: common::record_pk_id(domain.id()),
        },
        &dave,
    )
    .await
    .expect("permission");
    let permission_id = common::record_pk_id(permission.id());

    let outer = group("Outer", &dave).await;
    let inner = group("Inner", &dave).await;
    add_group_member_group(&outer, &inner, &dave)
        .await
        .expect("nest");
    add_group_member_group(&inner, &outer, &dave)
        .await
        .expect("cycle");
    add_group_member_user(&inner, "alice", &dave)
        .await
        .expect("alice");
    grant_permission_to_group(&permission_id, &outer, &dave)
        .await
        .expect("group grant");
    grant_permission_to_user(&permission_id, "bob", &dave)
        .await
        .expect("direct grant");

    let su = create_service_user(&w, "alice", "in-inner").await;
    add_group_member_service_user(&inner, &su, &w.as_user("carol"))
        .await
        .expect("service user in inner");
    w
}

fn expected() -> Vec<String> {
    // dave owns the holding groups, so he holds what they hold.
    vec!["alice".into(), "bob".into(), "dave".into()]
}

fn assert_not_authorized(err: &anyhow::Error) {
    assert!(
        matches!(
            err.downcast_ref::<GaugeServiceError>(),
            Some(GaugeServiceError::NotAuthorized { .. })
        ),
        "expected NotAuthorized, got {err:#}"
    );
}

#[tokio::test]
async fn system_lists_direct_nested_and_owner_holders_happy() {
    let w = deploy_world().await;
    let system = w.as_actor(Actor::System {
        operation: "ocr_job".into(),
    });
    let holders = list_permission_holders(&system, DEPLOY)
        .await
        .expect("list");
    assert_eq!(holders, expected(), "sorted, deduped, no service users");
}

#[tokio::test]
async fn super_user_and_editor_list_holders_happy() {
    let w = deploy_world().await;
    for user in ["carol", "dave"] {
        let holders = list_permission_holders(&w.as_user(user), DEPLOY)
            .await
            .unwrap_or_else(|e| panic!("{user}: {e:#}"));
        assert_eq!(holders, expected(), "{user}");
    }
}

#[tokio::test]
async fn service_user_with_lookup_grant_lists_holders_happy() {
    let w = deploy_world().await;
    let su = create_service_user(&w, "alice", "notifier").await;
    add_group_member_service_user(PERMISSION_HOLDER_READERS_GROUP_ID, &su, &w.as_user("carol"))
        .await
        .expect("join readers");
    let holders = list_permission_holders(&w.as_service_user(&su), DEPLOY)
        .await
        .expect("list");
    assert_eq!(holders, expected());
}

#[tokio::test]
async fn unknown_permission_lists_nobody_happy() {
    let w = deploy_world().await;
    let holders = list_permission_holders(&w.as_user("carol"), "test.nope")
        .await
        .expect("list");
    assert!(holders.is_empty());
}

#[tokio::test]
async fn service_user_without_lookup_grant_is_refused_sad() {
    let w = deploy_world().await;
    let su = create_service_user(&w, "alice", "no-grant").await;
    let err = list_permission_holders(&w.as_service_user(&su), DEPLOY)
        .await
        .expect_err("refused");
    assert_not_authorized(&err);
}

#[tokio::test]
async fn suspended_service_user_in_readers_is_refused_sad() {
    let w = deploy_world().await;
    let su = create_service_user(&w, "alice", "suspended").await;
    add_group_member_service_user(PERMISSION_HOLDER_READERS_GROUP_ID, &su, &w.as_user("carol"))
        .await
        .expect("join readers");
    set_service_user_status(&w, "alice", &su, ServiceUserAccountStatus::Suspended).await;
    let err = list_permission_holders(&w.as_service_user(&su), DEPLOY)
        .await
        .expect_err("refused");
    assert_not_authorized(&err);
}

#[tokio::test]
async fn holder_who_is_not_editor_is_refused_sad() {
    let w = deploy_world().await;
    // bob holds the permission but doesn't edit it; holding is not enough to list.
    let err = list_permission_holders(&w.as_user("bob"), DEPLOY)
        .await
        .expect_err("refused");
    assert_not_authorized(&err);
    // An unknown name doesn't let a plain user probe for an empty list either.
    let err = list_permission_holders(&w.as_user("bob"), "test.nope")
        .await
        .expect_err("refused");
    assert_not_authorized(&err);
}

#[tokio::test]
async fn anonymous_is_refused_sad() {
    let w = deploy_world().await;
    let err = list_permission_holders(&w.as_actor(Actor::Anonymous), DEPLOY)
        .await
        .expect_err("refused");
    assert_not_authorized(&err);
}

#[tokio::test]
async fn read_failure_is_an_error_sad() {
    let w = deploy_world().await;
    let system = w.as_actor(Actor::System {
        operation: "ocr_job".into(),
    });
    w.set_reads_failing(true);
    let result = list_permission_holders(&system, DEPLOY).await;
    w.set_reads_failing(false);
    assert!(
        result.is_err(),
        "read failure must not look like no holders"
    );
}

#[tokio::test]
async fn seed_creates_lookup_permission_and_group_idempotent_happy() {
    let w = world().await;
    let again = seed_service_user_permissions(&w.system)
        .await
        .expect("reseed");
    assert_eq!(again.permissions_created, 0);
    let su = create_service_user(&w, "alice", "seeded").await;
    add_group_member_service_user(PERMISSION_HOLDER_READERS_GROUP_ID, &su, &w.as_user("carol"))
        .await
        .expect("seeded group exists");
    assert!(
        gauge::service::actor_can(&w.as_service_user(&su), GAUGE_LIST_PERMISSION_HOLDERS)
            .await
            .expect("check")
    );
}
