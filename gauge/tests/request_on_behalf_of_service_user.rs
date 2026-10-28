//! Access requests filed on behalf of a service user the requestor owns: the owner asks, the
//! target's maintainer approves, and the service user gains access — without the maintainer ever
//! needing to see the service user, and without any `Actor::System` elevate (the TM-SEC-06 gate
//! in `no_elevate_path_gate.rs` enforces the latter across the service layer).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::service as svc;
use gauge::types::{
    PermissionRequestCreateInput, PermissionRequestDecision, PermissionRequestDecisionInput,
    PermissionRequestStatusDto, PermissionRequestTargetKind, PrincipalKind,
};
use lepton::generated::ServiceUserAccountStatus;
use service_users_fixtures::{create_service_user, set_service_user_status, world};
use valence::Model;

const TEAM: &str = "team";

fn group_request(target_id: &str, on_behalf_of: Option<&str>) -> PermissionRequestCreateInput {
    PermissionRequestCreateInput {
        target_kind: PermissionRequestTargetKind::Group,
        target_id: target_id.to_string(),
        reason: "Service user needs to join the team group".to_string(),
        on_behalf_of: on_behalf_of.map(ToString::to_string),
    }
}

/// Happy path: `alice` owns a service user and requests `bob`'s group for it; `bob`, who owns the
/// group but cannot see the service user, approves, and the service user becomes a member.
#[tokio::test]
async fn owner_requests_group_for_service_user_and_maintainer_approves_happy() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    let service_user = create_service_user(&w, "alice", "deploy-bot").await;

    let row = svc::create_permission_request(
        group_request(TEAM, Some(service_user.as_str())),
        &w.as_user("alice"),
    )
    .await
    .expect("alice files the request for her service user");
    assert_eq!(row.status, PermissionRequestStatusDto::Pending);
    let on_behalf_of = row.on_behalf_of.expect("row names the service user");
    assert_eq!(on_behalf_of.kind, PrincipalKind::ServiceUser);
    assert_eq!(on_behalf_of.label, "deploy-bot");

    let decided = svc::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: row.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &w.as_user("bob"),
    )
    .await
    .expect("bob approves the request for his group");
    assert_eq!(decided.status, PermissionRequestStatusDto::Approved);

    // A super user sees the full member list, including the service user just added.
    let members = svc::get_group_detail(TEAM, &w.as_user("carol"))
        .await
        .expect("group detail")
        .expect("group exists")
        .members;
    let member = members
        .iter()
        .find(|m| m.id == service_user.as_str())
        .expect("service user is now a member");
    assert_eq!(member.kind, PrincipalKind::ServiceUser);
}

/// Sad: a user cannot request access for a service user they do not own.
#[tokio::test]
async fn cannot_request_for_a_service_user_you_do_not_own_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    let service_user = create_service_user(&w, "alice", "deploy-bot").await;

    let err = svc::create_permission_request(
        group_request(TEAM, Some(service_user.as_str())),
        &w.as_user("dave"),
    )
    .await
    .expect_err("dave does not own alice's service user");
    assert!(
        err.to_string().contains("service user you own"),
        "unexpected error: {err}"
    );
}

/// Sad: a request is refused when the service user is already a member of the target group.
#[tokio::test]
async fn cannot_request_for_a_service_user_already_a_member_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    let service_user = create_service_user(&w, "alice", "deploy-bot").await;
    // Seed the membership as a super user so the request has nothing left to grant.
    svc::add_group_member_service_user(TEAM, &service_user, &w.as_user("carol"))
        .await
        .expect("super user adds the service user");

    let err = svc::create_permission_request(
        group_request(TEAM, Some(service_user.as_str())),
        &w.as_user("alice"),
    )
    .await
    .expect_err("service user already a member");
    assert!(
        err.to_string().contains("already a member"),
        "unexpected error: {err}"
    );
}

/// Sad: a paused (suspended) service user cannot be requested for.
#[tokio::test]
async fn cannot_request_for_a_paused_service_user_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    let service_user = create_service_user(&w, "alice", "deploy-bot").await;
    set_service_user_status(
        &w,
        "alice",
        &service_user,
        ServiceUserAccountStatus::Suspended,
    )
    .await;

    let err = svc::create_permission_request(
        group_request(TEAM, Some(service_user.as_str())),
        &w.as_user("alice"),
    )
    .await
    .expect_err("paused service user cannot be requested for");
    assert!(
        err.to_string().contains("paused"),
        "unexpected error: {err}"
    );
}

/// Sad: approving a request whose service user was deleted after filing is refused, and the
/// service user is not recreated as a member.
#[tokio::test]
async fn approving_for_a_deleted_service_user_is_refused_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    let service_user = create_service_user(&w, "alice", "deploy-bot").await;
    let row = svc::create_permission_request(
        group_request(TEAM, Some(service_user.as_str())),
        &w.as_user("alice"),
    )
    .await
    .expect("alice files the request");

    lepton::generated::ServiceUserAccount::delete(service_user.as_str(), &w.as_user("alice"), valence::use_!(r"**Test:** Fixture **service user** delete for gauge on-behalf-of request tests so the suite can check approval of a deleted service user is refused. CI and developers running the suite only."))
        .await
        .expect("alice deletes the service user");

    let err = svc::decide_permission_request(
        PermissionRequestDecisionInput {
            request_id: row.id.clone(),
            decision: PermissionRequestDecision::Approve,
        },
        &w.as_user("bob"),
    )
    .await
    .expect_err("deleted service user can't be granted");
    assert!(
        err.to_string().contains("no longer exists"),
        "unexpected error: {err}"
    );

    let members = svc::get_group_detail(TEAM, &w.as_user("carol"))
        .await
        .expect("group detail")
        .expect("group exists")
        .members;
    assert!(!members.iter().any(|m| m.id == service_user.as_str()));
    let still = svc::get_permission_request_detail(&row.id, &w.as_user("alice"))
        .await
        .expect("detail")
        .expect("request exists");
    assert_eq!(still.status, PermissionRequestStatusDto::Pending);
}

/// Sad: an unknown handle gets the same refusal as someone else's service user, so the reply
/// doesn't reveal which handles exist.
#[tokio::test]
async fn unknown_handle_gets_the_not_owned_refusal_sad() {
    let w = world().await;
    common::seed_group_with_owner(&w.system, TEAM, "bob").await;
    create_service_user(&w, "alice", "deploy-bot").await;

    for handle in ["deploy-bot", "no-such-bot"] {
        let err =
            svc::create_permission_request(group_request(TEAM, Some(handle)), &w.as_user("dave"))
                .await
                .expect_err("dave owns neither");
        assert!(
            err.to_string().contains("service user you own"),
            "{handle}: unexpected error: {err}"
        );
    }
}
