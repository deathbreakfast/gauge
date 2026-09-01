//! Permission-check Spectra emission capture contracts.
//!
//! Run: `cargo test -p gauge --features ssr --test permission_check_emission_integration`

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{record_pk_id, seed_user, test_valence};
use gauge::instrumentation::{
    begin_permission_check_capture, take_permission_check_captures, PermissionCheckOutcome,
};
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use valence::Actor;

#[tokio::test]
async fn actor_can_records_allow_and_deny_outcomes_happy_path() {
    let system = test_valence(Actor::System {
        operation: "permission_check_emission_setup".to_string(),
    })
    .await;
    seed_user("owner", "owner@example.com", &system).await;
    seed_user("member", "member@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let member_ctx = system.with_actor(Actor::User {
        user_id: "member".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: "EmissionOwners".to_string(),
            description: String::new(),
        },
        &owner_ctx,
    )
    .await
    .expect("group");
    let group_id = record_pk_id(group.id());
    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: "EmissionDomain".to_string(),
            description: String::new(),
        },
        &owner_ctx,
    )
    .await
    .expect("domain");
    let domain_id = record_pk_id(domain.id());
    let permission = service::create_permission(
        PermissionCreateInput {
            name: "EmissionPerm".to_string(),
            description: String::new(),
            owners_group_id: group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await
    .expect("permission");
    let permission_id = record_pk_id(permission.id());

    begin_permission_check_capture();
    assert!(
        !service::actor_can(&member_ctx, "EmissionPerm")
            .await
            .expect("deny check"),
        "no grant yet"
    );
    let after_deny = take_permission_check_captures();
    assert!(
        after_deny.iter().any(|c| {
            c.permission_name == "EmissionPerm" && c.outcome == PermissionCheckOutcome::Deny
        }),
        "expected deny capture, got {after_deny:?}"
    );

    service::grant_permission_to_user(&permission_id, "member", &owner_ctx)
        .await
        .expect("grant");

    begin_permission_check_capture();
    assert!(
        service::actor_can(&member_ctx, "EmissionPerm")
            .await
            .expect("allow check"),
        "after grant"
    );
    let after_allow = take_permission_check_captures();
    assert!(
        after_allow.iter().any(|c| {
            c.permission_name == "EmissionPerm" && c.outcome == PermissionCheckOutcome::Allow
        }),
        "expected allow capture, got {after_allow:?}"
    );
}

#[tokio::test]
async fn actor_can_empty_name_and_no_actor_record_outcomes_sad() {
    let system = test_valence(Actor::System {
        operation: "permission_check_emission_sad".to_string(),
    })
    .await;
    seed_user("u1", "u1@example.com", &system).await;
    let user_ctx = system.with_actor(Actor::User {
        user_id: "u1".to_string(),
    });
    let anon = system.with_actor(Actor::Anonymous);

    begin_permission_check_capture();
    assert!(
        !service::actor_can(&user_ctx, "   ")
            .await
            .expect("empty name"),
        "blank name denies"
    );
    let empty_caps = take_permission_check_captures();
    assert!(
        empty_caps
            .iter()
            .any(|c| c.outcome == PermissionCheckOutcome::Deny),
        "empty permission name must record deny, got {empty_caps:?}"
    );

    begin_permission_check_capture();
    assert!(
        !service::actor_can(&anon, "SomePerm")
            .await
            .expect("no actor"),
        "anonymous denies"
    );
    let anon_caps = take_permission_check_captures();
    assert!(
        anon_caps
            .iter()
            .any(|c| c.outcome == PermissionCheckOutcome::NoActor),
        "anonymous must record no_actor, got {anon_caps:?}"
    );
}
