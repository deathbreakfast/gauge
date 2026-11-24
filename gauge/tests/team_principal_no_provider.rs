//! With no `TeamMembershipProvider` registered, a team principal matches nobody.
//!
//! Its own test binary, so no provider is linked in.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::generated::{Permission, PermissionTeamPrincipal};
use gauge::service::{
    actor_can, actor_can_raw, create_domain, create_group, create_permission,
    grant_permission_to_team, GaugeServiceError,
};
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use valence::Model;

use service_users_fixtures::world;

const DEPLOY: &str = "test.team.unresolved";

#[tokio::test]
async fn team_principal_without_provider_denies_sad() {
    assert!(gauge::teams::provider().is_none());
    let w = world().await;
    let dave = w.as_user("dave");
    let owners = create_group(
        PermissionGroupCreateInput {
            name: "Deploy owners".into(),
            description: "Fixture group".into(),
        },
        &dave,
    )
    .await
    .expect("owners group");
    let domain = create_domain(
        PermissionDomainCreateInput {
            name: "Team deploys".into(),
            description: "Fixture domain".into(),
        },
        &dave,
    )
    .await
    .expect("domain");
    let permission = create_permission(
        PermissionCreateInput {
            name: DEPLOY.into(),
            description: "Deploy".into(),
            owners_group_id: common::record_pk_id(owners.id()),
            domain_id: common::record_pk_id(domain.id()),
        },
        &dave,
    )
    .await
    .expect("permission");
    let permission_id = common::record_pk_id(permission.id());

    let err = grant_permission_to_team(&permission_id, "eng", &dave)
        .await
        .expect_err("no provider, so no team can be read");
    assert!(matches!(
        err.downcast_ref::<GaugeServiceError>(),
        Some(GaugeServiceError::NotFound { .. })
    ));

    // Arrange the edge directly, as a grant made while a provider was registered would.
    let principal = PermissionTeamPrincipal::upsert(
        "team:eng",
        PermissionTeamPrincipal::new("eng".into(), "eng".into()).expect("principal"),
        &w.system,
        valence::use_!(r"**Test:** Fixture **team principal** save so the suite can check a team grant with no provider registered. CI only."),
    )
    .await
    .expect("upsert team principal");
    let permission = Permission::get(
        &permission_id,
        &w.system,
        valence::use_!(
            r"**Test:** Fixture **Permission** load so the suite can attach a team grant. CI only."
        ),
    )
    .await
    .unwrap()
    .expect("permission row");
    permission
        .relate_to_allowed_principal_record(
            principal.id().expect("principal id"),
            &w.system,
            valence::use_!(r"**Test:** Fixture **allowed-principal edge** to a team so the suite can check it with no provider registered. CI only."),
        )
        .await
        .expect("relate team principal");

    let alice = w.as_user("alice");
    assert!(!actor_can(&alice, DEPLOY).await.unwrap());
    assert!(!actor_can_raw(&alice, DEPLOY).await.unwrap());
}
