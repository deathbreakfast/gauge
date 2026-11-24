//! Team principals: grants to a provider-owned team, resolved at check time as the session.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(clippy::unused_async)]
mod common;
#[path = "common/service_users.rs"]
mod service_users_fixtures;

use gauge::service::{
    actor_can, actor_can_raw, create_domain, create_group, create_permission,
    get_permission_detail, grant_permission_to_team, revoke_permission_from_team, user_can,
    GaugeServiceError,
};
use gauge::teams::{TeamMembershipProvider, TeamMembershipProviderRegistration, TeamSummary};
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput, PrincipalKind,
};
use valence::{Actor, Valence};

use service_users_fixtures::{world, World};

const DEPLOY: &str = "test.team.deploy";

/// `(id, name, private, members)`.
const TEAMS: &[(&str, &str, bool, &[&str])] = &[
    ("eng", "Engineering", false, &["alice"]),
    ("ops", "Operations", true, &["bob", "dave"]),
    ("secret", "Secret", true, &["bob"]),
];

/// Answers as the actor on `v`, the way a real provider reads under privacy: anonymous
/// sessions read nothing, and a private team is visible only to its members.
struct FixtureTeams;

fn visible(team: &(&str, &str, bool, &[&str]), v: &Valence) -> bool {
    let actor = v.actor();
    if actor.is_system() {
        return true;
    }
    let Some(viewer) = actor.user_id() else {
        return false;
    };
    !team.2 || team.3.contains(&viewer)
}

#[async_trait::async_trait]
impl TeamMembershipProvider for FixtureTeams {
    async fn is_member(&self, team_id: &str, user_id: &str, v: &Valence) -> anyhow::Result<bool> {
        Ok(TEAMS
            .iter()
            .find(|t| t.0 == team_id)
            .is_some_and(|t| visible(t, v) && t.3.contains(&user_id)))
    }

    async fn team_name(&self, team_id: &str, v: &Valence) -> anyhow::Result<Option<String>> {
        Ok(TEAMS
            .iter()
            .find(|t| t.0 == team_id && visible(t, v))
            .map(|t| t.1.to_string()))
    }

    async fn search_teams(
        &self,
        query: &str,
        max: u32,
        v: &Valence,
    ) -> anyhow::Result<Vec<TeamSummary>> {
        let query = query.to_lowercase();
        Ok(TEAMS
            .iter()
            .filter(|t| visible(t, v) && t.1.to_lowercase().contains(&query))
            .take(max as usize)
            .map(|t| TeamSummary {
                id: t.0.to_string(),
                name: t.1.to_string(),
            })
            .collect())
    }
}

inventory::submit! { TeamMembershipProviderRegistration(&FixtureTeams) }

/// `dave` owns [`DEPLOY`]; nothing is granted yet. Returns the world and the permission id.
async fn deploy_world() -> (World, String) {
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
    (w, permission_id)
}

#[tokio::test]
async fn team_member_holds_team_grant_happy() {
    let (w, permission_id) = deploy_world().await;
    grant_permission_to_team(&permission_id, "eng", &w.as_user("dave"))
        .await
        .expect("grant to eng");

    let alice = w.as_user("alice");
    assert!(actor_can(&alice, DEPLOY).await.unwrap());
    assert!(actor_can_raw(&alice, DEPLOY).await.unwrap());
    assert!(!actor_can(&w.as_user("bob"), DEPLOY).await.unwrap());
}

#[tokio::test]
async fn stranger_to_private_team_denied_sad() {
    let (w, permission_id) = deploy_world().await;
    grant_permission_to_team(&permission_id, "ops", &w.as_user("dave"))
        .await
        .expect("dave is on ops and may grant to it");

    assert!(actor_can(&w.as_user("bob"), DEPLOY).await.unwrap());
    let alice = w.as_user("alice");
    assert!(!actor_can(&alice, DEPLOY).await.unwrap());
    assert!(!actor_can_raw(&alice, DEPLOY).await.unwrap());
    // Asked about a member, a session that can't read the team still gets no.
    assert!(!user_can(&alice, "bob", DEPLOY).await.unwrap());
}

#[tokio::test]
async fn anonymous_never_matches_team_grant_sad() {
    let (w, permission_id) = deploy_world().await;
    grant_permission_to_team(&permission_id, "eng", &w.as_user("dave"))
        .await
        .expect("grant to eng");

    let anon = w.as_actor(Actor::Anonymous);
    assert!(!actor_can(&anon, DEPLOY).await.unwrap());
    assert!(!actor_can_raw(&anon, DEPLOY).await.unwrap());
    assert!(!user_can(&anon, "alice", DEPLOY).await.unwrap());
}

#[tokio::test]
async fn grant_to_unreadable_team_not_found_sad() {
    let (w, permission_id) = deploy_world().await;
    let err = grant_permission_to_team(&permission_id, "secret", &w.as_user("dave"))
        .await
        .expect_err("dave can't read secret");
    assert!(matches!(
        err.downcast_ref::<GaugeServiceError>(),
        Some(GaugeServiceError::NotFound { .. })
    ));

    let err = grant_permission_to_team(&permission_id, "eng", &w.as_user("alice"))
        .await
        .expect_err("alice can't edit the permission");
    assert!(matches!(
        err.downcast_ref::<GaugeServiceError>(),
        Some(GaugeServiceError::NotAuthorized { .. })
    ));
}

#[tokio::test]
async fn allow_list_names_readable_teams_and_hides_the_rest_happy() {
    let (w, permission_id) = deploy_world().await;
    let dave = w.as_user("dave");
    grant_permission_to_team(&permission_id, "eng", &dave)
        .await
        .expect("grant to eng");
    grant_permission_to_team(&permission_id, "ops", &dave)
        .await
        .expect("grant to ops");

    let label = |detail: &gauge::types::PermissionDetailDto, id: &str| {
        detail
            .allow_list
            .iter()
            .find(|p| p.kind == PrincipalKind::Team && p.id == id)
            .map(|p| p.label.clone())
    };

    let for_dave = get_permission_detail(&permission_id, &dave)
        .await
        .unwrap()
        .expect("detail");
    assert_eq!(label(&for_dave, "eng").as_deref(), Some("Engineering"));
    assert_eq!(label(&for_dave, "ops").as_deref(), Some("Operations"));

    // carol is a super user who isn't on ops: the grant shows, the team name doesn't.
    let for_carol = get_permission_detail(&permission_id, &w.as_user("carol"))
        .await
        .unwrap()
        .expect("detail");
    assert_eq!(label(&for_carol, "eng").as_deref(), Some("Engineering"));
    assert_eq!(label(&for_carol, "ops").as_deref(), Some("Hidden team"));
}

#[tokio::test]
async fn revoke_team_grant_removes_access_happy() {
    let (w, permission_id) = deploy_world().await;
    let dave = w.as_user("dave");
    grant_permission_to_team(&permission_id, "eng", &dave)
        .await
        .expect("grant to eng");
    assert!(actor_can(&w.as_user("alice"), DEPLOY).await.unwrap());

    revoke_permission_from_team(&permission_id, "eng", &dave)
        .await
        .expect("revoke");
    assert!(!actor_can(&w.as_user("alice"), DEPLOY).await.unwrap());
    // Revoking again changes nothing.
    revoke_permission_from_team(&permission_id, "eng", &dave)
        .await
        .expect("second revoke is a no-op");
}

#[tokio::test]
async fn team_search_source_lists_readable_teams_only_happy() {
    let w = world().await;
    let registry = uf_search_core::SearchSourceRegistry::auto_discover();
    let keys = vec![gauge::search_sources::PermissionSearchSourceId::Team.into()];
    let ids = |items: Vec<uf_search_core::SearchSourceItem>| {
        let mut ids: Vec<String> = items.into_iter().map(|i| i.id).collect();
        ids.sort();
        ids
    };

    let for_alice = registry
        .query_many(&keys, &w.as_user("alice"), "", 10)
        .await
        .expect("search as alice");
    assert_eq!(ids(for_alice), vec!["eng".to_string()]);

    let for_bob = registry
        .query_many(&keys, &w.as_user("bob"), "o", 10)
        .await
        .expect("search as bob");
    assert_eq!(ids(for_bob), vec!["ops".to_string()]);
}
