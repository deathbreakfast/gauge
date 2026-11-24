//! Team principals: grants to a team owned by another product, resolved at check time.
//!
//! A permission can be granted to a team ([`PrincipalKind::Team`](crate::types::PrincipalKind::Team)).
//! Gauge stores only the team's bare id in a `permission_team_principal` row and never copies
//! the roster. When a permission is checked, Gauge asks the registered
//! [`TeamMembershipProvider`] whether the user is on the team, reading as the session doing the
//! check. Someone who joins the team gains access on their next check; someone who leaves loses
//! it the same way. Nothing is written when a roster changes, so nothing runs as System.
//!
//! Gauge calls the trait and never implements it, so it keeps no Cargo dependency on the
//! product that owns teams (Polaron). With no provider registered, a team principal matches
//! nobody. Two or more registrations are treated as a misconfiguration and also match nobody.
//!
//! # Register a provider
//!
//! ```ignore
//! use gauge::teams::{TeamMembershipProvider, TeamMembershipProviderRegistration, TeamSummary};
//!
//! struct PolaronTeams;
//!
//! #[async_trait::async_trait]
//! impl TeamMembershipProvider for PolaronTeams {
//!     async fn is_member(&self, team_id: &str, user_id: &str, v: &valence::Valence)
//!         -> anyhow::Result<bool> {
//!         polaron::teams::is_team_member(v, team_id, user_id).await
//!     }
//!     async fn team_name(&self, team_id: &str, v: &valence::Valence)
//!         -> anyhow::Result<Option<String>> {
//!         Ok(polaron::teams::get(v, team_id).await?.map(|t| t.name))
//!     }
//!     async fn search_teams(&self, query: &str, max: u32, v: &valence::Valence)
//!         -> anyhow::Result<Vec<TeamSummary>> {
//!         // ...
//!         # Ok(Vec::new())
//!     }
//! }
//!
//! inventory::submit! { TeamMembershipProviderRegistration(&PolaronTeams) }
//! ```
//!
//! # Re-entrancy
//!
//! The resource-grant check ([`crate::actor_can_raw`]) runs inside Valence privacy evaluation
//! and calls the provider from there. A provider's team read must not itself be gated on a
//! Gauge permission that can be granted to a team, or the check recurses.

use async_trait::async_trait;
use valence::Valence;

/// A team as the principal picker shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamSummary {
    /// The provider's bare team id, as stored on the team principal.
    pub id: String,
    /// Display name.
    pub name: String,
}

/// Answers team questions for Gauge. Implemented by the product that owns teams.
///
/// Every method reads as the actor on `v`. A team that actor can't read behaves as if it
/// doesn't exist: `is_member` answers `Ok(false)`, `team_name` answers `Ok(None)`, and
/// `search_teams` leaves it out.
#[async_trait]
pub trait TeamMembershipProvider: Send + Sync {
    /// Whether `user_id` (bare, no `user:` prefix) is on `team_id`, read as the actor on `v`.
    async fn is_member(&self, team_id: &str, user_id: &str, v: &Valence) -> anyhow::Result<bool>;

    /// The team's display name, or `None` when the actor on `v` can't read it.
    async fn team_name(&self, team_id: &str, v: &Valence) -> anyhow::Result<Option<String>>;

    /// Up to `max` teams the actor on `v` can read whose name matches `query`
    /// (an empty query matches every readable team).
    async fn search_teams(
        &self,
        query: &str,
        max: u32,
        v: &Valence,
    ) -> anyhow::Result<Vec<TeamSummary>>;
}

/// Registers a [`TeamMembershipProvider`] through `inventory`. Submit exactly one per binary.
pub struct TeamMembershipProviderRegistration(pub &'static dyn TeamMembershipProvider);

inventory::collect!(TeamMembershipProviderRegistration);

/// The registered provider, or `None` when there is none or more than one.
#[must_use]
pub fn provider() -> Option<&'static dyn TeamMembershipProvider> {
    let mut registrations = inventory::iter::<TeamMembershipProviderRegistration>.into_iter();
    let first = registrations.next()?;
    if registrations.next().is_some() {
        log::error!(
            "[gauge] more than one TeamMembershipProvider registered; team principals match nobody"
        );
        return None;
    }
    Some(first.0)
}

/// Whether the user behind `user_ids` (the candidate ids of one user) is on `team_id`,
/// asked as the session on `v`.
///
/// `Ok(false)` when no provider is registered, when the session is anonymous or a service
/// user, and when the session can't read the team.
pub(crate) async fn team_has_member(
    team_id: &str,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    let Some(provider) = provider() else {
        return Ok(false);
    };
    let actor = v.actor();
    if !actor.is_system() && actor.user_id().is_none() {
        return Ok(false);
    }
    if lepton_identity::service_users::ServiceUserId::from_actor(actor).is_some() {
        return Ok(false);
    }
    let Some(user_id) = user_ids.first() else {
        return Ok(false);
    };
    let user_id = crate::service::helpers::canonical_user_id(user_id);
    if team_id.is_empty() || user_id.is_empty() {
        return Ok(false);
    }
    provider.is_member(team_id, &user_id, v).await
}
