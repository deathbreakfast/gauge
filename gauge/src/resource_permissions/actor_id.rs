//! Typed actor identity for resource permission bundles.
//!
//! Provenance is enforced by construction: ordinary callers use
//! [`ActorId::from_valence`]. Explicit user/service ids for bootstrap are accepted
//! only when the live Valence actor is already [`valence::Actor::System`].

use valence::{Actor, Valence};

/// Person or service identity used as a resource-permission maintainer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorId {
    /// A Lepton user (bare id or `user:…` — stored canonicalized without prefix).
    User(String),
    /// A non-human service / bot (`Actor::ServiceUser`).
    Service(String),
}

impl ActorId {
    /// Derive identity from the live Valence actor.
    ///
    /// Returns [`None`] for Anonymous or System (System must use
    /// [`Self::user_for_system`] / [`Self::service_for_system`]).
    #[must_use]
    pub fn from_valence(v: &Valence) -> Option<Self> {
        match v.actor() {
            Actor::User { user_id } => {
                let bare = canonical_user_id(user_id);
                if bare.is_empty() {
                    None
                } else {
                    Some(Self::User(bare))
                }
            }
            Actor::ServiceUser { service_name } => {
                let name = service_name.trim();
                if name.is_empty() {
                    None
                } else {
                    Some(Self::Service(name.to_string()))
                }
            }
            Actor::System { .. } | Actor::Anonymous => None,
        }
    }

    /// Explicit user maintainer for System/bootstrap callers only.
    ///
    /// # Errors
    ///
    /// Returns an error string when `v` is not a System actor or `user_id` is empty.
    pub fn user_for_system(v: &Valence, user_id: impl AsRef<str>) -> Result<Self, &'static str> {
        if !v.actor().is_system() {
            return Err("ActorId::user_for_system requires a System Valence actor");
        }
        let bare = canonical_user_id(user_id.as_ref());
        if bare.is_empty() {
            return Err("user_id is empty");
        }
        Ok(Self::User(bare))
    }

    /// Explicit service maintainer for System/bootstrap callers only.
    ///
    /// # Errors
    ///
    /// Returns an error string when `v` is not a System actor or `service_name` is empty.
    pub fn service_for_system(
        v: &Valence,
        service_name: impl AsRef<str>,
    ) -> Result<Self, &'static str> {
        if !v.actor().is_system() {
            return Err("ActorId::service_for_system requires a System Valence actor");
        }
        let name = service_name.as_ref().trim();
        if name.is_empty() {
            return Err("service_name is empty");
        }
        Ok(Self::Service(name.to_string()))
    }

    /// Canonical bare user id when this is a [`Self::User`].
    #[must_use]
    pub fn as_user_id(&self) -> Option<&str> {
        match self {
            Self::User(id) => Some(id.as_str()),
            Self::Service(_) => None,
        }
    }

    /// True when this id matches the live Valence user actor (same bare id).
    #[must_use]
    pub fn matches_valence_user(&self, v: &Valence) -> bool {
        let Self::User(expected) = self else {
            return false;
        };
        let Some(uid) = v.actor().user_id() else {
            return false;
        };
        &canonical_user_id(uid) == expected
    }
}

fn canonical_user_id(user_id: &str) -> String {
    user_id
        .strip_prefix("user:")
        .unwrap_or(user_id)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use valence::{Actor, DatabaseBackend, InMemoryBackend, Valence, MEM_ENGINE_ID};

    fn valence_with(actor: Actor) -> Valence {
        let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
        Valence::builder()
            .add_backend(MEM_ENGINE_ID, backend)
            .with_actor(actor)
            .build()
            .expect("valence")
    }

    #[test]
    fn from_valence_user_and_rejects_system_forge() {
        let user_v = valence_with(Actor::User {
            user_id: "user:alice".into(),
        });
        assert_eq!(
            ActorId::from_valence(&user_v),
            Some(ActorId::User("alice".into()))
        );

        let forged = ActorId::user_for_system(&user_v, "bob");
        assert!(forged.is_err());

        let system_v = valence_with(Actor::System {
            operation: "boot".into(),
        });
        let ok = ActorId::user_for_system(&system_v, "bob").expect("system ok");
        assert_eq!(ok, ActorId::User("bob".into()));
    }
}
