//! Refuse Gauge writes from callers no person or System job stands behind.
//!
//! A few Gauge helpers (manifest sync, resource bundles, operator group seeds)
//! run their writes as System because they create control-plane rows that no
//! single user owns. The boot helpers accept only System; the bundle helpers
//! also accept a User. Both refuse service users and anonymous requests, which
//! could otherwise grant themselves permissions by calling them. The `service` layer gets the same result from
//! `require_user_id`.

use valence::{Actor, Valence};

use crate::service::GaugeServiceError;

/// `Ok` only for `System` callers: boot and host-wiring jobs. A `User`,
/// `ServiceUser` or `Anonymous` caller gets [`GaugeServiceError::NotAuthorized`]
/// naming `operation`. Use this for helpers that seed control-plane rows no
/// request should create, such as manifest sync and catalog seeding.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for any caller that is not System.
pub fn refuse_non_system_writer(v: &Valence, operation: &str) -> Result<(), GaugeServiceError> {
    match v.actor() {
        Actor::System { .. } => Ok(()),
        actor => {
            let actor_kind = match actor {
                Actor::User { .. } => "user",
                Actor::Anonymous => "anonymous",
                _ => "service_user",
            };
            log::warn!(
                target: "gauge.write_guard",
                "gauge write refused op={operation} actor_kind={actor_kind}"
            );
            Err(GaugeServiceError::not_authorized(operation))
        }
    }
}

/// `Ok` for `User` and `System` callers. `ServiceUser` (service users and infrastructure
/// services) and `Anonymous` callers get [`GaugeServiceError::NotAuthorized`]
/// naming `operation`.
///
/// # Errors
///
/// [`GaugeServiceError::NotAuthorized`] for a service user or anonymous caller.
pub fn refuse_unattributed_writer(v: &Valence, operation: &str) -> Result<(), GaugeServiceError> {
    match v.actor() {
        Actor::User { .. } | Actor::System { .. } => Ok(()),
        actor @ (Actor::ServiceUser { .. } | Actor::Anonymous) => {
            let actor_kind = if actor.is_anonymous() {
                "anonymous"
            } else {
                "service_user"
            };
            log::warn!(
                target: "gauge.write_guard",
                "gauge write refused op={operation} actor_kind={actor_kind}"
            );
            Err(GaugeServiceError::not_authorized(operation))
        }
    }
}
