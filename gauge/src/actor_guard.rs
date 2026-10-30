//! Refuse Gauge writes from callers no person or System job stands behind.
//!
//! A few Gauge helpers (manifest sync, resource bundles, operator group seeds)
//! run their writes as System because they create control-plane rows that no
//! single user owns. They must still refuse a caller that is a service user,
//! such as a service user, or an anonymous request: otherwise a service user could grant itself
//! permissions by calling them. The `service` layer gets the same result from
//! `require_user_id`.

use valence::{Actor, Valence};

use crate::service::GaugeServiceError;

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
