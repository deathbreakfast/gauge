//! Lepton's service user gate, answered from Gauge permissions.

use std::sync::Arc;

use async_trait::async_trait;
use lepton_identity::service_users::{
    install_service_user_gate, ServiceUserGate, ServiceUserGateAlreadyInstalled,
    ServiceUserGateError,
};
use valence::Valence;

use super::{LEPTON_SERVICE_USER_CREATE, LEPTON_SERVICE_USER_MANAGE_ANY};
use crate::actor_can_raw::actor_can_raw;

/// [`ServiceUserGate`] that asks Gauge: `may_create_service_user` is
/// [`LEPTON_SERVICE_USER_CREATE`] and `may_manage_any_service_user` is
/// [`LEPTON_SERVICE_USER_MANAGE_ANY`].
///
/// Both answers come from [`actor_can_raw`] on the Valence the privacy rule
/// passes in. That is a raw walk with no actor change, as `ServiceUserGate` requires.
/// Super users pass both checks. A failed lookup is reported as a
/// [`ServiceUserGateError`] with `reason_class = "gauge_lookup"`, which Lepton treats
/// as a refusal.
#[derive(Debug, Default, Clone, Copy)]
pub struct GaugeServiceUserGate;

async fn decide(
    v: &Valence,
    permission: &'static str,
    decision: &str,
) -> Result<bool, ServiceUserGateError> {
    actor_can_raw(v, permission).await.map_err(|_| {
        log::warn!(
            target: "gauge.service_user_gate",
            "service user gate lookup failed decision={decision} reason_class=gauge_lookup"
        );
        ServiceUserGateError {
            reason_class: "gauge_lookup",
        }
    })
}

#[async_trait]
impl ServiceUserGate for GaugeServiceUserGate {
    async fn may_create_service_user(
        &self,
        valence: &Valence,
    ) -> Result<bool, ServiceUserGateError> {
        decide(valence, LEPTON_SERVICE_USER_CREATE, "create").await
    }

    async fn may_manage_any_service_user(
        &self,
        valence: &Valence,
    ) -> Result<bool, ServiceUserGateError> {
        decide(valence, LEPTON_SERVICE_USER_MANAGE_ANY, "manage_any").await
    }
}

/// Install [`GaugeServiceUserGate`] as the process's Lepton service user gate.
///
/// Call once at host boot, after [`super::seed_service_user_permissions`] and before the
/// server takes requests.
///
/// # Errors
///
/// [`ServiceUserGateAlreadyInstalled`] when a gate is already installed in this process;
/// the first gate stays.
pub fn install_gauge_service_user_gate() -> Result<(), ServiceUserGateAlreadyInstalled> {
    install_service_user_gate(Arc::new(GaugeServiceUserGate))
}
