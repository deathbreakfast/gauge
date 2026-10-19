//! Service users in Gauge: group membership for service users, and the Lepton service user gate.
//!
//! A Lepton service user acts as its own Valence actor (`Actor::ServiceUser` named
//! `svc:<uuid>`). Gauge gives such an actor permissions only through groups:
//! add the service user with [`crate::service::add_group_member_service_user`], and
//! [`crate::service::actor_can`] / [`crate::actor_can_raw::actor_can_raw`] then
//! allow it whatever the group holds, while the service user is active. A service user is never a
//! super user, never owns a group, domain, or permission, and cannot write
//! anything in Gauge. Built-in service users, such as `cron`, still get nothing.
//!
//! The same module answers Lepton's service user gate. [`seed_service_user_permissions`]
//! creates [`LEPTON_SERVICE_USER_CREATE`] and [`LEPTON_SERVICE_USER_MANAGE_ANY`] plus the
//! "Service user creators" group, and [`install_gauge_service_user_gate`] makes Lepton ask
//! Gauge who may create service users and who may manage everyone's service users. The crate
//! root walks through both: [Give a service user permissions through a
//! group](crate#give-a-service-user-permissions-through-a-group) and [Back Lepton service user
//! creation with Gauge](crate#back-lepton-service-user-creation-with-gauge).

pub(crate) mod access;
mod gate;
mod policy;
mod seed;

use lepton_identity::service_users::{ServiceUserId, SERVICE_USER_PREFIX};

pub use gate::{install_gauge_service_user_gate, GaugeServiceUserGate};
pub use policy::{ServiceUserPrincipalManager, SERVICE_USER_PRINCIPAL_MANAGER};
pub use seed::{seed_service_user_permissions, ServiceUserSeedStats};

/// Permission that lets a user create service users they own.
pub const LEPTON_SERVICE_USER_CREATE: &str = "lepton.service_user.create";
/// Permission that lets a user view and manage every service user. Held by super users.
pub const LEPTON_SERVICE_USER_MANAGE_ANY: &str = "lepton.service_user.manage_any";
/// Id of the seeded group whose members hold [`LEPTON_SERVICE_USER_CREATE`].
pub const SERVICE_USER_CREATORS_GROUP_ID: &str = "service_user_creators";
/// Display name of [`SERVICE_USER_CREATORS_GROUP_ID`].
pub const SERVICE_USER_CREATORS_GROUP_NAME: &str = "Service user creators";

/// Valence table holding service user principals.
pub(crate) const SERVICE_USER_PRINCIPAL_TABLE: &str = "permission_service_user_principal";

/// Record id of a service user's principal row: `svc:<uuid>`.
pub(crate) fn service_user_principal_id(service_user: &ServiceUserId) -> String {
    format!("{SERVICE_USER_PREFIX}{}", service_user.as_str())
}
