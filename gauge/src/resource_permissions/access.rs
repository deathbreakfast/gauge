//! Change who can act on one resource: set or remove a principal's role on its bundle, and
//! restrict the bundle to its own grants by dropping the kind's umbrella groups.
//!
//! Every write here runs as the caller's own Valence (no System elevation) through the same
//! service calls Gauge's pages use, so history and privacy behave as they do there. The caller
//! needs Maintain on the bundle, or Super User.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use lepton_identity::service_users::ServiceUserId;
use valence::{RecordId, Valence};

use crate::generated::{Permission, PermissionGroup};
use crate::service::helpers::{
    get_domain_raw, get_group_principal_raw, get_group_raw, get_permission_raw,
    get_user_principal_raw, group_principal_id, user_principal_id,
};
use crate::service::{self, GaugeServiceError};
use crate::types::PrincipalKind;

use super::ensure::umbrella_grants;
use super::error::ResourcePermissionError;
use super::kinds::{
    domain_id, normalize_id_fragment, owners_group_id, permission_name, permission_record_id,
    ResourceAction, ResourceKindDescriptor,
};
use super::roles::{grants_for, Role};

/// Give `principal` exactly `role` on one resource, replacing whatever it held there.
///
/// `principal` is a user id, a group id, or a service user id with its [`PrincipalKind`].
/// For [`Role::Owner`] the principal becomes an owner of the bundle's owners group and its
/// direct grants on the bundle are dropped. For any other role it gets that role's grants
/// (see [`super::roles::grants_for`]), loses every other grant on the bundle, and stops
/// being an owner. Only the difference is written. Every check runs before the first write,
/// so a refused change leaves the bundle as it was.
///
/// Runs as the caller (no System elevation). The caller needs Maintain on the bundle or
/// Super User; owners hold Maintain through the owners group.
///
/// ```ignore
/// use gauge::resource_permissions::{roles::Role, set_principal_role};
/// use gauge::types::PrincipalKind;
///
/// // Give the ops team "Can run" on one job, as the signed-in owner.
/// set_principal_role(&session, CHRONON_JOB, "billing-rollup", (PrincipalKind::Group, "team_ops"), Role::Run)
///     .await?;
/// ```
///
/// # Errors
///
/// - [`ResourcePermissionError::LastOwner`] when this would demote the resource's only owner.
/// - [`ResourcePermissionError::InvalidResourceId`] when `resource_id` normalizes empty.
/// - [`ResourcePermissionError::GaugeService`] wrapping a [`GaugeServiceError`]:
///   `NotAuthorized` when the caller lacks Maintain or isn't a signed-in user or System,
///   `NotFound` when the resource has no bundle, `Validation` for a role the kind doesn't
///   offer, [`Role::Custom`], Owner for a service user, a malformed service user id, or the
///   bundle's own owners group as `principal`. Valence failures otherwise.
pub async fn set_principal_role<K>(
    v: &Valence,
    kind: K,
    resource_id: &str,
    principal: (PrincipalKind, &str),
    role: Role,
) -> Result<(), ResourcePermissionError>
where
    K: Into<ResourceKindDescriptor>,
{
    let op = "set_principal_role";
    let bundle = Bundle::load(v, kind.into(), resource_id, op).await?;
    let target = Target::parse(principal).map_err(|e| bundle.err(op, e))?;
    let desired = match role {
        Role::Owner => {
            if matches!(target, Target::ServiceUser(_)) {
                return Err(bundle.err(
                    op,
                    GaugeServiceError::validation("A service user can't own a resource"),
                ));
            }
            Desired::Owner
        }
        role => {
            let grants = grants_for(bundle.kind, &role).ok_or_else(|| {
                bundle.err(
                    op,
                    GaugeServiceError::validation(format!(
                        "A {} doesn't offer the role {role:?}",
                        bundle.kind.display_label
                    )),
                )
            })?;
            if let Some(missing) = grants.iter().find(|a| bundle.permission_id(**a).is_none()) {
                return Err(bundle.err(
                    op,
                    GaugeServiceError::validation(format!(
                        "This resource has no {} permission",
                        missing.as_str()
                    )),
                ));
            }
            Desired::Grants(grants.into_iter().collect())
        }
    };
    apply(v, &bundle, &target, &desired, op).await
}

/// Take away everything `principal` holds on one resource: its direct grants on the bundle
/// and any ownership or membership of the bundle's owners group.
///
/// Access the principal has through other groups or the kind's umbrella groups is not
/// touched. Removing a principal that holds nothing changes nothing. Runs as the caller; the
/// caller needs Maintain on the bundle or Super User.
///
/// # Errors
///
/// - [`ResourcePermissionError::LastOwner`] when `principal` is the resource's only owner.
/// - [`ResourcePermissionError::InvalidResourceId`] when `resource_id` normalizes empty.
/// - [`ResourcePermissionError::GaugeService`] wrapping a [`GaugeServiceError`]:
///   `NotAuthorized` when the caller lacks Maintain, `NotFound` when the resource has no
///   bundle, `Validation` for a malformed service user id or the bundle's own owners group.
///   Valence failures otherwise.
pub async fn remove_principal<K>(
    v: &Valence,
    kind: K,
    resource_id: &str,
    principal: (PrincipalKind, &str),
) -> Result<(), ResourcePermissionError>
where
    K: Into<ResourceKindDescriptor>,
{
    let op = "remove_principal";
    let bundle = Bundle::load(v, kind.into(), resource_id, op).await?;
    let target = Target::parse(principal).map_err(|e| bundle.err(op, e))?;
    apply(v, &bundle, &target, &Desired::Nothing, op).await
}

/// Restrict one resource to its own grants (`removed = true`), or open it to the kind's
/// umbrella groups again (`removed = false`).
///
/// Restricting revokes the kind's viewers, editors and operators groups from every permission
/// on this one bundle and sets the domain's `umbrella_removed` flag, which
/// [`super::ensure_resource_permission_bundle`] honours so a reboot doesn't grant them back.
/// Unrestricting clears the flag and grants the umbrella groups again (skipping any the host
/// never seeded). The flag is written first, so a failure part way leaves a state the next
/// call or ensure finishes. A kind with [`super::UmbrellaPolicy::None`] has no umbrella
/// groups; only the flag changes.
///
/// Runs as the caller; the caller needs Maintain on the bundle or Super User.
///
/// # Errors
///
/// - [`ResourcePermissionError::InvalidResourceId`] when `resource_id` normalizes empty.
/// - [`ResourcePermissionError::GaugeService`] wrapping a [`GaugeServiceError`]:
///   `NotAuthorized` when the caller lacks Maintain, `NotFound` when the resource has no
///   bundle or domain. Valence failures otherwise.
pub async fn set_umbrella_removed<K>(
    v: &Valence,
    kind: K,
    resource_id: &str,
    removed: bool,
) -> Result<(), ResourcePermissionError>
where
    K: Into<ResourceKindDescriptor>,
{
    let op = "set_umbrella_removed";
    let bundle = Bundle::load(v, kind.into(), resource_id, op).await?;
    let dom_id = domain_id(bundle.kind, &bundle.resource_id);
    let domain = get_domain_raw(&dom_id, v)
        .await
        .map_err(|e| bundle.err(op, e))?
        .ok_or_else(|| {
            bundle.err(
                op,
                GaugeServiceError::not_found("permission_domain", &dom_id),
            )
        })?;
    if *domain.umbrella_removed() != removed {
        domain
            .get_mutable(v, valence::use_!(r"When an owner **restricts one resource or opens it again** in **Gauge**, we **save whether the resource's kind-wide groups are removed** so a restart doesn't grant them back. Owners see the setting on the resource's access card."))
            .set_umbrella_removed(removed)
            .and_then(|m| m.set_updated_at(Utc::now()))
            .map_err(|e| bundle.err(op, e))?
            .commit()
            .await
            .map_err(|e| bundle.err(op, e))?;
    }

    for (action, perm_id, permission) in &bundle.permissions {
        let held = allowed_principals(permission, v)
            .await
            .map_err(|e| bundle.err(op, e))?;
        for group_id in umbrella_grants(&bundle.kind, *action) {
            let granted = group_principal_rid(group_id, v)
                .await
                .map_err(|e| bundle.err(op, e))?
                .is_some_and(|rid| held.contains(&rid));
            if removed && granted {
                service::revoke_permission_from_group(perm_id, group_id, v)
                    .await
                    .map_err(|e| bundle.err(op, e))?;
            } else if !removed && !granted {
                if get_group_raw(group_id, v)
                    .await
                    .map_err(|e| bundle.err(op, e))?
                    .is_none()
                {
                    log::debug!("[permission] skip re-grant missing group={group_id}");
                    continue;
                }
                service::grant_permission_to_group(perm_id, group_id, v)
                    .await
                    .map_err(|e| bundle.err(op, e))?;
            }
        }
    }
    log::info!(
        "[permission] set_umbrella_removed kind={} removed={removed}",
        bundle.kind.prefix
    );
    Ok(())
}

/// One resource's bundle as the caller sees it: the permissions that exist, by action.
struct Bundle {
    kind: ResourceKindDescriptor,
    resource_id: String,
    owners_group_id: String,
    /// (action, permission record id, permission row) for each action the bundle has.
    permissions: Vec<(ResourceAction, String, Permission)>,
}

impl Bundle {
    /// Load the bundle and check the caller may change it (Maintain, Super User, or System).
    async fn load(
        v: &Valence,
        kind: ResourceKindDescriptor,
        resource_id: &str,
        op: &str,
    ) -> Result<Self, ResourcePermissionError> {
        let resource_id = resource_id.trim().to_string();
        if normalize_id_fragment(&resource_id).is_empty() {
            return Err(ResourcePermissionError::InvalidResourceId {
                kind: kind.prefix.to_string(),
            });
        }
        let err =
            |e: anyhow::Error| ResourcePermissionError::service(kind.prefix, &resource_id, op, e);
        crate::actor_guard::refuse_unattributed_writer(v, op).map_err(|e| err(e.into()))?;

        let mut permissions = Vec::new();
        for action in kind.actions {
            let perm_id = permission_record_id(kind, &resource_id, *action);
            if let Some(permission) = get_permission_raw(&perm_id, v).await.map_err(err)? {
                permissions.push((*action, perm_id, permission));
            }
        }
        if permissions.is_empty() {
            return Err(err(GaugeServiceError::not_found(
                "resource_permission_bundle",
                &resource_id,
            )
            .into()));
        }

        let may_maintain = v.actor().is_system()
            || service::actor_can(
                v,
                &permission_name(kind, &resource_id, ResourceAction::Maintain),
            )
            .await
            .map_err(err)?
            || crate::super_user::actor_is_super_user(v)
                .await
                .map_err(err)?;
        if !may_maintain {
            log::warn!(
                target: "gauge.write_guard",
                "gauge write refused op={op} actor_kind=non_maintainer"
            );
            return Err(err(GaugeServiceError::not_authorized(op).into()));
        }

        Ok(Self {
            owners_group_id: owners_group_id(kind, &resource_id),
            kind,
            resource_id,
            permissions,
        })
    }

    fn permission_id(&self, action: ResourceAction) -> Option<&str> {
        self.permissions
            .iter()
            .find(|(a, _, _)| *a == action)
            .map(|(_, id, _)| id.as_str())
    }

    fn err(&self, op: &str, source: impl Into<anyhow::Error>) -> ResourcePermissionError {
        ResourcePermissionError::service(self.kind.prefix, &self.resource_id, op, source)
    }
}

/// The principal a role change is about.
enum Target {
    User(String),
    Group(String),
    ServiceUser(ServiceUserId),
}

impl Target {
    fn parse((kind, id): (PrincipalKind, &str)) -> Result<Self, GaugeServiceError> {
        let id = id.trim();
        if id.is_empty() {
            return Err(GaugeServiceError::validation("A principal id is required"));
        }
        Ok(match kind {
            PrincipalKind::User => Self::User(id.to_string()),
            PrincipalKind::Group => Self::Group(id.to_string()),
            PrincipalKind::ServiceUser => {
                Self::ServiceUser(ServiceUserId::parse(id).map_err(|e| {
                    GaugeServiceError::validation(format!("Invalid service user id: {e}"))
                })?)
            }
        })
    }

    /// The principal's record id, or `None` when it has never been granted anything.
    async fn principal_rid(&self, v: &Valence) -> anyhow::Result<Option<RecordId>> {
        Ok(match self {
            Self::User(id) => get_user_principal_raw(&user_principal_id(id), v)
                .await?
                .and_then(|p| p.id().cloned()),
            Self::Group(id) => group_principal_rid(id, v).await?,
            Self::ServiceUser(id) => service::get_service_user_principal_raw(id, v)
                .await?
                .and_then(|p| p.id().cloned()),
        })
    }

    async fn grant(&self, perm_id: &str, v: &Valence) -> anyhow::Result<()> {
        match self {
            Self::User(id) => service::grant_permission_to_user(perm_id, id, v).await,
            Self::Group(id) => service::grant_permission_to_group(perm_id, id, v).await,
            Self::ServiceUser(id) => {
                service::grant_permission_to_service_user_checked(perm_id, id, v).await
            }
        }
    }

    async fn revoke(&self, perm_id: &str, v: &Valence) -> anyhow::Result<()> {
        match self {
            Self::User(id) => service::revoke_permission_from_user(perm_id, id, v).await,
            Self::Group(id) => service::revoke_permission_from_group(perm_id, id, v).await,
            Self::ServiceUser(id) => {
                service::revoke_permission_from_service_user(perm_id, id, v).await
            }
        }
    }

    async fn add_owner_of(&self, group_id: &str, v: &Valence) -> anyhow::Result<()> {
        match self {
            Self::User(id) => service::add_group_owner_user(group_id, id, v).await,
            Self::Group(id) => service::add_group_owner_group(group_id, id, v).await,
            Self::ServiceUser(_) => {
                Err(GaugeServiceError::validation("A service user can't own a resource").into())
            }
        }
    }

    async fn remove_owner_of(&self, group_id: &str, v: &Valence) -> anyhow::Result<()> {
        match self {
            Self::User(id) => service::remove_group_owner_user(group_id, id, v).await,
            Self::Group(id) => service::remove_group_owner_group(group_id, id, v).await,
            Self::ServiceUser(_) => Ok(()),
        }
    }

    async fn remove_member_of(&self, group_id: &str, v: &Valence) -> anyhow::Result<()> {
        match self {
            Self::User(id) => service::remove_group_member_user(group_id, id, v).await,
            Self::Group(id) => service::remove_group_member_group(group_id, id, v).await,
            Self::ServiceUser(id) => {
                service::remove_group_member_service_user(group_id, id, v).await
            }
        }
    }
}

/// What the principal should end up with on the bundle.
enum Desired {
    /// Exactly these direct grants, and no link to the owners group.
    Grants(HashSet<ResourceAction>),
    /// Ownership of the owners group, and no direct grants.
    Owner,
    /// Nothing.
    Nothing,
}

/// Who holds what on a bundle right now.
struct Holdings {
    /// Direct grants by principal.
    direct: HashMap<RecordId, HashSet<ResourceAction>>,
    /// Owners of the bundle's owners group.
    owner_links: HashSet<RecordId>,
    /// Members of the bundle's owners group.
    member_links: HashSet<RecordId>,
    /// Principals whose role is Owner: owners or members of the owners group, or holding
    /// every action of the bundle directly. The owners group itself is left out.
    owners: HashSet<RecordId>,
}

impl Holdings {
    async fn read(
        bundle: &Bundle,
        owners_group: &PermissionGroup,
        v: &Valence,
    ) -> anyhow::Result<Self> {
        let mut direct: HashMap<RecordId, HashSet<ResourceAction>> = HashMap::new();
        for (action, _, permission) in &bundle.permissions {
            for rid in allowed_principals(permission, v).await? {
                direct.entry(rid).or_default().insert(*action);
            }
        }
        let owner_links: HashSet<RecordId> = owners_group
            .get_owners_record_ids(v, valence::use_!(r"When an owner **changes who can act on a resource** in **Gauge**, we **read the owners of the resource's owners group** so the change never leaves the resource without an owner. Owners see the result on the resource's access card."))
            .await?
            .into_iter()
            .collect();
        let member_links: HashSet<RecordId> = owners_group
            .get_members_record_ids(v, valence::use_!(r"When an owner **changes who can act on a resource** in **Gauge**, we **read the members of the resource's owners group** so the change never leaves the resource without an owner. Owners see the result on the resource's access card."))
            .await?
            .into_iter()
            .collect();

        let bundle_actions: Vec<ResourceAction> =
            bundle.permissions.iter().map(|(a, _, _)| *a).collect();
        let holds_everything = |held: &HashSet<ResourceAction>| {
            held.contains(&ResourceAction::Maintain)
                && bundle_actions.iter().all(|a| held.contains(a))
        };
        let own_group_rid = group_principal_rid(&bundle.owners_group_id, v).await?;
        let owners = owner_links
            .iter()
            .chain(member_links.iter())
            .cloned()
            .chain(
                direct
                    .iter()
                    .filter(|(_, held)| holds_everything(held))
                    .map(|(rid, _)| rid.clone()),
            )
            .filter(|rid| Some(rid) != own_group_rid.as_ref())
            .collect();
        Ok(Self {
            direct,
            owner_links,
            member_links,
            owners,
        })
    }
}

async fn apply(
    v: &Valence,
    bundle: &Bundle,
    target: &Target,
    desired: &Desired,
    op: &str,
) -> Result<(), ResourcePermissionError> {
    if matches!(target, Target::Group(id) if *id == bundle.owners_group_id) {
        return Err(bundle.err(
            op,
            GaugeServiceError::validation("The resource's owners group always holds every action"),
        ));
    }
    let owners_group = get_group_raw(&bundle.owners_group_id, v)
        .await
        .map_err(|e| bundle.err(op, e))?
        .ok_or_else(|| {
            bundle.err(
                op,
                GaugeServiceError::not_found("permission_group", &bundle.owners_group_id),
            )
        })?;
    let holdings = Holdings::read(bundle, &owners_group, v)
        .await
        .map_err(|e| bundle.err(op, e))?;
    let rid = target
        .principal_rid(v)
        .await
        .map_err(|e| bundle.err(op, e))?;
    let held: HashSet<ResourceAction> = rid
        .as_ref()
        .and_then(|r| holdings.direct.get(r))
        .cloned()
        .unwrap_or_default();
    let is_owner_link = rid
        .as_ref()
        .is_some_and(|r| holdings.owner_links.contains(r));
    let is_member_link = rid
        .as_ref()
        .is_some_and(|r| holdings.member_links.contains(r));
    let is_owner = rid.as_ref().is_some_and(|r| holdings.owners.contains(r));

    if is_owner && !matches!(desired, Desired::Owner) && holdings.owners.len() <= 1 {
        log::warn!(
            target: "gauge.write_guard",
            "gauge write refused op={op} reason=last_owner kind={}",
            bundle.kind.prefix
        );
        return Err(ResourcePermissionError::LastOwner {
            kind: bundle.kind.prefix.to_string(),
            resource_id: bundle.resource_id.clone(),
        });
    }

    let empty = HashSet::new();
    let keep = match desired {
        Desired::Grants(grants) => grants,
        Desired::Owner | Desired::Nothing => &empty,
    };
    // Add before taking away, so a role change never passes through "no access".
    if matches!(desired, Desired::Owner) && !is_owner_link {
        target
            .add_owner_of(&bundle.owners_group_id, v)
            .await
            .map_err(|e| bundle.err(op, e))?;
    }
    for (action, perm_id, _) in &bundle.permissions {
        if keep.contains(action) && !held.contains(action) {
            target
                .grant(perm_id, v)
                .await
                .map_err(|e| bundle.err(op, e))?;
        }
    }
    for (action, perm_id, _) in &bundle.permissions {
        if held.contains(action) && !keep.contains(action) {
            target
                .revoke(perm_id, v)
                .await
                .map_err(|e| bundle.err(op, e))?;
        }
    }
    if !matches!(desired, Desired::Owner) {
        if is_owner_link {
            target
                .remove_owner_of(&bundle.owners_group_id, v)
                .await
                .map_err(|e| bundle.err(op, e))?;
        }
        if is_member_link {
            target
                .remove_member_of(&bundle.owners_group_id, v)
                .await
                .map_err(|e| bundle.err(op, e))?;
        }
    }
    log::info!("[permission] {op} ok kind={}", bundle.kind.prefix);
    Ok(())
}

async fn allowed_principals(
    permission: &Permission,
    v: &Valence,
) -> anyhow::Result<HashSet<RecordId>> {
    Ok(permission
        .get_allowed_principals_record_ids(v, valence::use_!(r"When an owner **changes who can act on a resource** in **Gauge**, we **follow the allowed-principal edges** of the resource's permissions so only the difference is written. Owners see the result on the resource's access card."))
        .await?
        .into_iter()
        .collect())
}

async fn group_principal_rid(group_id: &str, v: &Valence) -> anyhow::Result<Option<RecordId>> {
    Ok(get_group_principal_raw(&group_principal_id(group_id), v)
        .await?
        .and_then(|p| p.id().cloned()))
}
