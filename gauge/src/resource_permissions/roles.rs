//! Roles over a resource bundle: the handful of grant sets people pick from instead of
//! ticking one box per action.
//!
//! A role is computed from the kind's actions, so the same [`Role`] means slightly different
//! grants on different kinds (Can edit includes Run only where the kind has Run):
//!
//! | Role | Grants | Offered when the kind has |
//! |------|--------|---------------------------|
//! | [`Role::View`] | View | always |
//! | [`Role::Run`] | View, Run | Run |
//! | [`Role::ReadUnmasked`] | View, Unmask | Unmask |
//! | [`Role::Edit`] | View, Run (if the kind has it), Edit | Edit |
//! | [`Role::Owner`] | every action, Maintain included (the owners group) | always |
//!
//! A set of grants that matches none of these is [`Role::Custom`], with the actions listed.
//! [`grants_for`] maps a role to its actions and [`role_of`] maps actions back to a role;
//! [`super::set_principal_role`] writes a role onto one principal.
//!
//! ```ignore
//! use gauge::resource_permissions::roles::{grants_for, role_of, Role};
//! use gauge::resource_permissions::{ResourceAction, ResourceKind};
//!
//! let kind = ResourceKind::NucleusStack; // View, Edit, Delete, Maintain
//! let edit = grants_for(kind, &Role::Edit).expect("stacks offer Can edit");
//! assert_eq!(edit, vec![ResourceAction::View, ResourceAction::Edit]);
//! assert_eq!(role_of(kind, &edit), Some(Role::Edit));
//! assert_eq!(grants_for(kind, &Role::Run), None); // stacks have no Run
//! ```

use std::collections::HashSet;

use super::kinds::{ResourceAction, ResourceKindDescriptor};

/// What a principal can do on one resource, in the terms the Access card shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    /// Can view: the View action.
    View,
    /// Can run: View and Run.
    Run,
    /// Can read unmasked: View and Unmask.
    ReadUnmasked,
    /// Can edit: View, Run when the kind has it, and Edit.
    Edit,
    /// Owner: every action on the resource, Maintain included. Written as ownership of the
    /// bundle's owners group.
    Owner,
    /// Grants that match no role, as action names (`"Edit"`, `"Delete"`, …) in a fixed order.
    Custom(Vec<String>),
}

impl Role {
    /// The roles a kind offers, in the order a picker lists them: Can view, Can run, Can read
    /// unmasked, Can edit, Owner. A role is left out when the kind lacks its action.
    #[must_use]
    pub fn offered(kind: impl Into<ResourceKindDescriptor>) -> Vec<Self> {
        let kind = kind.into();
        [
            Self::View,
            Self::Run,
            Self::ReadUnmasked,
            Self::Edit,
            Self::Owner,
        ]
        .into_iter()
        .filter(|role| grants_for(kind, role).is_some())
        .collect()
    }
}

/// Fixed order for listing actions, so [`Role::Custom`] and [`grants_for`] are stable.
const ACTION_ORDER: [ResourceAction; 8] = [
    ResourceAction::View,
    ResourceAction::Run,
    ResourceAction::Unmask,
    ResourceAction::Reveal,
    ResourceAction::Edit,
    ResourceAction::Delete,
    ResourceAction::Maintain,
    ResourceAction::Audit,
];

/// The actions `role` grants on a resource of `kind`, in a fixed order.
///
/// `None` when the kind doesn't offer the role (Can run on a kind with no Run, Can view on a
/// kind with no View) and for [`Role::Custom`], which has no grant set of its own.
/// [`Role::Owner`] returns every action of the kind: what the owners group holds.
#[must_use]
pub fn grants_for(
    kind: impl Into<ResourceKindDescriptor>,
    role: &Role,
) -> Option<Vec<ResourceAction>> {
    let kind = kind.into();
    let has = |action: ResourceAction| kind.actions.contains(&action);
    if !has(ResourceAction::View) && *role != Role::Owner {
        return None;
    }
    let wanted: Vec<ResourceAction> = match role {
        Role::View => vec![ResourceAction::View],
        Role::Run if has(ResourceAction::Run) => vec![ResourceAction::View, ResourceAction::Run],
        Role::ReadUnmasked if has(ResourceAction::Unmask) => {
            vec![ResourceAction::View, ResourceAction::Unmask]
        }
        Role::Edit if has(ResourceAction::Edit) => {
            let mut grants = vec![ResourceAction::View];
            if has(ResourceAction::Run) {
                grants.push(ResourceAction::Run);
            }
            grants.push(ResourceAction::Edit);
            grants
        }
        Role::Owner => kind.actions.to_vec(),
        Role::Run | Role::ReadUnmasked | Role::Edit | Role::Custom(_) => return None,
    };
    Some(in_order(wanted.iter().copied()))
}

/// The role a set of grants on a resource of `kind` amounts to.
///
/// Every action of the kind, Maintain included, is [`Role::Owner`]. A set equal to one role's
/// grants is that role. Anything else is [`Role::Custom`] listing the actions. Duplicates and
/// order in `grants` don't matter. `None` when `grants` is empty: no access is not a role.
#[must_use]
pub fn role_of(kind: impl Into<ResourceKindDescriptor>, grants: &[ResourceAction]) -> Option<Role> {
    let kind = kind.into();
    let held: HashSet<ResourceAction> = grants.iter().copied().collect();
    if held.is_empty() {
        return None;
    }
    if held.contains(&ResourceAction::Maintain) && kind.actions.iter().all(|a| held.contains(a)) {
        return Some(Role::Owner);
    }
    for role in [Role::View, Role::Run, Role::ReadUnmasked, Role::Edit] {
        if grants_for(kind, &role).is_some_and(|wanted| {
            wanted.len() == held.len() && wanted.iter().all(|a| held.contains(a))
        }) {
            return Some(role);
        }
    }
    Some(Role::Custom(
        in_order(held.into_iter())
            .into_iter()
            .map(|a| a.as_str().to_string())
            .collect(),
    ))
}

/// `actions` deduplicated and sorted by [`ACTION_ORDER`].
fn in_order(actions: impl Iterator<Item = ResourceAction>) -> Vec<ResourceAction> {
    let set: HashSet<ResourceAction> = actions.collect();
    ACTION_ORDER
        .into_iter()
        .filter(|a| set.contains(a))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{grants_for, role_of, Role};
    use crate::resource_permissions::default_groups::KindDefaultGroups;
    use crate::resource_permissions::kinds::{
        ResourceAction, ResourceKind, ResourceKindDescriptor, UmbrellaPolicy,
    };

    const GROUPS: KindDefaultGroups = KindDefaultGroups {
        creators: "k.creators",
        viewers: "k.viewers",
        editors: "k.editors",
        operators: "k.operators",
    };

    const fn kind(actions: &'static [ResourceAction]) -> ResourceKindDescriptor {
        ResourceKindDescriptor {
            prefix: "k",
            display_label: "K",
            actions,
            umbrella: UmbrellaPolicy::KindWide,
            groups: GROUPS,
            create_permission: "CreateK",
        }
    }

    /// A job-like kind: View, Run, Edit, Delete, Maintain.
    const JOB: ResourceKindDescriptor = kind(&[
        ResourceAction::View,
        ResourceAction::Run,
        ResourceAction::Edit,
        ResourceAction::Delete,
        ResourceAction::Maintain,
    ]);
    /// A topic-like kind: View, Run, Maintain.
    const TOPIC: ResourceKindDescriptor = kind(&[
        ResourceAction::View,
        ResourceAction::Run,
        ResourceAction::Maintain,
    ]);
    /// A table-like kind: View, Unmask, Edit, Maintain.
    const TABLE: ResourceKindDescriptor = kind(&[
        ResourceAction::View,
        ResourceAction::Unmask,
        ResourceAction::Edit,
        ResourceAction::Maintain,
    ]);

    fn descriptors() -> Vec<ResourceKindDescriptor> {
        vec![
            JOB,
            TOPIC,
            TABLE,
            ResourceKind::NeutrinoSecret.descriptor(),
            ResourceKind::NucleusStack.descriptor(),
            ResourceKind::GluonApp.descriptor(),
        ]
    }

    #[test]
    fn every_offered_role_round_trips_happy() {
        for d in descriptors() {
            let offered = Role::offered(d);
            assert!(offered.contains(&Role::View), "{}: View offered", d.prefix);
            assert!(
                offered.contains(&Role::Owner),
                "{}: Owner offered",
                d.prefix
            );
            for role in offered {
                let grants = grants_for(d, &role).expect("offered role has grants");
                assert_eq!(
                    role_of(d, &grants),
                    Some(role.clone()),
                    "{}: {role:?}",
                    d.prefix
                );
            }
        }
    }

    #[test]
    fn roles_follow_the_kind_actions_happy() {
        assert_eq!(
            grants_for(JOB, &Role::Edit),
            Some(vec![
                ResourceAction::View,
                ResourceAction::Run,
                ResourceAction::Edit
            ])
        );
        assert_eq!(
            grants_for(TABLE, &Role::Edit),
            Some(vec![ResourceAction::View, ResourceAction::Edit])
        );
        assert_eq!(
            grants_for(TABLE, &Role::ReadUnmasked),
            Some(vec![ResourceAction::View, ResourceAction::Unmask])
        );
        assert_eq!(
            Role::offered(TOPIC),
            vec![Role::View, Role::Run, Role::Owner]
        );
        assert_eq!(
            Role::offered(TABLE),
            vec![Role::View, Role::ReadUnmasked, Role::Edit, Role::Owner]
        );
        assert_eq!(
            Role::offered(JOB),
            vec![Role::View, Role::Run, Role::Edit, Role::Owner]
        );
    }

    #[test]
    fn roles_a_kind_lacks_have_no_grants_sad() {
        assert_eq!(grants_for(TOPIC, &Role::Edit), None);
        assert_eq!(grants_for(TABLE, &Role::Run), None);
        assert_eq!(grants_for(JOB, &Role::ReadUnmasked), None);
        assert_eq!(grants_for(JOB, &Role::Custom(vec!["Edit".into()])), None);
    }

    #[test]
    fn owner_is_every_action_including_maintain_happy() {
        let all = grants_for(JOB, &Role::Owner).expect("owner grants");
        assert_eq!(all.len(), JOB.actions.len());
        assert_eq!(role_of(JOB, &all), Some(Role::Owner));
        // Order and duplicates don't matter.
        let mut shuffled = all;
        shuffled.reverse();
        shuffled.push(ResourceAction::View);
        assert_eq!(role_of(JOB, &shuffled), Some(Role::Owner));
    }

    #[test]
    fn unmatched_grants_are_custom_sad() {
        assert_eq!(
            role_of(JOB, &[ResourceAction::Delete, ResourceAction::Edit]),
            Some(Role::Custom(vec!["Edit".into(), "Delete".into()]))
        );
        // Edit without View matches nothing.
        assert_eq!(
            role_of(TABLE, &[ResourceAction::Edit]),
            Some(Role::Custom(vec!["Edit".into()]))
        );
        // Everything but Maintain is not Owner.
        assert_eq!(
            role_of(
                TOPIC,
                &[
                    ResourceAction::View,
                    ResourceAction::Run,
                    ResourceAction::Unmask
                ]
            ),
            Some(Role::Custom(vec![
                "View".into(),
                "Run".into(),
                "Unmask".into()
            ]))
        );
        assert_eq!(role_of(JOB, &[]), None);
    }
}
