//! Frozen naming contract for the four platform resource kinds.
//!
//! Every string in this file already exists as a `permission`, `permission_domain`,
//! or `permission_group` primary key in deployed Valence data. Changing one is a
//! data migration, so a failure here means the refactor moved a wire name and the
//! fix belongs in the code under test, not in the table below.

use super::kinds::{
    domain_id, owners_group_id, permission_name, permission_record_id, ResourceAction,
    ResourceKind, UmbrellaPolicy,
};

/// Fixed input id. Its sanitized form is `res_42` and its FNV-1a digest is `b514137b`.
const RESOURCE_ID: &str = "res-42";

/// Expected per-kind metadata: the values every name builder reads.
struct KindGolden {
    kind: ResourceKind,
    prefix: &'static str,
    display_label: &'static str,
    umbrella: UmbrellaPolicy,
    create_permission: &'static str,
    /// creators, viewers, editors, operators.
    groups: [&'static str; 4],
    domain_id: &'static str,
    owners_group_id: &'static str,
    actions: &'static [ResourceAction],
}

const KINDS: &[KindGolden] = &[
    KindGolden {
        kind: ResourceKind::NeutrinoSecret,
        prefix: "neutrino_secret",
        display_label: "Neutrino secret",
        umbrella: UmbrellaPolicy::None,
        create_permission: "CreateNeutrinoSecrets",
        groups: [
            "neutrino.secret.creators",
            "neutrino.secret.viewers",
            "neutrino.secret.operators",
            "neutrino.secret.operators",
        ],
        domain_id: "rp_domain_neutrino_secret_res_42_b514137b",
        owners_group_id: "rp_owners_neutrino_secret_res_42_b514137b",
        actions: &[
            ResourceAction::View,
            ResourceAction::Reveal,
            ResourceAction::Edit,
            ResourceAction::Delete,
            ResourceAction::Maintain,
        ],
    },
    KindGolden {
        kind: ResourceKind::NucleusStack,
        prefix: "nucleus_stack",
        display_label: "Nucleus stack",
        umbrella: UmbrellaPolicy::KindWide,
        create_permission: "CreateNucleusStacks",
        groups: [
            "nucleus.stack.creators",
            "nucleus.stack.viewers",
            "nucleus.stack.editors",
            "nucleus.stack.operators",
        ],
        domain_id: "rp_domain_nucleus_stack_res_42_b514137b",
        owners_group_id: "rp_owners_nucleus_stack_res_42_b514137b",
        actions: &[
            ResourceAction::View,
            ResourceAction::Edit,
            ResourceAction::Delete,
            ResourceAction::Maintain,
        ],
    },
    KindGolden {
        kind: ResourceKind::GluonApp,
        prefix: "gluon_app",
        display_label: "Gluon application",
        umbrella: UmbrellaPolicy::KindWide,
        create_permission: "CreateGluonApplications",
        groups: [
            "gluon.app.creators",
            "gluon.app.viewers",
            "gluon.app.editors",
            "gluon.app.operators",
        ],
        domain_id: "rp_domain_gluon_app_res_42_b514137b",
        owners_group_id: "rp_owners_gluon_app_res_42_b514137b",
        actions: &[
            ResourceAction::View,
            ResourceAction::Edit,
            ResourceAction::Delete,
            ResourceAction::Maintain,
        ],
    },
    KindGolden {
        kind: ResourceKind::GluonAppSet,
        prefix: "gluon_app_set",
        display_label: "Gluon app set",
        umbrella: UmbrellaPolicy::KindWide,
        create_permission: "CreateGluonAppSets",
        groups: [
            "gluon.app_set.creators",
            "gluon.app_set.viewers",
            "gluon.app_set.editors",
            "gluon.app_set.operators",
        ],
        domain_id: "rp_domain_gluon_app_set_res_42_b514137b",
        owners_group_id: "rp_owners_gluon_app_set_res_42_b514137b",
        actions: &[
            ResourceAction::View,
            ResourceAction::Edit,
            ResourceAction::Delete,
            ResourceAction::Maintain,
        ],
    },
];

/// Expected `(permission_name, permission_record_id)` for every kind / action pair.
const ACTION_NAMES: &[(ResourceKind, ResourceAction, &str, &str)] = &[
    (
        ResourceKind::NeutrinoSecret,
        ResourceAction::View,
        "neutrino_secret.res_42_b514137b.View",
        "rp_perm_neutrino_secret_res_42_b514137b_view",
    ),
    (
        ResourceKind::NeutrinoSecret,
        ResourceAction::Reveal,
        "neutrino_secret.res_42_b514137b.Reveal",
        "rp_perm_neutrino_secret_res_42_b514137b_reveal",
    ),
    (
        ResourceKind::NeutrinoSecret,
        ResourceAction::Edit,
        "neutrino_secret.res_42_b514137b.Edit",
        "rp_perm_neutrino_secret_res_42_b514137b_edit",
    ),
    (
        ResourceKind::NeutrinoSecret,
        ResourceAction::Delete,
        "neutrino_secret.res_42_b514137b.Delete",
        "rp_perm_neutrino_secret_res_42_b514137b_delete",
    ),
    (
        ResourceKind::NeutrinoSecret,
        ResourceAction::Maintain,
        "neutrino_secret.res_42_b514137b.Maintain",
        "rp_perm_neutrino_secret_res_42_b514137b_maintain",
    ),
    (
        ResourceKind::NucleusStack,
        ResourceAction::View,
        "nucleus_stack.res_42_b514137b.View",
        "rp_perm_nucleus_stack_res_42_b514137b_view",
    ),
    (
        ResourceKind::NucleusStack,
        ResourceAction::Reveal,
        "nucleus_stack.res_42_b514137b.Reveal",
        "rp_perm_nucleus_stack_res_42_b514137b_reveal",
    ),
    (
        ResourceKind::NucleusStack,
        ResourceAction::Edit,
        "nucleus_stack.res_42_b514137b.Edit",
        "rp_perm_nucleus_stack_res_42_b514137b_edit",
    ),
    (
        ResourceKind::NucleusStack,
        ResourceAction::Delete,
        "nucleus_stack.res_42_b514137b.Delete",
        "rp_perm_nucleus_stack_res_42_b514137b_delete",
    ),
    (
        ResourceKind::NucleusStack,
        ResourceAction::Maintain,
        "nucleus_stack.res_42_b514137b.Maintain",
        "rp_perm_nucleus_stack_res_42_b514137b_maintain",
    ),
    (
        ResourceKind::GluonApp,
        ResourceAction::View,
        "gluon_app.res_42_b514137b.View",
        "rp_perm_gluon_app_res_42_b514137b_view",
    ),
    (
        ResourceKind::GluonApp,
        ResourceAction::Reveal,
        "gluon_app.res_42_b514137b.Reveal",
        "rp_perm_gluon_app_res_42_b514137b_reveal",
    ),
    (
        ResourceKind::GluonApp,
        ResourceAction::Edit,
        "gluon_app.res_42_b514137b.Edit",
        "rp_perm_gluon_app_res_42_b514137b_edit",
    ),
    (
        ResourceKind::GluonApp,
        ResourceAction::Delete,
        "gluon_app.res_42_b514137b.Delete",
        "rp_perm_gluon_app_res_42_b514137b_delete",
    ),
    (
        ResourceKind::GluonApp,
        ResourceAction::Maintain,
        "gluon_app.res_42_b514137b.Maintain",
        "rp_perm_gluon_app_res_42_b514137b_maintain",
    ),
    (
        ResourceKind::GluonAppSet,
        ResourceAction::View,
        "gluon_app_set.res_42_b514137b.View",
        "rp_perm_gluon_app_set_res_42_b514137b_view",
    ),
    (
        ResourceKind::GluonAppSet,
        ResourceAction::Reveal,
        "gluon_app_set.res_42_b514137b.Reveal",
        "rp_perm_gluon_app_set_res_42_b514137b_reveal",
    ),
    (
        ResourceKind::GluonAppSet,
        ResourceAction::Edit,
        "gluon_app_set.res_42_b514137b.Edit",
        "rp_perm_gluon_app_set_res_42_b514137b_edit",
    ),
    (
        ResourceKind::GluonAppSet,
        ResourceAction::Delete,
        "gluon_app_set.res_42_b514137b.Delete",
        "rp_perm_gluon_app_set_res_42_b514137b_delete",
    ),
    (
        ResourceKind::GluonAppSet,
        ResourceAction::Maintain,
        "gluon_app_set.res_42_b514137b.Maintain",
        "rp_perm_gluon_app_set_res_42_b514137b_maintain",
    ),
];

#[test]
fn action_suffixes_are_golden() {
    assert_eq!(ResourceAction::View.as_str(), "View");
    assert_eq!(ResourceAction::Edit.as_str(), "Edit");
    assert_eq!(ResourceAction::Delete.as_str(), "Delete");
    assert_eq!(ResourceAction::Maintain.as_str(), "Maintain");
    assert_eq!(ResourceAction::Reveal.as_str(), "Reveal");
}

#[test]
fn kind_metadata_is_golden() {
    for g in KINDS {
        assert_eq!(g.kind.prefix(), g.prefix, "prefix for {:?}", g.kind);
        assert_eq!(
            g.kind.display_label(),
            g.display_label,
            "display_label for {:?}",
            g.kind
        );
        assert_eq!(
            g.kind.umbrella_policy(),
            g.umbrella,
            "umbrella_policy for {:?}",
            g.kind
        );
        assert_eq!(
            g.kind.create_permission_name(),
            g.create_permission,
            "create_permission_name for {:?}",
            g.kind
        );
        let groups = g.kind.default_groups();
        assert_eq!(
            [
                groups.creators,
                groups.viewers,
                groups.editors,
                groups.operators
            ],
            g.groups,
            "default_groups for {:?}",
            g.kind
        );
        assert_eq!(
            g.kind.default_actions(),
            g.actions.to_vec(),
            "default_actions for {:?}",
            g.kind
        );
    }
}

#[test]
fn domain_and_owners_ids_are_golden() {
    for g in KINDS {
        assert_eq!(
            domain_id(g.kind, RESOURCE_ID),
            g.domain_id,
            "domain_id for {:?}",
            g.kind
        );
        assert_eq!(
            owners_group_id(g.kind, RESOURCE_ID),
            g.owners_group_id,
            "owners_group_id for {:?}",
            g.kind
        );
    }
}

#[test]
fn permission_names_and_record_ids_are_golden() {
    for (kind, action, name, record_id) in ACTION_NAMES {
        assert_eq!(
            permission_name(*kind, RESOURCE_ID, *action),
            *name,
            "permission_name for {kind:?}/{action:?}"
        );
        assert_eq!(
            permission_record_id(*kind, RESOURCE_ID, *action),
            *record_id,
            "permission_record_id for {kind:?}/{action:?}"
        );
    }
}
