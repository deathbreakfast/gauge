#[allow(unused_imports)]
use crate::side_effects::history_logger::PermissionHistoryWriter;
use crate::privacy_policies::{PERMISSION_OWNER_RECURSIVE, SUPER_USER_GROUP_MEMBER};
use valence::prelude::*;
use valence::privacy_policies::common::AUTHENTICATED;

valence_schema! {
    Permission {
        table: "permission",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Permission object defining allow-list principals and owners group",

        traits: [PermissionShared, HistorySource],

        policies: {
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            // Maintainers (owners group) or Super User; session actor — no System elevate.
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [PERMISSION_OWNER_RECURSIVE],
            },
            delete: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [PERMISSION_OWNER_RECURSIVE],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            created_by: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            owners_group: {
                r#type: FieldType::Record("permission_group"),
                required: true,
            },
            domain: {
                r#type: FieldType::Record("permission_domain"),
                required: true,
            },
        ],

        connections: [
            created_by: {
                table: "user",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "lepton::generated::User",
            },
            owners_group: {
                table: "permission_group",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "crate::generated::PermissionGroup",
            },
            domain: {
                table: "permission_domain",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "crate::generated::PermissionDomain",
            },
            allowed_principals: {
                table: "trait:PermissionPrincipal",
                cardinality: ManyToMany,
                edge_table: "permission_allowed_principal",
                target_trait: "PermissionPrincipal",
                on_delete: Cascade,
            },
        ],

        side_effects: [PermissionHistoryWriter]
    }
}
