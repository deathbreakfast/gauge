#[allow(unused_imports)]
use crate::side_effects::history_logger::PermissionHistoryWriter;
use crate::privacy_policies::{GROUP_OWNER_RECURSIVE, SUPER_USER_GROUP_MEMBER};
use valence::prelude::*;
use valence::privacy_policies::common::AUTHENTICATED;

valence_schema! {
    PermissionGroup {
        table: "permission_group",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Permission user group with owner and member relationships",

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
            // Maintainers (owners) or Super User; session actor — no System elevate.
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [GROUP_OWNER_RECURSIVE],
            },
            delete: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [GROUP_OWNER_RECURSIVE],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
        ],

        connections: [
            owners: {
                table: "trait:PermissionPrincipal",
                cardinality: ManyToMany,
                edge_table: "permission_group_owner_principal",
                target_trait: "PermissionPrincipal",
                on_delete: Cascade,
            },
            members: {
                table: "trait:PermissionPrincipal",
                cardinality: ManyToMany,
                edge_table: "permission_group_member_principal",
                target_trait: "PermissionPrincipal",
                on_delete: Cascade,
            },
        ],

        side_effects: [PermissionHistoryWriter]
    }
}
