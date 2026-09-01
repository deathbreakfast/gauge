use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;
use valence::prelude::*;
use valence::privacy_policies::common::AUTHENTICATED;

valence_schema! {
    PermissionDomain {
        table: "permission_domain",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Permission grouping domain used to organize permission definitions",

        traits: [PermissionShared],

        policies: {
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            // No domain maintainers list yet — Super User only (System jobs pass via SUPER evaluator).
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
            },
            delete: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            // Marks domains created by `ensure_resource_permission_bundle`.
            // Not used to deny catalog reads today — hook for future tenancy /
            // UI distinction between resource plumbing and taxonomy domains.
            resource_scoped: {
                r#type: FieldType::Boolean,
                required: true,
                default: false,
            },
            // Raw resource id when `resource_scoped` (auditable ACL key for G3).
            // Empty / absent for taxonomy domains.
            resource_id: {
                r#type: FieldType::String,
                required: false,
            },
        ],
    }
}
