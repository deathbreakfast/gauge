use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;

valence_schema! {
    PermissionUserPrincipal {
        table: "permission_user_principal",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Principal wrapper for user records in permission trait-targeted relations",

        traits: [PermissionPrincipal],

        policies: {
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
            },
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
            },
            delete: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [SYSTEM_ONLY],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            user: {
                r#type: FieldType::Record("user"),
                required: true,
            },
        ],

        connections: [
            user: {
                table: "user",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "lepton::generated::User",
            },
        ],
    }
}
