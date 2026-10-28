use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use crate::service_users::SERVICE_USER_PRINCIPAL_MANAGER;
use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;

valence_schema! {
    PermissionServiceUserPrincipal {
        repository: "https://github.com/unified-field-dev/gauge",
        table: "permission_service_user_principal",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Principal wrapper for Lepton service users in permission group membership",

        traits: [PermissionPrincipal],

        policies: {
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [SYSTEM_ONLY, SERVICE_USER_PRINCIPAL_MANAGER],
            },
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [SYSTEM_ONLY, SERVICE_USER_PRINCIPAL_MANAGER],
            },
            delete: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [SYSTEM_ONLY, SERVICE_USER_PRINCIPAL_MANAGER],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            service_user: {
                r#type: FieldType::Record("service_user_account"),
                required: true,
            },
        ],

        connections: [
            service_user: {
                table: "service_user_account",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
                model: "lepton::generated::ServiceUserAccount",
            },
        ],
    }
}
