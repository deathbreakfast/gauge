use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;

// No connection: the team lives in another product (Polaron) and Gauge takes no Cargo
// dependency on it. The row holds only the provider's bare team id, no user data. A team
// that is later deleted leaves a row that matches nobody.
valence_schema! {
    PermissionTeamPrincipal {
        repository: "https://github.com/unified-field-dev/gauge",
        table: "permission_team_principal",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Principal wrapper for provider-owned teams, resolved through TeamMembershipProvider at check time",

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
            team_id: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::MinLength(1), Validator::MaxLength(200)],
            },
        ],
    }
}
