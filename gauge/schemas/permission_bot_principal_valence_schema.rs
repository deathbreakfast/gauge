use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use crate::bots::BOT_PRINCIPAL_BOT_MANAGER;
use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;

valence_schema! {
    PermissionBotPrincipal {
        repository: "https://github.com/unified-field-dev/gauge",
        table: "permission_bot_principal",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Principal wrapper for Lepton bot accounts in permission group membership",

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
                allow: [SYSTEM_ONLY, BOT_PRINCIPAL_BOT_MANAGER],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            bot: {
                r#type: FieldType::Record("bot"),
                required: true,
            },
        ],

        connections: [
            bot: {
                table: "bot",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
                model: "lepton::generated::Bot",
            },
        ],
    }
}
