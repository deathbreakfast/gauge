#[allow(unused_imports)]
use crate::side_effects::permission_request_notifier::PermissionRequestNotifier;
use crate::privacy_policies::{REQUEST_TARGET_MAINTAINER, SUPER_USER_GROUP_MEMBER};
use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, BLOCK_ALL};

valence_schema! {
    PermissionRequest {
        table: "permission_request",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Request from a user to gain access to a permission or permission group",

        policies: {
            // Authenticated may read; service filters requestor/reviewer visibility.
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [AUTHENTICATED],
            },
            // Decide: target maintainers or Super User; session actor — no System elevate.
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [REQUEST_TARGET_MAINTAINER],
            },
            delete: {
                always_block: [BLOCK_ALL],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            requestor: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            approver: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            target: {
                r#type: FieldType::Record("permission"),
                required: true,
            },
            reason: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::MinLength(1), Validator::MaxLength(2000)],
            },
            status: {
                r#type: FieldType::Enum(&["PENDING", "APPROVED", "DENIED"]),
                required: true,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
        ],

        connections: [
            requestor: {
                table: "user",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "lepton::generated::User",
            },
            approver: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: Restrict,
                model: "lepton::generated::User",
            },
            target: {
                table: "permission",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "crate::generated::Permission",
                target_trait: "PermissionShared",
            },
        ],

        side_effects: [PermissionRequestNotifier]
    }
}
