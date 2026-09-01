use crate::privacy_policies::SUPER_USER_GROUP_MEMBER;
use valence::prelude::*;

valence_schema! {
    PermissionHistory {
        table: "permission_history",
        version: "0.2.2",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Append-only RecordHistory rows for permission and permission-group mutations",

        traits: [RecordHistory],

        policies: {
            // All ops defer to source. Parent Permission/Group Read is AUTHENTICATED —
            // list_history / get_gauge_history_page still apply can-edit as defense-in-depth.
            // Create evaluates parent Update (owner recursive / Super User).
            read: { defer_to_edge: "source" },
            create: { defer_to_edge: "source" },
            update: { defer_to_edge: "source" },
            delete: { defer_to_edge: "source" },
        },

        fields: [],
    }
}
