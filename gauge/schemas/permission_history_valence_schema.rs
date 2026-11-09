use crate::privacy_policies::{HISTORY_APPEND, SUPER_USER_GROUP_MEMBER};
use valence::prelude::*;

valence_schema! {
    PermissionHistory {
        repository: "https://github.com/unified-field-dev/gauge",
        table: "permission_history",
        version: "0.2.3",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Append-only RecordHistory rows for permission and permission-group mutations",

        traits: [RecordHistory],

        policies: {
            // All ops defer to source. Parent Permission/Group Read is AUTHENTICATED —
            // list_history / get_gauge_history_page still apply can-edit as defense-in-depth.
            // Create evaluates parent Update (owner recursive / Super User), plus a group's own
            // `created` entry, which is written before its owner edge exists.
            read: { defer_to_edge: "source" },
            create: { always_allow: [SUPER_USER_GROUP_MEMBER], allow: [HISTORY_APPEND] },
            update: { defer_to_edge: "source" },
            delete: { defer_to_edge: "source" },
        },

        fields: [],
    }
}
