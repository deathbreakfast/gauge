use valence::prelude::*;

valence_trait_schema! {
    HistorySource {
        connections: [
            record_history: {
                table: "trait:RecordHistory",
                cardinality: HasMany,
                reverse_field: "source",
                target_trait: "RecordHistory",
                on_delete: Cascade,
            },
        ],
    }
}
