use valence::prelude::*;

valence_trait_schema! {
    RecordHistory {
        fields: [
            id: { r#type: FieldType::String, primary_key: true, required: true },
            source: {
                r#type: FieldType::Record("permission"),
                required: true,
            },
            field_name: { r#type: FieldType::String, required: true },
            old_value: { r#type: FieldType::String, required: true },
            new_value: { r#type: FieldType::String, required: true },
            changed_at: { r#type: FieldType::DateTime, required: true },
            actor: {
                r#type: FieldType::Record("user"),
                required: false,
            },
        ],
        connections: [
            source: {
                table: "trait:HistorySource",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                target_trait: "HistorySource",
            },
            actor: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "lepton::generated::User",
            },
        ],
    }
}
