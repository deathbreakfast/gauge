use valence::prelude::*;

valence_trait_schema! {
    PermissionShared {
        fields: [
            name: {
                r#type: FieldType::String,
                required: true,
                // Uniqueness is enforced in `gauge::service` (create_group /
                // create_permission). Schema-level `unique: true` still emits a
                // Surreal `SELECT VALUE` check that SQLite rejects.
                validations: [Validator::MinLength(1), Validator::MaxLength(200)],
            },
            description: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(2000)],
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
    }
}
