use valence::prelude::*;

valence_trait_schema! {
    PermissionPrincipal {
        repository: "https://github.com/unified-field-dev/gauge",
        fields: [
            source_id: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::MinLength(1), Validator::MaxLength(200)],
            },
        ],
    }
}
