use valence::prelude::*;

valence_trait_schema! {
    PermissionPrincipal {
        fields: [
            source_id: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::MinLength(1), Validator::MaxLength(200)],
            },
        ],
    }
}
