//! Build script.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let target = std::env::var("TARGET").unwrap_or_default();

    // SSR-only generated models; skip host codegen when cross-compiling hydrate (wasm32).
    if target.contains("wasm32") {
        return Ok(());
    }

    let schemas_dir = std::path::PathBuf::from("schemas");
    println!("cargo:rerun-if-changed=schemas/");

    run_valence_generate(&schemas_dir, &out_dir)?;
    Ok(())
}

fn run_valence_generate(
    schemas_dir: &std::path::Path,
    out_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    valence_codegen::generate_models(&valence_codegen::CodegenConfig {
        schemas_dir: schemas_dir.to_path_buf(),
        out_dir: out_dir.to_path_buf(),
        file_suffix: "_valence_schema.rs",
        trait_file_suffix: "_valence_trait.rs",
    })?;
    Ok(())
}
