//! TM-SEC-06: interactive gauge paths must not mid-request elevate to `Actor::System`.
//!
//! Bootstrap / teardown writes against Super-User-only tables may elevate; those
//! **files** are allowlisted below with a rationale. History append/cascade uses
//! session Valence + `defer_to_edge` (no allowlist elevates).
#![cfg(feature = "ssr")]
#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

fn crate_src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn scan_rs_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn forbidden_elevate(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("//") {
        return false;
    }
    trimmed.contains("with_actor(Actor::System")
        || trimmed.contains("with_actor(valence::Actor::System")
}

/// Files under `src/` allowed to elevate, with a one-line rationale.
///
/// Rationale: these write against Super-User-only tables (`permission_domain`
/// create/delete, catalog seed, Super User group bootstrap) that session actors
/// cannot pass via policy alone. Do not add `service/` or `side_effects/` here.
const fn elevate_allowlist() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "resource_permissions/ensure.rs",
            "resource bundle ensure/teardown writes Super-User-only domain/group/permission rows",
        ),
        (
            "resource_permissions/default_groups.rs",
            "catalog seed creates Super-User-gated domain + Create* permission",
        ),
        (
            "manifest_sync.rs",
            "manifest sync upserts taxonomy domains under System",
        ),
        (
            "gluon_operator_groups.rs",
            "Gluon operator group seed is host bootstrap under System",
        ),
        (
            "scripts/ensure_super_user_group.rs",
            "Chronon one-shot Super User group bootstrap",
        ),
        (
            "scripts/sync_super_user_membership_roles.rs",
            "Chronon Super User membership sync",
        ),
        (
            "scripts/migrate_principal_connections.rs",
            "one-shot principal edge migration",
        ),
        (
            "scripts/revoke_neutrino_secret_umbrella_grants.rs",
            "one-shot revoke of NeutrinoSecret umbrella grant edges",
        ),
        (
            "super_user.rs",
            "Super User membership graph read under System (typed get re-enters privacy)",
        ),
    ]
}

fn relative_src(path: &Path, root: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |p| p.to_string_lossy().replace('\\', "/"),
    )
}

fn is_allowlisted(rel: &str) -> bool {
    elevate_allowlist()
        .iter()
        .any(|(path_suffix, _)| rel.ends_with(path_suffix))
}

#[test]
fn whole_crate_must_not_elevate_to_system_except_allowlist_tm_sec_06() {
    let root = crate_src_root();
    let mut files = Vec::new();
    scan_rs_files(&root, &mut files);

    assert!(
        !files.is_empty(),
        "expected sources under {}",
        root.display()
    );

    let mut hits = Vec::new();
    for path in &files {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        let rel = relative_src(path, &root);
        if is_allowlisted(&rel) {
            continue;
        }
        for (idx, line) in src.lines().enumerate() {
            if forbidden_elevate(line) {
                hits.push(format!("{}:{}: {}", rel, idx + 1, line.trim()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "mid-request System elevates forbidden outside allowlist (TM-SEC-06):\n{}\n\n\
         To allow a site, add the file to elevate_allowlist() with a rationale.",
        hits.join("\n")
    );
}

#[test]
fn allowlist_entries_exist_and_elevate() {
    let root = crate_src_root();
    for (path_suffix, rationale) in elevate_allowlist() {
        assert!(
            !rationale.is_empty(),
            "allowlist entry {path_suffix} missing rationale"
        );
        let path = root.join(path_suffix);
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("allowlist path missing {}: {e}", path.display()));
        assert!(
            src.lines().any(forbidden_elevate),
            "allowlisted file {} has no elevate line — remove from allowlist if obsolete",
            path.display()
        );
    }
}
