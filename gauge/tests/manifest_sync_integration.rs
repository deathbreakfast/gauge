//! Manifest sync + Gluon operator group seed contracts.
//!
//! Run: `cargo test -p gauge --features ssr --test manifest_sync_integration`

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{seed_user, test_valence};
use gauge::gluon_operator_groups::ensure_gluon_default_operator_groups;
use gauge::manifest_sync::{
    sync_permission_manifests, PermissionDomainInput, PermissionInput, PermissionManifestInput,
};
use gauge::service;
use valence::{Actor, Model, StringPredicate};

fn sample_manifest() -> PermissionManifestInput {
    PermissionManifestInput {
        app_id: "gauge_test_app".into(),
        domains: vec![PermissionDomainInput {
            key: "Gauge.Test".into(),
            name: "Gauge Test".into(),
            description: "manifest sync domain".into(),
            permissions: vec![PermissionInput {
                name: "GaugeTestManifestPerm".into(),
                description: "created by manifest sync".into(),
            }],
        }],
    }
}

fn gluon_shaped_manifest() -> PermissionManifestInput {
    PermissionManifestInput {
        app_id: "gluon".into(),
        domains: vec![PermissionDomainInput {
            key: "gluon".into(),
            name: "Gluon".into(),
            description: "gluon ops".into(),
            permissions: vec![
                PermissionInput {
                    name: "ManageGluonRegistries".into(),
                    description: "registries".into(),
                },
                PermissionInput {
                    name: "SyncGluonImages".into(),
                    description: "images".into(),
                },
                PermissionInput {
                    name: "ManageCloudSecrets".into(),
                    description: "secrets".into(),
                },
                PermissionInput {
                    name: "ManageCloudProviderAccounts".into(),
                    description: "accounts".into(),
                },
                PermissionInput {
                    name: "OperateCloudResources".into(),
                    description: "resources".into(),
                },
                PermissionInput {
                    name: "ManageControlPlanePools".into(),
                    description: "pools".into(),
                },
                PermissionInput {
                    name: "ManageControlPlaneAuthorityHandoff".into(),
                    description: "handoff".into(),
                },
                PermissionInput {
                    name: "DeployLocalImages".into(),
                    description: "deploy".into(),
                },
                PermissionInput {
                    name: "ManageGluonBuilds".into(),
                    description: "builds".into(),
                },
            ],
        }],
    }
}

#[tokio::test]
async fn sync_permission_manifest_creates_rows_happy_path() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "manifest_sync_happy".to_string(),
    })
    .await;

    let first = sync_permission_manifests(&system, &[sample_manifest()]).await?;
    assert_eq!(first.domains_created, 1, "first run creates domain");
    assert_eq!(first.permissions_created, 1, "first run creates permission");
    assert_eq!(first.domains_existing, 0);
    assert_eq!(first.permissions_existing, 0);

    let second = sync_permission_manifests(&system, &[sample_manifest()]).await?;
    assert_eq!(second.domains_created, 0);
    assert_eq!(second.permissions_created, 0);
    assert_eq!(second.domains_existing, 1, "idempotent domain");
    assert_eq!(second.permissions_existing, 1, "idempotent permission");

    seed_user("ops", "ops@example.test", &system).await;
    let ops = system.with_actor(Actor::User {
        user_id: "ops".to_string(),
    });
    assert!(
        !service::actor_can(&ops, "GaugeTestManifestPerm").await?,
        "manifest creates the permission row but does not grant outsiders"
    );

    let named = gauge::generated::Permission::query(&system)
        .where_name(StringPredicate::Equals("GaugeTestManifestPerm".into()))
        .limit(1)
        .first()
        .await?;
    assert!(named.is_some(), "permission row must exist after sync");

    Ok(())
}

#[tokio::test]
async fn sync_permission_manifest_empty_is_noop_sad() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "manifest_sync_empty".to_string(),
    })
    .await;

    let stats = sync_permission_manifests(&system, &[]).await?;
    assert_eq!(stats.domains_created, 0);
    assert_eq!(stats.permissions_created, 0);
    assert_eq!(stats.domains_existing, 0);
    assert_eq!(stats.permissions_existing, 0);

    let empty_app = PermissionManifestInput {
        app_id: "empty_app".into(),
        domains: vec![],
    };
    let stats2 = sync_permission_manifests(&system, &[empty_app]).await?;
    assert_eq!(stats2.domains_created, 0);
    assert_eq!(stats2.permissions_created, 0);

    Ok(())
}

#[tokio::test]
async fn ensure_gluon_operator_groups_idempotent_happy_path() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "gluon_operator_groups_happy".to_string(),
    })
    .await;

    sync_permission_manifests(&system, &[gluon_shaped_manifest()]).await?;
    ensure_gluon_default_operator_groups(&system).await?;
    ensure_gluon_default_operator_groups(&system).await?;

    let registry = gauge::generated::PermissionGroup::get("gluon_registry_operator", &system)
        .await?
        .expect("gluon_registry_operator group");
    assert_eq!(registry.name(), "Gluon registry operator");

    seed_user("gluon_ops", "gluon_ops@example.test", &system).await;
    let ops = system.with_actor(Actor::User {
        user_id: "gluon_ops".to_string(),
    });

    // Attach member under system: ensure-created groups have no human owner.
    let user = lepton::generated::User::get("gluon_ops", &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        "user:gluon_ops",
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            "gluon_ops".to_string(),
        )?,
        &system,
    )
    .await?;
    registry
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    assert!(
        service::actor_can(&ops, "ManageGluonRegistries").await?,
        "member of operator group must hold granted permission"
    );

    Ok(())
}

#[tokio::test]
async fn ensure_gluon_operator_groups_before_manifest_skips_grants_sad() -> anyhow::Result<()> {
    let system = test_valence(Actor::System {
        operation: "gluon_operator_before_manifest".to_string(),
    })
    .await;

    // No panic / hard error: missing permission names are skipped with a warn.
    ensure_gluon_default_operator_groups(&system).await?;

    let registry = gauge::generated::PermissionGroup::get("gluon_registry_operator", &system)
        .await?
        .expect("group still created");
    assert_eq!(registry.name(), "Gluon registry operator");

    seed_user("early", "early@example.test", &system).await;
    let early = system.with_actor(Actor::User {
        user_id: "early".to_string(),
    });
    let user = lepton::generated::User::get("early", &system)
        .await?
        .expect("user");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        "user:early",
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("id").clone(),
            "early".to_string(),
        )?,
        &system,
    )
    .await?;
    registry
        .relate_to_member_record(principal.id().expect("pid"), &system)
        .await?;

    assert!(
        !service::actor_can(&early, "ManageGluonRegistries").await?,
        "without manifest permission rows, group membership must not allow"
    );

    Ok(())
}
