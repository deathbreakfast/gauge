//! Logical database name for gauge Valence schemas.
//!
//! Gauge tables live on their own `gauge` logical so a host can give permission
//! data a dedicated backend. Hosts call [`register_storage`] once per router;
//! it registers the backend under the backend's own engine id and under
//! [`SCHEMA_ENGINE_ID`], the engine the schemas declare.

use std::sync::Arc;

use valence::{
    router_key, Database, DatabaseBackend, DatabaseFromEngine, DatabaseRouter, MEM_ENGINE_ID,
};

/// Logical database name gauge schemas are registered under.
pub const LOGICAL_NAME: &str = "gauge";

/// Engine id every gauge schema declares in its `database:` storage.
pub const SCHEMA_ENGINE_ID: &str = MEM_ENGINE_ID;

/// [`DatabaseFromEngine`] pointing at [`LOGICAL_NAME`] on the in-memory engine.
///
/// In-memory storage keeps trait-backed principal `source_id` fields and
/// permission CRUD round-tripping under L0 Valence. Hosts on another engine
/// route these schemas with [`register_storage`].
pub const DEFAULT_STORAGE: DatabaseFromEngine =
    Database::from_engine(LOGICAL_NAME, SCHEMA_ENGINE_ID);

/// Logical names test/server routers should link for gauge models to resolve.
pub const EMBEDDED_SURREAL_LOGICAL_NAMES: &[&str] = &[LOGICAL_NAME];

/// Router key gauge schemas resolve through ([`SCHEMA_ENGINE_ID`]:[`LOGICAL_NAME`]).
#[must_use]
pub fn schema_router_key() -> String {
    router_key(LOGICAL_NAME, SCHEMA_ENGINE_ID)
}

/// Route every gauge schema to `backend`.
///
/// Registers [`LOGICAL_NAME`] under `backend.engine_id()` and under
/// [`SCHEMA_ENGINE_ID`]. Without the second key Valence falls back to the
/// router's default backend and gauge rows land in the host's default database.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use valence::{DatabaseBackend, DatabaseRouter, InMemoryBackend};
///
/// let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
/// let mut router = DatabaseRouter::new();
/// gauge::embedded_surreal::register_storage(&mut router, backend);
/// assert!(router
///     .resolve(&gauge::embedded_surreal::schema_router_key())
///     .is_ok());
/// ```
pub fn register_storage(router: &mut DatabaseRouter, backend: Arc<dyn DatabaseBackend>) {
    router.register(
        router_key(LOGICAL_NAME, backend.engine_id()),
        Arc::clone(&backend),
    );
    router.register(schema_router_key(), backend);
}

#[cfg(test)]
mod tests {
    use super::*;
    use valence::{SqliteBackend, SQLITE_ENGINE_ID};

    #[tokio::test]
    async fn register_storage_adds_backend_and_schema_engine_keys_happy_path() {
        let backend: Arc<dyn DatabaseBackend> =
            Arc::new(SqliteBackend::connect_memory().await.expect("sqlite"));
        let mut router = DatabaseRouter::new();
        register_storage(&mut router, Arc::clone(&backend));

        let via_schema = router.resolve(&schema_router_key()).expect("schema key");
        let via_engine = router
            .resolve(&router_key(LOGICAL_NAME, SQLITE_ENGINE_ID))
            .expect("engine key");
        assert!(Arc::ptr_eq(&via_schema, &backend));
        assert!(Arc::ptr_eq(&via_engine, &backend));
    }

    #[test]
    fn unregistered_router_does_not_resolve_gauge_sad() {
        let router = DatabaseRouter::new();
        assert!(router.resolve(&schema_router_key()).is_err());
        assert_ne!(LOGICAL_NAME, "default");
    }
}
