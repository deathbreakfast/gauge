//! Logical embedded database name for gauge Valence schemas.

use valence::{Database, DatabaseFromEngine, MEM_ENGINE_ID};

/// Logical database name gauge schemas are registered under.
pub const LOGICAL_NAME: &str = "default";

/// [`DatabaseFromEngine`] pointing at [`LOGICAL_NAME`] on the in-memory engine.
///
/// In-memory storage keeps trait-backed principal `source_id` fields and
/// permission CRUD round-tripping under L0 Valence. Hosts that wire `SQLite` should
/// register an equivalent backend under this logical name or override schema
/// storage at composition time.
pub const DEFAULT_STORAGE: DatabaseFromEngine = Database::from_engine(LOGICAL_NAME, MEM_ENGINE_ID);

/// Logical names test/server routers should link for gauge models to resolve.
pub const EMBEDDED_SURREAL_LOGICAL_NAMES: &[&str] = &[LOGICAL_NAME];
