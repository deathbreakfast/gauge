//! Emit UC1/UC3 rows for permission checks at the gauge service choke point.

use std::cell::RefCell;

use spectra_core::{try_log_event, try_record_counter};
use valence::{Actor, Valence};

use super::events::permission_check_log_fields;

thread_local! {
    static PERMISSION_CHECK_CALLER: RefCell<Option<String>> = const { RefCell::new(None) };
    /// When `Some`, [`record_permission_check`] appends owned snapshots for tests.
    static PERMISSION_CHECK_CAPTURE: RefCell<Option<Vec<CapturedPermissionCheck>>> =
        const { RefCell::new(None) };
}

/// Outcome of a permission check at the choke point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionCheckOutcome {
    /// Actor holds the permission (directly or via inheritance / Super User).
    Allow,
    /// Actor does not hold the permission.
    Deny,
    /// Check failed due to an unexpected error.
    Error,
    /// No user actor on the Valence handle.
    NoActor,
}

impl PermissionCheckOutcome {
    /// Stable wire / metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
            Self::NoActor => "no_actor",
        }
    }
}

/// Low-cardinality bucket for metric labels (never the full permission name).
pub fn coarse_permission_kind(permission_name: &str) -> &'static str {
    if permission_name.is_empty() {
        return "empty";
    }
    match permission_name.bytes().filter(|&b| b == b'.').count() {
        0 => "catalog",
        1 => "app",
        _ => "resource",
    }
}

/// Owned snapshot of a permission-check emission (test capture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPermissionCheck {
    /// Permission name that was checked.
    pub permission_name: String,
    /// Check outcome.
    pub outcome: PermissionCheckOutcome,
}

/// Begin capturing [`record_permission_check`] calls on this thread (clears prior buffer).
///
/// Intended for integration tests; not part of the product host contract.
#[doc(hidden)]
pub fn begin_permission_check_capture() {
    PERMISSION_CHECK_CAPTURE.with(|slot| {
        *slot.borrow_mut() = Some(Vec::new());
    });
}

/// Stop capturing and return all snapshots since [`begin_permission_check_capture`].
#[doc(hidden)]
pub fn take_permission_check_captures() -> Vec<CapturedPermissionCheck> {
    PERMISSION_CHECK_CAPTURE.with(|slot| slot.borrow_mut().take().unwrap_or_default())
}

/// RAII guard setting the permission-check caller tag for the current task.
pub struct PermissionCheckCallerGuard {
    prev: Option<String>,
}

impl PermissionCheckCallerGuard {
    /// Set `caller` as the permission-check surface tag until this guard is dropped.
    pub fn new(caller: &str) -> Self {
        let prev = PERMISSION_CHECK_CALLER.with(|slot| {
            let prev = slot.borrow().clone();
            *slot.borrow_mut() = Some(caller.to_string());
            prev
        });
        Self { prev }
    }
}

impl Drop for PermissionCheckCallerGuard {
    fn drop(&mut self) {
        PERMISSION_CHECK_CALLER.with(|slot| {
            (*slot.borrow_mut()).clone_from(&self.prev);
        });
    }
}

/// Optional surface tag for the next permission check in this task.
pub fn with_permission_check_caller<F, R>(caller: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    PERMISSION_CHECK_CALLER.with(|slot| {
        let prev = slot.borrow().clone();
        *slot.borrow_mut() = Some(caller.to_string());
        let out = f();
        *slot.borrow_mut() = prev;
        out
    })
}

fn current_caller_tag() -> String {
    PERMISSION_CHECK_CALLER.with(|slot| slot.borrow().clone().unwrap_or_default())
}

fn viewer_key_from_actor(actor: &Actor) -> String {
    match actor {
        Actor::User { user_id } => user_id.clone(),
        Actor::ServiceUser { service_name } => format!("service:{service_name}"),
        Actor::System { operation } => format!("system:{operation}"),
        Actor::Anonymous => "anonymous".to_string(),
    }
}

fn operation_from_actor(actor: &Actor) -> String {
    match actor {
        Actor::System { operation } => operation.clone(),
        _ => String::new(),
    }
}

/// One permission check attempt (allow / deny / error / `no_actor`).
#[derive(Debug, Clone)]
pub struct PermissionCheckRecord<'a> {
    /// Name of the permission that was checked.
    pub permission_name: &'a str,
    /// Outcome.
    pub outcome: PermissionCheckOutcome,
    /// Stable viewer identity label derived from the Valence actor.
    pub viewer_key: String,
    /// System-actor operation label, empty for non-system actors.
    pub operation: String,
    /// Optional surface tag set via [`with_permission_check_caller`] or
    /// [`PermissionCheckCallerGuard`].
    pub caller: String,
    /// Error detail, empty on success.
    pub error_message: String,
}

impl<'a> PermissionCheckRecord<'a> {
    /// Build a record for `permission_name`/`outcome`, deriving viewer/operation/caller
    /// context from `v` and the current task's caller tag.
    pub fn from_valence(
        v: &Valence,
        permission_name: &'a str,
        outcome: PermissionCheckOutcome,
    ) -> Self {
        let actor = v.actor();
        Self {
            permission_name,
            outcome,
            viewer_key: viewer_key_from_actor(actor),
            operation: operation_from_actor(actor),
            caller: current_caller_tag(),
            error_message: String::new(),
        }
    }

    /// Attach an error message to this record (builder-style).
    pub fn with_error(mut self, message: impl Into<String>) -> Self {
        self.error_message = message.into();
        self
    }
}

/// Record UC1 counter + UC3 event for a permission check.
pub fn record_permission_check(record: &PermissionCheckRecord<'_>) {
    PERMISSION_CHECK_CAPTURE.with(|slot| {
        if let Some(buf) = slot.borrow_mut().as_mut() {
            buf.push(CapturedPermissionCheck {
                permission_name: record.permission_name.to_string(),
                outcome: record.outcome,
            });
        }
    });
    // Counters use low-cardinality labels only; full name stays on the log event.
    try_record_counter(
        "gauge_permission_checks",
        &[
            (
                "permission_kind",
                coarse_permission_kind(record.permission_name),
            ),
            ("outcome", record.outcome.as_str()),
        ],
        1,
    );
    try_log_event(
        "gauge_permission_check_log",
        &permission_check_log_fields(
            record.permission_name,
            record.outcome.as_str(),
            &record.operation,
            &record.caller,
            &record.viewer_key,
            &record.error_message,
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_permission_kind_buckets() {
        assert_eq!(coarse_permission_kind(""), "empty");
        assert_eq!(coarse_permission_kind("CreateGluonApplications"), "catalog");
        assert_eq!(coarse_permission_kind("counter.admin"), "app");
        assert_eq!(coarse_permission_kind("gluon_app.app-1.View"), "resource");
    }
}
