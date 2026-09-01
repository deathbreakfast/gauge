//! UC3 field builders for gauge permission check logs.

use serde_json::{json, Value};

const MAX_MESSAGE_LEN: usize = 512;
const ELLIPSIS: &str = "…";

/// Truncate `message` to at most [`MAX_MESSAGE_LEN`] bytes on a char boundary.
pub fn truncate_message(message: &str) -> String {
    if message.len() <= MAX_MESSAGE_LEN {
        return message.to_string();
    }
    let budget = MAX_MESSAGE_LEN.saturating_sub(ELLIPSIS.len());
    let mut end = budget;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ELLIPSIS}", &message[..end])
}

pub fn permission_check_log_fields(
    permission_name: &str,
    outcome: &str,
    operation: &str,
    caller: &str,
    viewer_key: &str,
    error_message: &str,
) -> Value {
    json!({
        "permission_name": permission_name,
        "outcome": outcome,
        "operation": operation,
        "caller": caller,
        "viewer_key": viewer_key,
        "error_message": truncate_message(error_message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_message_short_unchanged() {
        assert_eq!(truncate_message("ok"), "ok");
    }

    #[test]
    fn truncate_message_long_ends_with_ellipsis() {
        let long = "a".repeat(600);
        let t = truncate_message(&long);
        assert!(t.ends_with('…'));
        assert!(t.len() <= MAX_MESSAGE_LEN);
    }

    #[test]
    fn truncate_message_respects_utf8_boundaries() {
        // Fill past the budget with multi-byte chars so a naive byte slice would panic.
        let long = "é".repeat(400);
        let t = truncate_message(&long);
        assert!(t.ends_with('…'));
        assert!(t.is_char_boundary(t.len() - "…".len()));
        assert!(t.len() <= MAX_MESSAGE_LEN);
    }

    #[test]
    fn permission_check_log_fields_shape() {
        let v = permission_check_log_fields("p", "allow", "op", "c", "vk", "err");
        assert_eq!(v["permission_name"], "p");
        assert_eq!(v["outcome"], "allow");
    }
}
