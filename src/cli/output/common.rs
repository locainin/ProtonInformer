use std::path::Path;

/// Formats an optional path without exposing platform-specific sentinel values
pub(super) fn display_optional_path(path: Option<&Path>) -> String {
    path.map_or_else(|| "<unknown>".into(), |path| path.display().to_string())
}
