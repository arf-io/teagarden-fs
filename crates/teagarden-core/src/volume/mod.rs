/// Volume configuration types.
pub mod config;
pub mod journal_head;
#[cfg(test)]
#[allow(dead_code, missing_docs)]
mod journal_head_r9;
pub mod lockout;
/// Volume manager: create/open lifecycle, paths, and locking.
pub mod manager;
pub mod metadata_journal;
pub mod metadata_snapshot;
/// Random group-name generation for volume channels.
pub mod names;
/// Marker that the local metadata DB must be rebuilt from Telegram.
pub mod rebuild_marker;
pub mod shared;
