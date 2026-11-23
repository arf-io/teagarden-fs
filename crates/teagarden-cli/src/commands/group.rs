//! Shared TeaGarden forum-group identity.
//!
//! All volumes for a given TeaGarden identity are stored as topics inside ONE
//! Telegram supergroup forum. That group's id and access hash live here, in
//! `~/.config/teagarden/group.json`, so every volume can find the shared group.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use teagarden_telegram::client::ForumAdmin;

/// Persisted identity of the shared TeaGarden forum supergroup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    /// Telegram supergroup (megagroup forum) id.
    pub group_id: i64,
    /// Group access hash captured at creation. Note it is session-scoped, so it is
    /// re-resolved at mount; this stored value is a hint / fallback.
    pub group_access_hash: i64,
    /// Human-readable group title.
    #[serde(default)]
    pub title: String,
}

/// Path to `group.json` in the config directory (see `utils::config_dir`).
pub fn group_config_path() -> Result<PathBuf> {
    Ok(super::utils::config_dir()?.join("group.json"))
}

/// Load the shared group config at `path` (normally [`group_config_path`]), or
/// `None` if it has not been created yet.
pub fn load_group_config_at(path: &Path) -> Option<GroupConfig> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Persist the shared group config to `path` (0600), creating the parent dir
/// if needed.
pub fn save_group_config_at(path: &Path, cfg: &GroupConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        teagarden_core::fsutil::ensure_private_dir(parent).context("create config dir")?;
    }
    let json = serde_json::to_string_pretty(cfg).context("serialize group.json")?;
    std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// A storage location freshly allocated on Telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocated {
    /// The shared group.
    pub group_id: i64,
    /// Its access hash.
    pub group_access_hash: i64,
    /// The new topic.
    pub topic_id: i64,
}

/// Reuse the shared storage group recorded at `group_path` (creating it on the
/// first volume or device, titled `group_name` or a random name), then create
/// ONE new forum topic for a volume or device.
///
/// The topic title is random words, never the volume's or device's name: a
/// topic title is visible to Telegram, and the user's name for their data is
/// kept local only. Nothing identifies a topic by its title — volumes and
/// devices record and use the topic id — so the title carries no meaning.
/// Deliberately takes no name parameter, so a caller cannot leak one.
pub async fn allocate_topic(
    forum: &dyn ForumAdmin,
    group_path: &Path,
    group_name: Option<&str>,
) -> Result<Allocated> {
    let (group_id, group_access_hash) = match load_group_config_at(group_path) {
        Some(g) => (g.group_id, g.group_access_hash),
        None => {
            let title = group_name
                .map(str::to_string)
                .unwrap_or_else(teagarden_core::volume::names::generate_group_name);
            let (gid, ghash) = forum
                .create_forum_group(&title)
                .await
                .map_err(super::utils::telegram_err)?;
            save_group_config_at(
                group_path,
                &GroupConfig {
                    group_id: gid,
                    group_access_hash: ghash,
                    title: title.clone(),
                },
            )?;
            println!("Created the shared storage group '{title}' (group {gid}).");
            (gid, ghash)
        }
    };
    let topic_title = teagarden_core::volume::names::generate_group_name();
    let topic_id = forum
        .create_topic(group_id, group_access_hash, &topic_title)
        .await
        .map_err(super::utils::telegram_err)?;
    Ok(Allocated {
        group_id,
        group_access_hash,
        topic_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use teagarden_telegram::mock::{ForumCall, MockTransport};

    /// Two allocations: the first creates the group (with the requested title)
    /// and a topic, the second reuses the group. Topic titles are fresh random
    /// three-word names; the group is created once.
    #[tokio::test]
    async fn allocate_topic_reuses_the_group_and_titles_topics_randomly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group.json");
        let mock = MockTransport::new();
        let a = allocate_topic(&mock, &path, Some("my group"))
            .await
            .unwrap();
        let b = allocate_topic(&mock, &path, Some("ignored")).await.unwrap();
        assert_eq!(a.group_id, b.group_id);
        assert_ne!(a.topic_id, b.topic_id);
        let calls = mock.forum_calls();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(
            calls[0],
            ForumCall::CreateGroup {
                title: "my group".into()
            }
        );
        for call in &calls[1..] {
            let ForumCall::CreateTopic {
                title, group_id, ..
            } = call
            else {
                panic!("expected a topic creation, got {call:?}");
            };
            assert_eq!(*group_id, a.group_id);
            assert_eq!(title.split_whitespace().count(), 3, "{title}");
        }
        assert_eq!(load_group_config_at(&path).unwrap().group_id, a.group_id);
    }
}
