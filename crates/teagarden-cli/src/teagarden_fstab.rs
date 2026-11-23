use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One entry in the teagarden.fstab mount table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    /// Volume display name or UUID.
    pub volume: String,
    /// Mount point path. `~` is expanded to the home directory.
    pub mountpoint: String,
    /// Mount automatically at login (used by service installer). Default: true.
    #[serde(default = "bool_true")]
    pub auto: bool,
    /// Pass `allow_other` to FUSE (requires `user_allow_other` in /etc/fuse.conf). Default: false.
    #[serde(default)]
    pub allow_other: bool,
    /// Optional path to a file containing the volume password (enables non-interactive mounting).
    pub password_file: Option<String>,
}

fn bool_true() -> bool {
    true
}

impl MountEntry {
    pub fn expanded_mountpoint(&self) -> PathBuf {
        expand_tilde(&self.mountpoint)
    }
}

/// Expand a leading `~` / `~/` in `path` to the user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
    } else if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// The teagarden.fstab file — a TOML table of volume mount entries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TeagardenFstab {
    #[serde(rename = "mount", default)]
    pub mounts: Vec<MountEntry>,
}

impl TeagardenFstab {
    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(crate::commands::utils::config_dir()?.join("teagarden.fstab"))
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read teagarden.fstab: {e}"))?;
        toml::from_str(&content).map_err(|e| anyhow::anyhow!("parse teagarden.fstab: {e}"))
    }

    pub fn save(&self) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            teagarden_core::fsutil::ensure_private_dir(parent)
                .map_err(|e| anyhow::anyhow!("create config dir: {e}"))?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("serialize teagarden.fstab: {e}"))?;
        // SECURITY: teagarden.fstab contains password file paths — write with 0o600
        // (owner read/write only) to prevent other users from reading it.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("open teagarden.fstab: {e}"))?
            .write_all(content.as_bytes())
            .map_err(|e| anyhow::anyhow!("write teagarden.fstab: {e}"))
    }

    /// Find an entry by volume name (case-insensitive).
    pub fn find(&self, volume: &str) -> Option<&MountEntry> {
        let needle = volume.to_lowercase();
        self.mounts
            .iter()
            .find(|m| m.volume.to_lowercase() == needle)
    }
}
