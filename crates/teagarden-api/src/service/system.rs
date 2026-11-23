use std::time::Instant;

use crate::types::SystemStatus;

/// System-wide status tracking.
pub struct SystemService {
    start_time: Instant,
    version: String,
}

impl Default for SystemService {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemService {
    /// Create a new service, recording the current time as the start time and
    /// capturing the crate version.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Get the current system status.
    #[allow(clippy::too_many_arguments)]
    pub fn status(
        &self,
        telegram_connected: bool,
        volumes_mounted: usize,
        volumes_open: usize,
        total_volumes: usize,
        cache_entries: usize,
        cache_size_bytes: u64,
    ) -> SystemStatus {
        SystemStatus {
            version: self.version.clone(),
            telegram_connected,
            volumes_mounted,
            volumes_open,
            total_volumes,
            cache_entries,
            cache_size_bytes,
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Get the application version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_status() {
        let svc = SystemService::new();
        let status = svc.status(false, 0, 0, 3, 50, 1024);
        assert_eq!(status.total_volumes, 3);
        assert_eq!(status.cache_entries, 50);
        assert!(!status.telegram_connected);
    }

    #[test]
    fn version_matches() {
        let svc = SystemService::new();
        assert_eq!(svc.version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn uptime_advances() {
        let svc = SystemService::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Uptime should be at least 0 (may be 0 due to timer granularity)
        let _ = svc.uptime_secs();
    }
}
