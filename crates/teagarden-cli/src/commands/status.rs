use anyhow::Result;

use teagarden_api::service::system::SystemService;
use teagarden_core::volume::manager;

/// Read active TeaGarden FUSE mounts from /proc/mounts (Linux) or `mount` output (macOS).
/// Returns a list of mountpoints where TeaGarden is currently mounted.
fn active_mounts() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let content = match std::fs::read_to_string("/proc/mounts") {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        content
            .lines()
            .filter(|l| {
                let mut parts = l.splitn(4, ' ');
                let _device = parts.next().unwrap_or("");
                let _mp = parts.next().unwrap_or("");
                let fstype = parts.next().unwrap_or("");
                fstype == "fuse.teagarden"
            })
            .filter_map(|l| l.split(' ').nth(1))
            .map(|mp| mp.replace("\\040", " "))
            .collect()
    }

    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("mount")
            .output()
            .unwrap_or_else(|_| std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: vec![],
                stderr: vec![],
            });
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains("teagarden"))
            .filter_map(|l| {
                // "TeaGarden on /path (macfuse, ...)"
                l.split(" on ").nth(1).and_then(|r| r.split(" (").next())
            })
            .map(str::to_string)
            .collect()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        vec![]
    }
}

fn session_file_path() -> std::path::PathBuf {
    super::utils::session_file_path()
}

fn cache_dir() -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.cache"))
        .join("teagarden")
}

fn cache_size_str(dir: &std::path::Path) -> String {
    if !dir.exists() {
        return "not initialized".into();
    }
    let total = walkdir_size(dir);
    human_bytes(total)
}

fn walkdir_size(dir: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.filter_map(|e| e.ok())
        .map(|e| {
            let p = e.path();
            if p.is_dir() {
                walkdir_size(&p)
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub async fn show() -> Result<()> {
    let sys = SystemService::new();
    let volumes_dir = manager::default_volumes_dir();

    let volumes = manager::list_volumes(&volumes_dir).unwrap_or_default();
    let total_volumes = volumes.len();

    let mounts = active_mounts();
    let mounted_count = mounts.len();

    let session_path = session_file_path();
    let credentials = super::utils::load_telegram_credentials();

    let telegram_status = if session_path.exists() && credentials.is_ok() {
        "configured (session present)"
    } else if credentials.is_ok() {
        "credentials set (run 'teagarden auth login')"
    } else {
        "not configured (run 'teagarden configure')"
    };

    let cache_dir = cache_dir();
    let cache_status = cache_size_str(&cache_dir);

    println!("TeaGarden Status");
    println!("====================");
    println!();
    println!("Version:    {}", sys.version());
    println!(
        "Volumes:    {} configured, {} mounted",
        total_volumes, mounted_count
    );

    if !mounts.is_empty() {
        for mp in &mounts {
            println!("              ↳ {mp}");
        }
    }

    println!("Telegram:   {telegram_status}");
    println!("Cache:      {cache_status}");
    println!("Data dir:   {}", volumes_dir.display());
    println!();

    if total_volumes == 0 {
        println!("Get started: teagarden volume create");
    } else {
        println!("Use `teagarden volume list` to see volumes.");
    }

    Ok(())
}
