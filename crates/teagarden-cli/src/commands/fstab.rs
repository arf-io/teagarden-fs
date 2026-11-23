use anyhow::{Context, Result};

use crate::teagarden_fstab::{MountEntry, TeagardenFstab};

pub async fn list() -> Result<()> {
    let tab = TeagardenFstab::load()?;

    if tab.mounts.is_empty() {
        println!("teagarden.fstab is empty.");
        println!();
        println!("Add an entry:");
        println!("  teagarden fstab add --volume \"ember pulses swiftly\" --mountpoint ~/vault");
        return Ok(());
    }

    println!(
        "{:<32}  {:<28}  {:<5}  OPTIONS",
        "VOLUME", "MOUNTPOINT", "AUTO"
    );
    println!("{}", "-".repeat(80));

    for m in &tab.mounts {
        let mut opts = Vec::new();
        if m.allow_other {
            opts.push("allow-other");
        }
        if m.password_file.is_some() {
            opts.push("password-file");
        }
        let opts_str = if opts.is_empty() {
            "-".to_string()
        } else {
            opts.join(",")
        };
        println!(
            "{:<32}  {:<28}  {:<5}  {}",
            m.volume, m.mountpoint, m.auto, opts_str
        );
    }

    println!();
    println!(
        "{} entry(ies). Config: {}",
        tab.mounts.len(),
        TeagardenFstab::path()?.display()
    );
    Ok(())
}

pub async fn add(
    volume: &str,
    mountpoint: &str,
    auto: bool,
    allow_other: bool,
    password_file: Option<&str>,
) -> Result<()> {
    let mut tab = TeagardenFstab::load()?;

    if tab.find(volume).is_some() {
        anyhow::bail!(
            "Volume '{}' already has an entry in teagarden.fstab.\nUse `teagarden fstab remove --volume \"{}\"` first.",
            volume, volume
        );
    }

    tab.mounts.push(MountEntry {
        volume: volume.to_string(),
        mountpoint: mountpoint.to_string(),
        auto,
        allow_other,
        password_file: password_file.map(str::to_string),
    });

    tab.save()?;
    println!("Added '{}' → '{}'", volume, mountpoint);
    println!("  auto={auto}  allow_other={allow_other}");
    if let Some(pf) = password_file {
        println!("  password-file={pf}");
    }
    println!();
    println!("Use `teagarden fstab list` to view all entries.");
    Ok(())
}

pub async fn remove(volume: &str) -> Result<()> {
    let mut tab = TeagardenFstab::load()?;
    let before = tab.mounts.len();
    tab.mounts
        .retain(|m| m.volume.to_lowercase() != volume.to_lowercase());

    if tab.mounts.len() == before {
        anyhow::bail!("No entry for '{}' in teagarden.fstab.", volume);
    }

    tab.save()?;
    println!("Removed '{}' from teagarden.fstab.", volume);
    Ok(())
}

pub async fn mount_all() -> Result<()> {
    let tab = TeagardenFstab::load()?;
    let auto_entries: Vec<_> = tab.mounts.iter().filter(|m| m.auto).collect();

    if auto_entries.is_empty() {
        println!("No auto=true entries in teagarden.fstab.");
        return Ok(());
    }

    let exe = std::env::current_exe().context("resolve teagarden executable")?;
    let mut mounted = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for entry in auto_entries {
        let mp = entry.expanded_mountpoint();
        std::fs::create_dir_all(&mp)
            .map_err(|e| anyhow::anyhow!("create mountpoint {}: {e}", mp.display()))?;

        match &entry.password_file {
            Some(pf) => {
                // The daemonizing CLI waits until the mount is observable or the
                // child exits. It reads this file in the short-lived parent and
                // pipes the secret to the long-lived mount, so neither secret nor
                // path remains in that process's argv.
                let mut cmd = std::process::Command::new(&exe);
                cmd.args(["volume", "mount", "--daemonize"]);
                cmd.arg(&entry.volume);
                cmd.arg(&mp);
                if entry.allow_other {
                    cmd.arg("--allow-other");
                }
                cmd.args(["--password-file", pf]);

                match cmd.output() {
                    Ok(output) if output.status.success() => {
                        println!("Mounted: '{}' → '{}'", entry.volume, mp.display());
                        mounted += 1;
                    }
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!(
                            "Failed to mount '{}' at '{}': {}{}",
                            entry.volume,
                            mp.display(),
                            output.status,
                            if stderr.trim().is_empty() {
                                String::new()
                            } else {
                                format!(": {}", stderr.trim())
                            }
                        );
                        failed += 1;
                    }
                    Err(error) => {
                        eprintln!("Failed to execute mount for '{}': {error}", entry.volume);
                        failed += 1;
                    }
                }
            }
            None => {
                eprintln!(
                    "Skipping '{}': no password_file set. \
                     Mount interactively with `teagarden volume mount \"{}\" {}` \
                     or add a password_file to the teagarden.fstab entry.",
                    entry.volume,
                    entry.volume,
                    mp.display()
                );
                skipped += 1;
            }
        }
    }

    println!();
    println!("{mounted} mounted, {skipped} skipped (no password_file), {failed} failed.");
    if failed > 0 {
        anyhow::bail!("{failed} configured teagarden.fstab mount(s) failed");
    }
    Ok(())
}

pub async fn unmount_all() -> Result<()> {
    let tab = TeagardenFstab::load()?;
    let mounted = active_fuse_mounts();

    if tab.mounts.is_empty() {
        println!("No entries in teagarden.fstab.");
        return Ok(());
    }

    let mut unmounted = 0usize;
    let mut not_mounted = 0usize;
    let mut failed = 0usize;

    for entry in &tab.mounts {
        let mp = entry.expanded_mountpoint();
        let mp_str = mp.to_string_lossy().to_string();

        if mounted.contains(&mp_str) {
            match super::volume::unmount(&mp_str).await {
                Ok(()) => {
                    println!("Unmounted: {mp_str}");
                    unmounted += 1;
                }
                Err(error) => {
                    eprintln!("Failed to unmount {mp_str}: {error:#}");
                    failed += 1;
                }
            }
        } else {
            not_mounted += 1;
        }
    }

    println!();
    println!("{unmounted} unmounted, {not_mounted} already unmounted, {failed} failed.");
    if failed > 0 {
        anyhow::bail!("{failed} teagarden.fstab unmount(s) failed");
    }
    Ok(())
}

fn active_fuse_mounts() -> Vec<String> {
    super::volume::active_fuse_mounts().into_values().collect()
}
