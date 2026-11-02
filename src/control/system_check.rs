use anyhow::{bail, Result};
use std::collections::BTreeSet;

/// Checks if `enroll` is mistakenly being run with root/sudo privileges.
pub fn check_enroll_privileges(allow_root: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        let is_sudo = std::env::var("SUDO_USER").is_ok();

        if (is_root || is_sudo) && !allow_root {
            bail!(
                "Running 'open-cisco-zta enroll' with root/sudo privileges is not recommended!\n\n\
                 Browser-based SSO authentication and configuration files should belong to your\n\
                 regular desktop user account. Running under sudo often causes:\n\
                   • Browser launch failures (sandbox, Wayland, or X11 display permission issues)\n\
                   • Configuration files in ~/.config/open-cisco-zta owned by root\n\n\
                 Recommended action:\n\
                   Run without sudo:\n\
                     open-cisco-zta enroll\n\n\
                 If you genuinely intend to enroll as root (e.g. on a headless server), pass `--allow-root`:\n\
                     sudo open-cisco-zta enroll --allow-root\n"
            );
        }
    }
    Ok(())
}

/// Checks if `run` in full system mode (TUN + Split-DNS) has root privileges on Linux or administrator rights on Windows.
pub fn check_run_privileges(proxy_only: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if proxy_only {
            return Ok(());
        }

        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            bail!(
                "Administrator privileges (root / sudo) are required to create the virtual\n\
                 TUN interface and configure system routing tables.\n\n\
                 How to fix:\n\
                   • Run with sudo (full TUN + Split-DNS system mode):\n\
                       sudo open-cisco-zta run\n\n\
                   • Or run in unprivileged SOCKS5h proxy mode (no root required):\n\
                       open-cisco-zta run --proxy-only\n"
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        if proxy_only {
            return Ok(());
        }

        // S-1-16-12288 is the High mandatory level SID present in an elevated token
        let elevated = std::process::Command::new("whoami")
            .arg("/groups")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"))
            .unwrap_or(false);
        if !elevated {
            bail!(
                "Administrator privileges are required to create the virtual
                 TUN interface and configure system routing tables.

                 How to fix:
                   • Run from an elevated PowerShell (Run as administrator):
                       open-cisco-zta run

                   • Or run in unprivileged SOCKS5h proxy mode:
                       open-cisco-zta run --proxy-only
"
            );
        }
    }
    Ok(())
}

/// Checks if official Cisco Secure Client services or daemons are currently running.
pub fn check_conflicting_cisco_agents(force: bool) -> Result<()> {
    if force {
        return Ok(());
    }

    let mut detected = BTreeSet::new();

    // 1. Linux service & process checks
    #[cfg(target_os = "linux")]
    {
        let target_daemons = ["csc_zta_agent", "acsockd", "vpnagentd"];

        // Check systemd services
        for name in &target_daemons {
            if let Ok(status) = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", name])
                .status()
            {
                if status.success() {
                    detected.insert(format!("{} (systemd service active)", name));
                }
            }
        }

        // Check running processes via /proc
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let comm_path = path.join("comm");
                    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                        let comm_trimmed = comm.trim();
                        for target in &target_daemons {
                            if comm_trimmed == *target {
                                detected.insert(format!("{} (process running, PID: {})", target, entry.file_name().to_string_lossy()));
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Windows process checks
    #[cfg(target_os = "windows")]
    {
        let target_exes = ["csc_zta_agent.exe", "acsockd.exe", "vpnagentd.exe"];
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let list = String::from_utf8_lossy(&output.stdout);
            for exe in &target_exes {
                if list.contains(exe) {
                    detected.insert(format!("{} (process running)", exe));
                }
            }
        }
    }

    if !detected.is_empty() {
        let mut list_str = String::new();
        for item in &detected {
            list_str.push_str(&format!("  • {}\n", item));
        }

        bail!(
            "Official Cisco Secure Client components are currently active!\n\n\
             Detected components:\n\
             {}\n\
             Running open-cisco-zta concurrently with the official Cisco agent causes\n\
             socket filter, port binding, and network interface conflicts.\n\n\
             Please stop the official Cisco services before starting open-cisco-zta:\n\
               sudo systemctl stop csc_zta_agent acsockd vpnagentd\n\n\
             To prevent them from restarting automatically:\n\
               sudo systemctl disable --now csc_zta_agent acsockd\n\n\
             (To bypass this safety check and run anyway, pass `--force`)\n",
            list_str.trim_end()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_root_bypasses_enroll_check() {
        assert!(check_enroll_privileges(true).is_ok());
    }

    #[test]
    fn test_proxy_only_bypasses_run_check() {
        assert!(check_run_privileges(true).is_ok());
    }

    #[test]
    fn test_force_bypasses_cisco_agent_check() {
        assert!(check_conflicting_cisco_agents(true).is_ok());
    }
}
