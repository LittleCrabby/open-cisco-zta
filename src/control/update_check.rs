use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const GITHUB_REPO: &str = "LittleCrabby/open-cisco-zta";
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60; // 24 hours
const CACHE_FILE_NAME: &str = ".update_cache.json";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UpdateCache {
    pub last_checked_epoch: u64,
    pub latest_version: String,
}

/// Checks if update checking has been explicitly disabled via environment variables.
pub fn is_update_check_disabled() -> bool {
    if let Ok(val) = std::env::var("OPEN_CISCO_ZTA_NO_UPDATE_CHECK") {
        if val == "1" || val.eq_ignore_ascii_case("true") || val.eq_ignore_ascii_case("yes") {
            return true;
        }
    }
    if let Ok(val) = std::env::var("CI") {
        if !val.is_empty() && val != "0" && !val.eq_ignore_ascii_case("false") {
            return true;
        }
    }
    false
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns true if `latest` is strictly newer than `current` according to SemVer.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let clean_current = current.trim().trim_start_matches('v');
    let clean_latest = latest.trim().trim_start_matches('v');

    match (
        semver::Version::parse(clean_current),
        semver::Version::parse(clean_latest),
    ) {
        (Ok(curr), Ok(lat)) => lat > curr,
        _ => false,
    }
}

/// Reads the cached latest version from disk without making any network calls.
/// Returns `Some(latest_version)` if a newer version is cached and available.
pub fn get_cached_update(config_dir: &Path) -> Option<String> {
    if is_update_check_disabled() {
        return None;
    }

    let cache = load_cache(config_dir)?;
    let current = env!("CARGO_PKG_VERSION");
    if is_newer_version(current, &cache.latest_version) {
        Some(cache.latest_version)
    } else {
        None
    }
}

/// Reads the raw cache file if present and valid.
pub fn load_cache(config_dir: &Path) -> Option<UpdateCache> {
    let cache_path = config_dir.join(CACHE_FILE_NAME);
    let content = std::fs::read_to_string(cache_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Saves the cache to disk. On Linux, if executed under sudo, restores ownership to SUDO_USER.
pub fn save_cache(config_dir: &Path, cache: &UpdateCache) {
    let cache_path = config_dir.join(CACHE_FILE_NAME);
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        if std::fs::create_dir_all(config_dir).is_ok()
            && std::fs::write(&cache_path, json).is_ok()
        {
            #[cfg(target_os = "linux")]
            adjust_cache_permissions(&cache_path);
        }
    }
}

#[cfg(target_os = "linux")]
fn adjust_cache_permissions(path: &Path) {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if sudo_user != "root" {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            if let Ok(c_user) = CString::new(sudo_user) {
                unsafe {
                    let mut pwd: libc::passwd = std::mem::zeroed();
                    let mut result: *mut libc::passwd = std::ptr::null_mut();
                    let mut buf = vec![0 as libc::c_char; 4096];

                    if libc::getpwnam_r(
                        c_user.as_ptr(),
                        &mut pwd,
                        buf.as_mut_ptr(),
                        buf.len(),
                        &mut result,
                    ) == 0
                        && !result.is_null()
                    {
                        if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
                            libc::chown(c_path.as_ptr(), pwd.pw_uid, pwd.pw_gid);
                        }
                    }
                }
            }
        }
    }
}

/// Fetches the latest released version tag from GitHub.
///
/// Tries two mechanisms:
/// 1. Fast HEAD request on `https://github.com/{repo}/releases/latest`
///    which returns 302 with Location: .../tag/vX.Y.Z (bypasses REST API rate limits).
/// 2. REST API fallback (`https://api.github.com/repos/{repo}/releases/latest`).
pub async fn fetch_latest_release() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;

    // Strategy 1: HEAD redirect check (zero rate-limit quota used)
    let redirect_url = format!("https://github.com/{}/releases/latest", GITHUB_REPO);
    if let Ok(resp) = client.head(&redirect_url).send().await {
        if resp.status().is_redirection() {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                if let Ok(loc_str) = loc.to_str() {
                    if let Some(tag) = loc_str.rsplit('/').next() {
                        let clean_tag = tag.trim().trim_start_matches('v');
                        if semver::Version::parse(clean_tag).is_ok() {
                            return Ok(clean_tag.to_string());
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: Official GitHub REST API
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    let resp = client
        .get(&api_url)
        .header(
            reqwest::header::USER_AGENT,
            format!("open-cisco-zta/{}", env!("CARGO_PKG_VERSION")),
        )
        .header(reqwest::header::ACCEPT, "application/vnd.github.v3+json")
        .send()
        .await
        .context("GitHub API request failed")?;

    if resp.status().is_success() {
        #[derive(Deserialize)]
        struct ReleaseResponse {
            tag_name: String,
        }
        let rel: ReleaseResponse = resp.json().await.context("Failed to parse release JSON")?;
        let clean_tag = rel.tag_name.trim().trim_start_matches('v');
        if semver::Version::parse(clean_tag).is_ok() {
            return Ok(clean_tag.to_string());
        }
    }

    anyhow::bail!("Could not resolve latest release version from GitHub")
}

/// Spawns a background task to refresh the version cache if it is older than 24h.
/// Returns JoinHandle if a task was spawned.
pub fn spawn_background_check(config_dir: PathBuf) -> Option<tokio::task::JoinHandle<()>> {
    if is_update_check_disabled() {
        return None;
    }

    let now = current_epoch_secs();
    if let Some(cache) = load_cache(&config_dir) {
        if now.saturating_sub(cache.last_checked_epoch) < CHECK_INTERVAL_SECS {
            return None;
        }
    }

    Some(tokio::spawn(async move {
        let now = current_epoch_secs();
        match fetch_latest_release().await {
            Ok(latest) => {
                save_cache(
                    &config_dir,
                    &UpdateCache {
                        last_checked_epoch: now,
                        latest_version: latest,
                    },
                );
            }
            Err(_) => {
                // On failure (e.g. offline, rate-limited), set backoff to 2 hours so we don't
                // spam network requests on every command.
                let backoff_epoch = now.saturating_sub(CHECK_INTERVAL_SECS.saturating_sub(7200));
                let old_latest = load_cache(&config_dir)
                    .map(|c| c.latest_version)
                    .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
                save_cache(
                    &config_dir,
                    &UpdateCache {
                        last_checked_epoch: backoff_epoch,
                        latest_version: old_latest,
                    },
                );
            }
        }
    }))
}

/// Performs an immediate check and updates the cache, returning the latest version if newer.
pub async fn check_now(config_dir: &Path) -> Option<String> {
    if is_update_check_disabled() {
        return None;
    }

    let now = current_epoch_secs();
    if let Ok(latest) = fetch_latest_release().await {
        save_cache(
            config_dir,
            &UpdateCache {
                last_checked_epoch: now,
                latest_version: latest.clone(),
            },
        );
        let current = env!("CARGO_PKG_VERSION");
        if is_newer_version(current, &latest) {
            return Some(latest);
        }
    }
    None
}

/// Formats the notification banner string.
pub fn format_update_banner(current: &str, latest: &str, use_color: bool) -> String {
    let url = format!("https://github.com/{}/releases/latest", GITHUB_REPO);

    let (yellow, bold, reset, cyan) = if use_color {
        ("\x1b[33m", "\x1b[1m", "\x1b[0m", "\x1b[36m")
    } else {
        ("", "", "", "")
    };

    let title_text = format!("Update available: v{} → v{}", current, latest);
    let link_text = format!("Download at: {}", url);

    let title_chars = title_text.chars().count();
    let link_chars = link_text.chars().count();
    let content_chars = title_chars.max(link_chars);
    let inner_width = content_chars + 4; // 2 spaces left, 2 spaces right

    let border_top = format!("╭{}╮", "─".repeat(inner_width));
    let border_bottom = format!("╰{}╯", "─".repeat(inner_width));

    let title_pad = inner_width.saturating_sub(title_chars + 2);
    let link_pad = inner_width.saturating_sub(link_chars + 2);

    format!(
        "\n{yellow}{border_top}{reset}\n\
         {yellow}│{reset}  {bold}Update available:{reset} v{} → {yellow}v{}{reset}{title_spaces}{yellow}│{reset}\n\
         {yellow}│{reset}  Download at: {cyan}{}{reset}{link_spaces}{yellow}│{reset}\n\
         {yellow}{border_bottom}{reset}\n",
        current,
        latest,
        url,
        title_spaces = " ".repeat(title_pad),
        link_spaces = " ".repeat(link_pad),
    )
}

/// Prints a prominent notification banner to stderr if stderr is connected to a terminal.
pub fn print_update_banner(latest_version: &str) {
    if is_update_check_disabled() {
        return;
    }

    if !std::io::stderr().is_terminal() {
        return;
    }

    let current = env!("CARGO_PKG_VERSION");
    let use_color = std::env::var("NO_COLOR").is_err();
    let banner = format_update_banner(current, latest_version, use_color);
    eprintln!("{}", banner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.1.0", "0.1.1"));
        assert!(is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("0.1.0", "1.0.0"));
        assert!(is_newer_version("v0.1.0", "v0.2.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.2.0", "0.1.0"));
        assert!(!is_newer_version("v0.2.0", "v0.1.0"));
        assert!(!is_newer_version("invalid", "0.1.0"));
    }

    #[test]
    fn test_format_update_banner_alignment() {
        let banner = format_update_banner("0.1.0", "0.2.0", false);
        let lines: Vec<&str> = banner.trim().lines().collect();
        assert_eq!(lines.len(), 4);

        // All border lines should have matching character counts
        let len0 = lines[0].chars().count();
        let len1 = lines[1].chars().count();
        let len2 = lines[2].chars().count();
        let len3 = lines[3].chars().count();

        assert_eq!(len0, len1, "Line 1 width mismatch");
        assert_eq!(len1, len2, "Line 2 width mismatch");
        assert_eq!(len2, len3, "Line 3 width mismatch");
    }

    #[test]
    fn test_cache_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("zta_test_{}", current_epoch_secs()));
        let cache = UpdateCache {
            last_checked_epoch: 12345678,
            latest_version: "0.9.9".to_string(),
        };

        save_cache(&temp_dir, &cache);
        let loaded = load_cache(&temp_dir).expect("Cache should load");
        assert_eq!(loaded, cache);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
