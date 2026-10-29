fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "release".to_string());

    println!("cargo:rustc-env=OPEN_CISCO_ZTA_GIT_HASH={}", git_hash);
}
