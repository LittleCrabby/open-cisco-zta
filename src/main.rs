use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use open_cisco_zta::config::ConfigManager;
use open_cisco_zta::control::{ConfigSync, SyncResult};
use open_cisco_zta::crypto::inspect_certificate;
use open_cisco_zta::dataplane::mux::Http2MuxTransport;
use open_cisco_zta::dataplane::router::RouteMatcher;
use open_cisco_zta::dataplane::socks5::Socks5Server;
use open_cisco_zta::net::{DnsServer, FakeIpPool, SystemRouteManager, TunDevice};
use open_cisco_zta::plugins::OsProfile;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "open-cisco-zta")]
#[command(author, version = concat!(env!("CARGO_PKG_VERSION"), " (git: ", env!("OPEN_CISCO_ZTA_GIT_HASH"), ")"))]
#[command(about = "High-performance alternative client for Cisco Secure Access ZTNA")]
struct Cli {
    #[arg(short, long, help = "Custom configuration directory path")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Display current enrollment, routing rules, and certificate status")]
    Status,

    #[command(about = "Trigger a ConfigSync request to Cisco ZTNA proxy")]
    Sync,

    #[command(about = "Run the ZTNA daemon (TUN interface and/or local SOCKS5h proxy)")]
    Run {
        #[arg(
            long,
            help = "Run in non-root user proxy mode (only SOCKS5h, no TUN or system routes)"
        )]
        proxy_only: bool,

        #[arg(
            long,
            default_value = "127.0.0.1:1080",
            help = "Listen address for local SOCKS5h server"
        )]
        socks_addr: SocketAddr,

        #[arg(
            long,
            default_value = "127.0.0.1:1053",
            help = "Listen address for embedded Fake-IP DNS server"
        )]
        dns_addr: SocketAddr,

        #[arg(
            long,
            default_value = "1.1.1.1:53",
            help = "Upstream DNS resolver for non-corporate domains"
        )]
        upstream_dns: SocketAddr,

        #[arg(
            long,
            default_value = "ztna0",
            help = "Virtual TUN interface name"
        )]
        tun_name: String,

        #[arg(
            long,
            default_value = "100.64.0.1",
            help = "IPv4 address assigned to TUN interface"
        )]
        tun_ip: Ipv4Addr,

        #[arg(
            long = "os-profile",
            alias = "spoof-os",
            value_enum,
            help = "Override OS profile / posture spoofing (auto, linux, windows). Defaults to enrollment profile"
        )]
        os_profile: Option<OsProfile>,

        #[arg(
            short,
            long,
            help = "Force start even if official Cisco Secure Client is detected or running"
        )]
        force: bool,
    },

    #[command(about = "Bootstrap new client enrollment")]
    Enroll {
        #[arg(long, help = "Pass the SSO JWT token directly (optional)")]
        token: Option<String>,

        #[arg(
            long = "os-profile",
            alias = "spoof-os",
            value_enum,
            default_value = "auto",
            help = "OS profile / posture spoofing (auto, linux, windows)"
        )]
        os_profile: OsProfile,

        #[arg(
            long,
            help = "Allow running enrollment with root/sudo privileges (not recommended)"
        )]
        allow_root: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config_mgr = if let Some(dir) = cli.config_dir {
        ConfigManager::with_dir(dir)
    } else {
        ConfigManager::new()
    };

    // Non-blocking update check:
    // 1. Read existing cached release version (instant disk read).
    let cached_update = open_cisco_zta::control::get_cached_update(config_mgr.base_dir());
    // 2. If cache is stale (>24h), spawn a background check task.
    let update_task = open_cisco_zta::control::spawn_background_check(config_mgr.base_dir().to_path_buf());

    let res = match cli.command {
        Commands::Status => cmd_status(&config_mgr).await,
        Commands::Sync => cmd_sync(&config_mgr).await,
        Commands::Run {
            proxy_only,
            socks_addr,
            dns_addr,
            upstream_dns,
            tun_name,
            tun_ip,
            os_profile,
            force,
        } => {
            cmd_run(
                &config_mgr,
                proxy_only,
                socks_addr,
                dns_addr,
                upstream_dns,
                tun_name,
                tun_ip,
                os_profile,
                force,
            )
            .await
        }
        Commands::Enroll {
            token,
            os_profile,
            allow_root,
        } => cmd_enroll(&config_mgr, token, os_profile, allow_root).await,
    };

    // Allow a brief window (up to 400ms) for background update task to finish saving cache if pending
    if let Some(task) = update_task {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(400), task).await;
    }

    // Display update banner if a newer version is known
    let latest_to_notify = cached_update.or_else(|| open_cisco_zta::control::get_cached_update(config_mgr.base_dir()));
    if let Some(latest_ver) = latest_to_notify {
        open_cisco_zta::control::print_update_banner(&latest_ver);
    }

    res
}

async fn cmd_status(mgr: &ConfigManager) -> Result<()> {
    println!("=== Open Cisco ZTNA Client Status ===");
    println!("Config Directory: {:?}", mgr.base_dir());
    println!("Client Version  : v{}", env!("CARGO_PKG_VERSION"));
    if let Some(latest) = open_cisco_zta::control::get_cached_update(mgr.base_dir()) {
        println!("Latest Version  : v{} (UPDATE AVAILABLE)", latest);
    } else {
        println!("Latest Version  : Up to date (or check pending)");
    }

    match mgr.load_enrollment() {
        Ok(enrollment) => {
            println!("\n[Enrollment Information]");
            println!("  Organization ID : {}", enrollment.org_id);
            println!("  User ID         : {}", enrollment.user_id);
            println!("  ZTNA Device ID  : {}", enrollment.ztna_device_id);
            println!("  Config Sync URL : {}", enrollment.config_sync_url);
            println!(
                "  Config ETag     : {}",
                enrollment.config_etag.as_deref().unwrap_or("(none)")
            );
            println!(
                "  Sync Interval   : {} min",
                enrollment.config_sync_interval.as_deref().unwrap_or("10")
            );
            println!(
                "  Client Alias    : {}",
                enrollment.client_cert_alias.as_deref().unwrap_or("(none)")
            );
            println!(
                "  OS Profile      : {}",
                enrollment.os_profile.as_deref().unwrap_or("auto")
            );
        }
        Err(e) => {
            println!("\n[!] Enrollment info not found: {:?}", e);
        }
    }

    match mgr.load_ztna_config() {
        Ok(ztna_config) => {
            let matcher = RouteMatcher::from_resource_configs(&ztna_config.resource_configs);
            println!("\n[Routing Policies]");
            println!("  CIDR Include Subnets : {}", matcher.cidr_includes_count());
            println!("  FQDN Include Rules   : {}", matcher.fqdn_includes_count());
            println!("  FQDN Exclude Rules   : {}", matcher.fqdn_excludes.len());

            println!("\nSample Corporate CIDRs:");
            for net in matcher.cidr_includes.iter().take(5) {
                println!("    - {}", net);
            }
            if matcher.cidr_includes.len() > 5 {
                println!("    ... and {} more subnets", matcher.cidr_includes.len() - 5);
            }

            println!("\nSample Corporate FQDNs:");
            for fqdn in matcher.fqdn_includes.iter().take(5) {
                match fqdn {
                    open_cisco_zta::dataplane::router::DomainPattern::Exact(e) => {
                        println!("    - {}", e);
                    }
                    open_cisco_zta::dataplane::router::DomainPattern::Wildcard(w) => {
                        println!("    - *.{}", w);
                    }
                }
            }
            if matcher.fqdn_includes.len() > 5 {
                println!("    ... and {} more rules", matcher.fqdn_includes.len() - 5);
            }
        }
        Err(e) => {
            println!("\n[!] ZTNA Config not found: {:?}", e);
        }
    }

    let cert_path = mgr.cert_path();
    println!("\n[Client Certificate]");
    if cert_path.exists() {
        println!("  Certificate Path: {:?}", cert_path);
        match inspect_certificate(&cert_path) {
            Ok(info) => {
                println!("  Subject   : {}", info.subject);
                println!("  Issuer    : {}", info.issuer);
                println!("  Valid From: {}", info.not_before);
                println!("  Valid To  : {}", info.not_after);
                println!("  SAN URIs  :");
                for san in &info.san_entries {
                    println!("    - {}", san);
                }
            }
            Err(e) => {
                println!("  [!] Failed to parse certificate: {:?}", e);
            }
        }
    } else {
        println!("  [!] Client certificate not found at {:?}", cert_path);
    }

    let key_path = mgr.key_path();
    println!("\n[Client Private Key]");
    if key_path.exists() {
        println!("  Key Path: {:?}", key_path);
    } else {
        println!("  [NOTE] Software PEM key not found at {:?}", key_path);
        println!("         (Run `open-cisco-zta enroll` to generate client credentials)");
    }

    println!("\n======================================");
    Ok(())
}

async fn cmd_sync(mgr: &ConfigManager) -> Result<()> {
    let syncer = ConfigSync::new(ConfigManager::with_dir(mgr.base_dir()));
    match syncer.sync_once().await {
        Ok(SyncResult::NotModified { etag, interval }) => {
            println!("ConfigSync: 304 Not Modified. ETag: {}, interval: {:?} min", etag, interval);
            Ok(())
        }
        Ok(SyncResult::Updated { etag, interval, new_config }) => {
            println!(
                "ConfigSync: 200 OK! Updated config with {} resource configs. ETag: {}, interval: {:?} min",
                new_config.resource_configs.len(),
                etag,
                interval
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("ConfigSync error: {:?}", e);
            Err(e)
        }
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to register SIGTERM handler")?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.context("Failed waiting for Ctrl+C")?;
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, initiating graceful shutdown...");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("Failed waiting for Ctrl+C")
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run(
    mgr: &ConfigManager,
    proxy_only: bool,
    socks_addr: SocketAddr,
    dns_addr: SocketAddr,
    upstream_dns: SocketAddr,
    tun_name: String,
    tun_ip: Ipv4Addr,
    os_profile: Option<OsProfile>,
    force: bool,
) -> Result<()> {
    open_cisco_zta::control::check_run_privileges(proxy_only)?;
    open_cisco_zta::control::check_conflicting_cisco_agents(force)?;

    let enrollment = mgr.load_enrollment()
        .context("Could not load enrollment. Please check ~/.config/open-cisco-zta/enrollment.json")?;

    let profile = os_profile.unwrap_or_else(|| {
        enrollment
            .os_profile
            .as_deref()
            .and_then(|p| p.parse::<OsProfile>().ok())
            .unwrap_or_default()
    });
    tracing::info!("Using active OS profile / posture: {:?}", profile);

    let ztna_config = match mgr.load_ztna_config() {
        Ok(cfg) => cfg,
        Err(load_err) => {
            tracing::info!(
                "Cached ztna_config.json not found ({:?}); performing initial ConfigSync...",
                load_err
            );
            let syncer = ConfigSync::with_os_profile(
                ConfigManager::with_dir(mgr.base_dir()),
                Some(profile),
            );
            if let Err(sync_err) = syncer.sync_once().await {
                tracing::warn!("Initial ConfigSync attempt failed: {:?}", sync_err);
            }
            mgr.load_ztna_config()
                .context("Could not load ztna_config. Please check ~/.config/open-cisco-zta/ztna_config.json")?
        }
    };

    let router = Arc::new(RouteMatcher::from_resource_configs(&ztna_config.resource_configs));
    let fake_pool = FakeIpPool::new();

    if let Some(latest) = open_cisco_zta::control::get_cached_update(mgr.base_dir()) {
        tracing::warn!(
            "A newer release of open-cisco-zta is available: v{} -> v{}. Visit https://github.com/{}/releases/latest",
            env!("CARGO_PKG_VERSION"),
            latest,
            open_cisco_zta::control::update_check::GITHUB_REPO
        );
    }

    // Spawn periodic 24-hour update checker task for long-running daemon
    let update_base_dir = mgr.base_dir().to_path_buf();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(24 * 3600)).await;
            if let Some(latest) = open_cisco_zta::control::check_now(&update_base_dir).await {
                tracing::warn!(
                    "A new release of open-cisco-zta is available: v{} -> v{}. Visit https://github.com/{}/releases/latest",
                    env!("CARGO_PKG_VERSION"),
                    latest,
                    open_cisco_zta::control::update_check::GITHUB_REPO
                );
            }
        }
    });

    // Spawn periodic ConfigSync background task
    let sync_interval_mins = enrollment
        .config_sync_interval
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10)
        .max(1);
    let sync_base_dir = mgr.base_dir().to_path_buf();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(sync_interval_mins * 60));
        interval.tick().await; // first tick is immediate
        loop {
            interval.tick().await;
            let syncer = ConfigSync::with_os_profile(
                ConfigManager::with_dir(&sync_base_dir),
                Some(profile),
            );
            match syncer.sync_once().await {
                Ok(SyncResult::Updated { etag, new_config, .. }) => {
                    tracing::info!(
                        "Periodic ConfigSync updated policy ({} resource configs, ETag: {})",
                        new_config.resource_configs.len(),
                        etag
                    );
                }
                Ok(SyncResult::NotModified { etag, .. }) => {
                    tracing::debug!("Periodic ConfigSync: 304 Not Modified (ETag: {})", etag);
                }
                Err(e) => {
                    tracing::warn!("Periodic ConfigSync failed: {:?}", e);
                }
            }
        }
    });

    let proxy_host = url::Url::parse(&enrollment.config_sync_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| format!("proxy-{}.zpc.sse.cisco.com", enrollment.org_id));
    let proxy_port = 443;

    let cert_path = Some(mgr.cert_path());
    let key_path = Some(mgr.key_path());

    let mux = Arc::new(Http2MuxTransport::new(
        proxy_host,
        proxy_port,
        cert_path,
        key_path,
        Some(Arc::new(open_cisco_zta::plugins::DefaultAcidexProvider::with_profile(profile))),
    ));

    // Start SOCKS5h server
    let socks_server = Socks5Server::new(socks_addr, Arc::clone(&router), Arc::clone(&mux));
    tokio::spawn(async move {
        if let Err(e) = socks_server.run().await {
            tracing::error!("SOCKS5 server terminated with error: {:?}", e);
        }
    });

    let tun_supported = cfg!(any(target_os = "linux", target_os = "windows"));
    let effective_proxy_only = proxy_only || !tun_supported;

    if !tun_supported && !proxy_only {
        println!("Note: Kernel TUN interface and system routes are currently supported on Linux and Windows.");
        println!("Automatically running in `--proxy-only` mode (SOCKS5h proxy).");
    }

    if effective_proxy_only {
        // In proxy-only mode, DNS runs on dns_addr (e.g. 127.0.0.1:1053)
        let dns_server = DnsServer::new(dns_addr, upstream_dns, Arc::clone(&router), fake_pool.clone());
        tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                tracing::error!("DNS server error: {:?}", e);
            }
        });

        tracing::info!("Running in PROXY-ONLY mode on {}", socks_addr);
        println!("ZTNA SOCKS5h proxy running on socks5h://{}", socks_addr);
        println!("Press Ctrl+C to stop.");
        wait_for_shutdown_signal().await?;
        println!("\nShutting down.");
        return Ok(());
    }

    // Step 1: Create TUN Device first so the IP (100.64.0.1) is available to bind
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let tun_dev = TunDevice::new(
        &tun_name,
        tun_ip,
        netmask,
        1400,
        Arc::clone(&router),
        fake_pool.clone(),
        Arc::clone(&mux),
        upstream_dns,
    );

    tun_dev.run().await
        .with_context(|| format!("Failed to create TUN interface '{}'. Ensure you run with 'sudo' (Linux) or as administrator with wintun.dll next to the executable (Windows).", tun_name))?;

    // Step 2: Start Fake-IP DNS servers
    // Primary on 127.0.0.1:53 for reliable systemd-resolved Split-DNS over loopback (no firewalld/rp_filter drops)
    let loopback_dns_addr = "127.0.0.1:53".parse::<SocketAddr>().unwrap();
    let dns_server_loopback = DnsServer::new(loopback_dns_addr, upstream_dns, Arc::clone(&router), fake_pool.clone());
    tokio::spawn(async move {
        if let Err(e) = dns_server_loopback.run().await {
            tracing::warn!("Failed to bind loopback DNS server on {}: {:?}", loopback_dns_addr, e);
        }
    });

    // Also bind on TUN IP (100.64.0.1:53)
    let primary_dns_addr = SocketAddr::new(IpAddr::V4(tun_ip), 53);
    let dns_server_primary = DnsServer::new(primary_dns_addr, upstream_dns, Arc::clone(&router), fake_pool.clone());
    tokio::spawn(async move {
        let _ = dns_server_primary.run().await;
    });

    // Also run local DNS listener on 127.0.0.1:1053 for manual test queries
    let fallback_dns_addr = dns_addr;
    if fallback_dns_addr != primary_dns_addr && fallback_dns_addr != loopback_dns_addr {
        let dns_server_local = DnsServer::new(fallback_dns_addr, upstream_dns, Arc::clone(&router), fake_pool.clone());
        tokio::spawn(async move {
            let _ = dns_server_local.run().await;
        });
    }

    // Step 3: Apply system routing and Split-DNS in systemd-resolved
    let route_mgr = SystemRouteManager::new(&tun_name);
    let included_cidrs: Vec<_> = router
        .cidr_includes
        .iter()
        .copied()
        .filter(|inc| !router.cidr_excludes.iter().any(|exc| exc.contains(inc)))
        .collect();
    let _ = route_mgr.apply_routes(&included_cidrs);

    // Build the minimal set of routing domains for systemd-resolved
    let mut all_domains = BTreeSet::new();
    for fqdn in &router.fqdn_includes {
        let raw = match fqdn {
            open_cisco_zta::dataplane::router::DomainPattern::Exact(e) => e.as_str(),
            open_cisco_zta::dataplane::router::DomainPattern::Wildcard(w) => w.as_str(),
        };
        let clean = raw.trim_start_matches("*.").trim_end_matches('.').to_lowercase();
        if !clean.is_empty() && router.matches_domain(&clean) {
            all_domains.insert(clean);
        }
    }

    // Prune redundant subdomains so systemd-resolved routing table stays clean and fast
    let domain_list: Vec<String> = all_domains.into_iter().collect();
    let mut search_domains = Vec::new();
    for d in &domain_list {
        let is_subdomain = domain_list
            .iter()
            .any(|other| other != d && d.ends_with(&format!(".{}", other)));
        if !is_subdomain {
            search_domains.push(d.clone());
        }
    }

    // Point systemd-resolved to 127.0.0.1 for instant, reliable resolution over loopback.
    // Windows NRPT rules need a routable resolver address, so use the TUN IP there.
    #[cfg(target_os = "windows")]
    let split_dns_ip = tun_ip.to_string();
    #[cfg(not(target_os = "windows"))]
    let split_dns_ip = "127.0.0.1".to_string();
    let _ = route_mgr.configure_split_dns(&split_dns_ip, &search_domains);

    println!("Open Cisco ZTNA All-in-One is active!");
    println!("  - Interface : {} ({})", tun_name, tun_ip);
    println!("  - DNS       : {}:53 (UDP/TCP) -> Split-DNS for {:?}", tun_ip, search_domains);
    println!("  - SOCKS5h   : socks5h://{}", socks_addr);
    println!("Press Ctrl+C to stop.");
    wait_for_shutdown_signal().await?;

    println!("\nShutting down. Cleaning up network routes...");
    let _ = route_mgr.cleanup();
    println!("Done.");

    Ok(())
}

async fn cmd_enroll(
    mgr: &ConfigManager,
    token_arg: Option<String>,
    os_profile: OsProfile,
    allow_root: bool,
) -> Result<()> {
    open_cisco_zta::control::check_enroll_privileges(allow_root)?;

    use open_cisco_zta::config::EnrollmentState;
    use open_cisco_zta::control::browser::AutoCookieCapture;
    use open_cisco_zta::control::enroll::EnrollmentService;
    use open_cisco_zta::crypto::dpop::DpopSigner;
    use std::io::{self, Write};
    use std::process::Command;
    use uuid::Uuid;

    println!("================================================================================");
    println!("                     Open Cisco ZTNA Client Enrollment                         ");
    println!("================================================================================\n");

    let svc = EnrollmentService::new();
    let dpop = DpopSigner::new_random();

    println!("[1/4] Contacting Cisco Secure Access enrollment bootstrap endpoint...");
    let init = svc
        .bootstrap(&dpop)
        .await
        .context("Failed to initialize enrollment with Cisco Cloud")?;

    let sso_url = init
        .sso_begin_url
        .context("No SSO begin URL returned by Cisco")?;
    println!("\n[2/4] Browser Authentication Required");
    println!("--------------------------------------------------------------------------------");
    println!("Please authenticate with your corporate credentials at:");
    println!("\n  {}\n", sso_url);
    println!("--------------------------------------------------------------------------------");

    let raw_token = if let Some(tok) = token_arg {
        println!("Using SSO token provided via CLI flag.");
        tok
    } else if AutoCookieCapture::is_available() {
        println!("[*] Launching browser with automatic SSO token capture...");
        println!("[*] Complete your SSO login in the browser window that opens.\n");
        match AutoCookieCapture::capture(&sso_url).await {
            Ok(Some(tok)) => {
                println!("[+] Automatically captured 'elb-sso-jwt' from browser!");
                tok
            }
            _ => {
                println!("\nAutomatic capture could not detect cookie. Please paste token manually:");
                print!("Paste 'elb-sso-jwt' here: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                input.trim().to_string()
            }
        }
    } else {
        #[cfg(target_os = "windows")]
        let _ = Command::new("cmd").args(["/C", "start", "", &sso_url]).spawn();
        #[cfg(not(target_os = "windows"))]
        let _ = Command::new("xdg-open").arg(&sso_url).spawn();

        println!("Instructions:");
        println!("  1. Complete SSO login in your browser.");
        println!("  2. Once the page displays \"You've successfully logged in...\", open DevTools (F12).");
        println!("  3. Go to Application / Storage -> Cookies (for enroll-ui.ztna.sse.cisco.com).");
        println!("  4. Copy the value of cookie: 'elb-sso-jwt'");
        print!("\nPaste the 'elb-sso-jwt' token here: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    if raw_token.is_empty() {
        anyhow::bail!("SSO token cannot be empty!");
    }

    println!("\n[3/4] Decoding SSO Token and Registering Device...");
    let claims = EnrollmentService::parse_sso_jwt(&raw_token)?;
    let raw_sub = claims.sub.clone().unwrap_or_else(|| "default_org".to_string());
    let org_id = if let Some(stripped) = raw_sub.strip_prefix("org/") {
        stripped.split('/').next().unwrap_or(&raw_sub).to_string()
    } else {
        raw_sub
    };
    let username = claims.username.clone().unwrap_or_else(|| "user".to_string());
    let dev_reg_url = claims.dev_reg_url.clone().unwrap_or_else(|| {
        "https://devices.api.umbrella.com/deployments/v2/ztna".to_string()
    });
    let config_sync_url = claims.config_sync_url.clone().unwrap_or_else(|| {
        format!(
            "https://proxy-{}.zpc.sse.cisco.com/.well-known/zta-config/cisco/v2",
            org_id
        )
    });

    println!("  Organization ID : {}", org_id);
    println!("  User Email      : {}", username);
    println!("  Device Reg URL  : {}", dev_reg_url);
    println!("  Config Sync URL : {}", config_sync_url);
    println!("  OS Profile      : {}", os_profile);

    let client_gen_id = Uuid::new_v4().to_string();
    let (dr_jwt, dev_reg_device_id) = svc
        .register_device(&dev_reg_url, &raw_token, &dpop, &client_gen_id)
        .await
        .context("Failed to complete device registration with Cisco Umbrella API")?;
    println!("  Device Registration: OK");

    let (auth_jwt, device_id, user_id, duo_device_id, dha_base_url, san_map) =
        if let Some(ref dha_reg_url) = claims.dha_reg_url {
            println!("  DHA Registration URL : {}", dha_reg_url);
            let (dha_jwt, dha_claims) = svc
                .register_dha(dha_reg_url, &raw_token, &dr_jwt, &dpop, os_profile)
                .await
                .context("Failed to complete DHA posture registration with Cisco Cloud")?;

            let ztna_dev_id = dha_claims
                .ztna_device_id
                .clone()
                .unwrap_or_else(|| dev_reg_device_id.clone());
            let uid = dha_claims
                .user_id
                .clone()
                .or_else(|| claims.user_id.clone())
                .unwrap_or_else(|| username.clone());
            println!("  DHA Registration   : OK (ZTNA Device ID: {})", ztna_dev_id);

            let mut map = std::collections::HashMap::new();
            if !dha_claims.identifiers.is_empty() {
                for (k, v) in &dha_claims.identifiers {
                    map.insert(k.clone(), v.clone());
                }
            } else {
                map.insert("urn:cisco:sse:dhaid".to_string(), "nil".to_string());
                map.insert("urn:cisco:sse:orgid".to_string(), org_id.clone());
                map.insert("urn:cisco:sse:userid".to_string(), uid.clone());
                map.insert("urn:cisco:sse:username".to_string(), username.clone());
                map.insert("urn:cisco:sse:ztna:deviceid".to_string(), ztna_dev_id.clone());
                if let Some(orig) = dha_claims.origin_id.as_ref().or(claims.origin_id.as_ref()) {
                    map.insert("urn:cisco:sse:ztna:originid".to_string(), orig.clone());
                }
            }

            (
                dha_jwt,
                ztna_dev_id,
                uid,
                dha_claims.duo_device_id,
                dha_claims.dha_base_url,
                map,
            )
        } else {
            let uid = claims.user_id.clone().unwrap_or_else(|| username.clone());
            let mut map = std::collections::HashMap::new();
            map.insert("urn:cisco:sse:dhaid".to_string(), "nil".to_string());
            map.insert("urn:cisco:sse:orgid".to_string(), org_id.clone());
            map.insert("urn:cisco:sse:userid".to_string(), uid.clone());
            map.insert("urn:cisco:sse:username".to_string(), username.clone());
            map.insert(
                "urn:cisco:sse:ztna:deviceid".to_string(),
                dev_reg_device_id.clone(),
            );
            if let Some(ref orig) = claims.origin_id {
                map.insert("urn:cisco:sse:ztna:originid".to_string(), orig.clone());
            }
            for (k, v) in &claims.identifiers {
                map.entry(k.clone()).or_insert_with(|| v.clone());
            }
            (dr_jwt, dev_reg_device_id, uid, None, None, map)
        };

    let acme_dir_url = claims
        .acme_dir_url
        .as_deref()
        .unwrap_or("https://prod.acme.sse.cisco.com/acme/acme/directory");

    // Save enrollment.json
    let enrollment = EnrollmentState {
        org_id: org_id.clone(),
        duo_device_id,
        ztna_device_id: device_id.clone(),
        dha_base_url,
        user_id: user_id.clone(),
        label: Some(format!("SSE enrollment by user {}", username)),
        enrollment_type: Some("CiscoSecureAccess".to_string()),
        local_uid: None,
        enrollment_time: None,
        config_sync_url: config_sync_url.clone(),
        config_etag: None,
        config_hash: None,
        config_sync_interval: Some("10".to_string()),
        last_config_sync_success_time: None,
        choice_id: Some("cisco-secure-access/default".to_string()),
        certificate_expiration_time: None,
        certificate_state: Some("Ok".to_string()),
        client_cert_file: Some(mgr.cert_path().to_string_lossy().to_string()),
        client_key_file: Some(mgr.key_path().to_string_lossy().to_string()),
        acme_dir_url: Some(acme_dir_url.to_string()),
        client_cert_alias: None,
        os_profile: Some(os_profile.to_string()),
    };
    mgr.save_enrollment(&enrollment)?;
    println!("  Saved enrollment info to {:?}", mgr.enrollment_path());

    println!("\n[4/4] Setting up Client Credentials & Initial Sync...");

    svc.issue_certificate(
        acme_dir_url,
        &device_id,
        &san_map,
        &auth_jwt,
        &dpop,
        mgr.base_dir(),
    )
    .await
    .context("Failed to issue genuine client mTLS certificate via Cisco ACME")?;

    println!("\n[*] Performing initial configuration sync with Cisco Cloud...");
    if let Err(e) = cmd_sync(mgr).await {
        tracing::warn!("Initial configuration sync returned note: {:?}", e);
    }

    println!("\n================================================================================");
    println!("                      Enrollment Successfully Configured!                       ");
    println!("================================================================================");
    println!("Configuration directory: {:?}", mgr.base_dir());
    println!("You can now run:");
    #[cfg(target_os = "windows")]
    println!("  open-cisco-zta.exe run\n");
    #[cfg(not(target_os = "windows"))]
    println!("  sudo open-cisco-zta run\n");

    Ok(())
}
