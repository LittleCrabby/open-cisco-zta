use anyhow::Result;
use ipnet::IpNet;

pub struct SystemRouteManager {
    tun_dev: String,
}

impl SystemRouteManager {
    pub fn new(tun_dev: &str) -> Self {
        Self {
            tun_dev: tun_dev.to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn apply_routes(&self, cidrs: &[IpNet]) -> Result<()> {
        // Add interface to trusted zone in firewalld if firewalld is active
        let _ = self.run_cmd("firewall-cmd", &["--zone=trusted", "--add-interface", &self.tun_dev]);

        tracing::info!("Adding Fake-IP route 198.18.0.0/15 via {}", self.tun_dev);
        self.run_cmd("ip", &["route", "replace", "198.18.0.0/15", "dev", &self.tun_dev])?;

        for cidr in cidrs {
            let cidr_str = cidr.to_string();
            tracing::debug!("Adding corporate CIDR route {} via {}", cidr_str, self.tun_dev);
            let _ = self.run_cmd("ip", &["route", "replace", &cidr_str, "dev", &self.tun_dev]);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply_routes(&self, _cidrs: &[IpNet]) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn configure_split_dns(&self, dns_ip: &str, search_domains: &[String]) -> Result<()> {
        tracing::info!(
            "Configuring Split-DNS in systemd-resolved for {} -> DNS: {}",
            self.tun_dev,
            dns_ip
        );

        let _ = self.run_cmd("resolvectl", &["dns", &self.tun_dev, dns_ip]);

        if !search_domains.is_empty() {
            let mut domain_args = vec!["domain", &self.tun_dev];
            let domain_strings: Vec<String> = search_domains
                .iter()
                .map(|d| {
                    let clean = d.trim_start_matches("*.").trim();
                    format!("~{}", clean)
                })
                .collect();

            for d in &domain_strings {
                domain_args.push(d.as_str());
            }

            tracing::info!(
                "Setting search domains on {}: {:?}",
                self.tun_dev,
                domain_strings
            );
            let _ = self.run_cmd("resolvectl", &domain_args);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn configure_split_dns(&self, _dns_ip: &str, _search_domains: &[String]) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn cleanup(&self) -> Result<()> {
        tracing::info!("Cleaning up network interface {}", self.tun_dev);
        let _ = self.run_cmd("firewall-cmd", &["--zone=trusted", "--remove-interface", &self.tun_dev]);
        let _ = self.run_cmd("ip", &["link", "set", "dev", &self.tun_dev, "down"]);
        let _ = self.run_cmd("ip", &["link", "delete", &self.tun_dev]);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn run_cmd(&self, program: &str, args: &[&str]) -> Result<()> {
        use anyhow::Context;
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute command: {} {:?}", program, args))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "Command {} {:?} returned exit code {:?}: {}",
                program,
                args,
                output.status.code(),
                stderr.trim()
            );
        }
        Ok(())
    }
}
