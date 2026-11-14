use crate::config::schema::ResourceConfig;
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    Exact(String),
    Wildcard(String), // e.g. "example.corp" for "*.example.corp"
}

impl DomainPattern {
    pub fn parse(pattern: &str) -> Self {
        let pattern = pattern.trim().to_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            DomainPattern::Wildcard(suffix.to_string())
        } else {
            DomainPattern::Exact(pattern)
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim().trim_end_matches('.').to_lowercase();
        match self {
            DomainPattern::Exact(exact) => domain == *exact,
            DomainPattern::Wildcard(suffix) => {
                if domain == *suffix {
                    true
                } else if domain.ends_with(suffix) {
                    let prefix_len = domain.len() - suffix.len();
                    prefix_len > 0 && domain.as_bytes()[prefix_len - 1] == b'.'
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteMatcher {
    pub cidr_includes: Vec<IpNet>,
    pub cidr_excludes: Vec<IpNet>,
    pub fqdn_includes: Vec<DomainPattern>,
    pub fqdn_excludes: Vec<DomainPattern>,
    live_override: Arc<RwLock<Option<Arc<RouteMatcher>>>>,
}

impl RouteMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_resource_configs(configs: &[ResourceConfig]) -> Self {
        let mut matcher = Self::new();
        for rc in configs {
            if let Some(ref cidr) = rc.cidr {
                for inc in &cidr.include {
                    if let Ok(net) = IpNet::from_str(inc.trim()) {
                        matcher.cidr_includes.push(net);
                    }
                }
                for exc in &cidr.exclude {
                    if let Ok(net) = IpNet::from_str(exc.trim()) {
                        matcher.cidr_excludes.push(net);
                    }
                }
            }
            if let Some(ref fqdn) = rc.fqdn {
                for inc in &fqdn.include {
                    matcher.fqdn_includes.push(DomainPattern::parse(inc));
                }
                for exc in &fqdn.exclude {
                    matcher.fqdn_excludes.push(DomainPattern::parse(exc));
                }
            }
        }
        matcher
    }

    /// Replaces the active routing rules atomically for all shared holders of this `RouteMatcher`.
    pub fn update_from_resource_configs(&self, configs: &[ResourceConfig]) {
        let new_matcher = Arc::new(Self::from_resource_configs(configs));
        if let Ok(mut guard) = self.live_override.write() {
            *guard = Some(new_matcher);
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.matches_ip(ip);
            }
        }
        for exc in &self.cidr_excludes {
            if exc.contains(&ip) {
                return false;
            }
        }
        for inc in &self.cidr_includes {
            if inc.contains(&ip) {
                return true;
            }
        }
        false
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.matches_domain(domain);
            }
        }
        for exc in &self.fqdn_excludes {
            if exc.matches(domain) {
                return false;
            }
        }
        for inc in &self.fqdn_includes {
            if inc.matches(domain) {
                return true;
            }
        }
        false
    }

    pub fn should_route(&self, host: &str, ip: Option<IpAddr>) -> bool {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.should_route(host, ip);
            }
        }
        let clean_host = host.split(':').next().unwrap_or(host);
        if let Ok(parsed_ip) = clean_host.parse::<IpAddr>() {
            return self.matches_ip(parsed_ip);
        }

        if self.matches_domain(clean_host) {
            return true;
        }

        if let Some(ip) = ip {
            return self.matches_ip(ip);
        }

        false
    }

    /// Returns included CIDRs not completely contained in any excluded CIDR.
    pub fn effective_included_cidrs(&self) -> Vec<IpNet> {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.effective_included_cidrs();
            }
        }
        self.cidr_includes
            .iter()
            .copied()
            .filter(|inc| !self.cidr_excludes.iter().any(|exc| exc.contains(inc)))
            .collect()
    }

    /// Returns sorted, deduplicated corporate search domains with redundant subdomains pruned.
    pub fn pruned_search_domains(&self) -> Vec<String> {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.pruned_search_domains();
            }
        }
        let mut all_domains = BTreeSet::new();
        for fqdn in &self.fqdn_includes {
            let raw = match fqdn {
                DomainPattern::Exact(e) => e.as_str(),
                DomainPattern::Wildcard(w) => w.as_str(),
            };
            let clean = raw.trim_start_matches("*.").trim_end_matches('.').to_lowercase();
            if !clean.is_empty() && self.matches_domain(&clean) {
                all_domains.insert(clean);
            }
        }

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
        search_domains
    }

    pub fn cidr_includes_count(&self) -> usize {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.cidr_includes_count();
            }
        }
        self.cidr_includes.len()
    }

    pub fn fqdn_includes_count(&self) -> usize {
        if let Ok(guard) = self.live_override.read() {
            if let Some(ref active) = *guard {
                return active.fqdn_includes_count();
            }
        }
        self.fqdn_includes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::*;

    #[test]
    fn test_domain_pattern() {
        let p_wildcard = DomainPattern::parse("*.example.corp");
        assert!(p_wildcard.matches("example.corp"));
        assert!(p_wildcard.matches("app.example.corp"));
        assert!(p_wildcard.matches("sub.app.example.corp"));
        assert!(!p_wildcard.matches("notexample.corp"));
        assert!(!p_wildcard.matches("other.corp"));

        let p_exact = DomainPattern::parse("git.example.corp");
        assert!(p_exact.matches("git.example.corp"));
        assert!(!p_exact.matches("sub.git.example.corp"));
        assert!(!p_exact.matches("example.corp"));
    }

    #[test]
    fn test_route_matcher() {
        let resource_configs = vec![ResourceConfig {
            id: "res-1".to_string(),
            label: Some("Corporate Rules".to_string()),
            cidr: Some(CidrFilter {
                include: vec![
                    "172.17.12.41/32".to_string(),
                    "10.10.89.0/24".to_string(),
                    "192.168.1.0/24".to_string(),
                ],
                exclude: vec!["10.10.89.100/32".to_string()],
            }),
            fqdn: Some(FqdnFilter {
                include: vec![
                    "git.example.corp".to_string(),
                    "*.internal.example.corp".to_string(),
                ],
                exclude: vec!["*.sse.cisco.com".to_string()],
            }),
        }];

        let matcher = RouteMatcher::from_resource_configs(&resource_configs);

        // Domain matching
        assert!(matcher.matches_domain("git.example.corp"), "git.example.corp must match");
        assert!(matcher.matches_domain("consul.test.platform.internal.example.corp"), "*.internal.example.corp wildcard must match");
        assert!(!matcher.matches_domain("proxy-1234567.zpc.sse.cisco.com"), "*.sse.cisco.com must be excluded");
        assert!(!matcher.matches_domain("google.com"), "google.com must not match");

        // CIDR matching
        assert!(matcher.matches_ip("172.17.12.41".parse().unwrap()), "172.17.12.41/32 must match");
        assert!(matcher.matches_ip("10.10.89.5".parse().unwrap()), "10.10.89.0/24 must match");
        assert!(!matcher.matches_ip("10.10.89.100".parse().unwrap()), "10.10.89.100 excluded must not match");
        assert!(!matcher.matches_ip("8.8.8.8".parse().unwrap()), "8.8.8.8 must not match");

        assert_eq!(matcher.cidr_includes_count(), 3);
        assert_eq!(matcher.fqdn_includes_count(), 2);
    }

    #[test]
    fn test_route_matcher_live_update() {
        let initial_configs = vec![ResourceConfig {
            id: "res-1".to_string(),
            label: None,
            cidr: Some(CidrFilter {
                include: vec!["10.0.0.0/8".to_string()],
                exclude: vec![],
            }),
            fqdn: Some(FqdnFilter {
                include: vec!["*.old.corp".to_string()],
                exclude: vec![],
            }),
        }];

        let matcher = Arc::new(RouteMatcher::from_resource_configs(&initial_configs));
        let matcher_ref = Arc::clone(&matcher);

        assert!(matcher_ref.matches_domain("app.old.corp"));
        assert!(!matcher_ref.matches_domain("db.new.corp"));
        assert!(matcher_ref.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(!matcher_ref.matches_ip("172.16.0.5".parse().unwrap()));

        let updated_configs = vec![ResourceConfig {
            id: "res-2".to_string(),
            label: None,
            cidr: Some(CidrFilter {
                include: vec!["172.16.0.0/16".to_string(), "192.168.10.0/24".to_string()],
                exclude: vec!["192.168.10.0/24".to_string()],
            }),
            fqdn: Some(FqdnFilter {
                include: vec![
                    "*.new.corp".to_string(),
                    "sub.new.corp".to_string(),
                    "portal.extra.corp".to_string(),
                ],
                exclude: vec![],
            }),
        }];

        matcher.update_from_resource_configs(&updated_configs);

        assert!(!matcher_ref.matches_domain("app.old.corp"));
        assert!(matcher_ref.matches_domain("db.new.corp"));
        assert!(!matcher_ref.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(matcher_ref.matches_ip("172.16.0.5".parse().unwrap()));
        assert!(!matcher_ref.matches_ip("192.168.10.5".parse().unwrap()));
        assert_eq!(matcher_ref.cidr_includes_count(), 2);
        assert_eq!(matcher_ref.fqdn_includes_count(), 3);

        let effective = matcher_ref.effective_included_cidrs();
        assert_eq!(effective, vec!["172.16.0.0/16".parse::<IpNet>().unwrap()]);

        let pruned = matcher_ref.pruned_search_domains();
        assert_eq!(pruned, vec!["new.corp".to_string(), "portal.extra.corp".to_string()]);
    }
}
