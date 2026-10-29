use crate::config::schema::ResourceConfig;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

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

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
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

    pub fn cidr_includes_count(&self) -> usize {
        self.cidr_includes.len()
    }

    pub fn fqdn_includes_count(&self) -> usize {
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
}
