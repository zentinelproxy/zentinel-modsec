//! Network operators (@ipMatch).

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// IP match operator (@ipMatch).
pub struct IpMatchOperator {
    networks: Vec<IpNetwork>,
}

impl IpMatchOperator {
    /// Create from space-separated IP/CIDR list.
    pub fn new(ips: &str) -> Result<Self> {
        let networks = ips
            .split_whitespace()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                // Handle bare IPs (add /32 or /128)
                if s.contains('/') {
                    s.parse::<IpNetwork>()
                } else {
                    // Try as IP address first
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        match ip {
                            IpAddr::V4(v4) => Ok(IpNetwork::V4(
                                ipnetwork::Ipv4Network::new(v4, 32).unwrap(),
                            )),
                            IpAddr::V6(v6) => Ok(IpNetwork::V6(
                                ipnetwork::Ipv6Network::new(v6, 128).unwrap(),
                            )),
                        }
                    } else {
                        s.parse::<IpNetwork>()
                    }
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::InvalidIp {
                value: ips.to_string(),
                message: e.to_string(),
            })?;

        Ok(Self { networks })
    }

    /// Create from a file containing IPs/CIDRs.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::RuleFileLoad {
            path: path.into(),
            source: e,
        })?;

        let networks = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| {
                if s.contains('/') {
                    s.parse::<IpNetwork>()
                } else {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        match ip {
                            IpAddr::V4(v4) => Ok(IpNetwork::V4(
                                ipnetwork::Ipv4Network::new(v4, 32).unwrap(),
                            )),
                            IpAddr::V6(v6) => Ok(IpNetwork::V6(
                                ipnetwork::Ipv6Network::new(v6, 128).unwrap(),
                            )),
                        }
                    } else {
                        s.parse::<IpNetwork>()
                    }
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::InvalidIp {
                value: path.to_string(),
                message: e.to_string(),
            })?;

        Ok(Self { networks })
    }

    /// Check if an IP is in any of the networks.
    fn contains(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(*ip))
    }
}

impl Operator for IpMatchOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(ip) = value.parse::<IpAddr>() {
            if self.contains(&ip) {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "ipMatch"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_match_single() {
        let op = IpMatchOperator::new("192.168.1.1").unwrap();
        assert!(op.execute("192.168.1.1").matched);
        assert!(!op.execute("192.168.1.2").matched);
    }

    #[test]
    fn test_ip_match_cidr() {
        let op = IpMatchOperator::new("192.168.1.0/24").unwrap();
        assert!(op.execute("192.168.1.1").matched);
        assert!(op.execute("192.168.1.255").matched);
        assert!(!op.execute("192.168.2.1").matched);
    }

    #[test]
    fn test_ip_match_multiple() {
        let op = IpMatchOperator::new("10.0.0.0/8 192.168.0.0/16").unwrap();
        assert!(op.execute("10.1.2.3").matched);
        assert!(op.execute("192.168.1.1").matched);
        assert!(!op.execute("172.16.0.1").matched);
    }
}
