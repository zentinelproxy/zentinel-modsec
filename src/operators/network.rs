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
    /// Create from a comma- and/or whitespace-separated IP/CIDR list.
    pub fn new(ips: &str) -> Result<Self> {
        let networks = ips
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Self::parse_network)
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
            .map(Self::parse_network)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::InvalidIp {
                value: path.to_string(),
                message: e.to_string(),
            })?;

        Ok(Self { networks })
    }

    fn parse_network(value: &str) -> std::result::Result<IpNetwork, ipnetwork::IpNetworkError> {
        let net = value.parse::<IpNetwork>()?;
        // Mask first: prefixes shorter than /96 do not retain the mapped IPv4 prefix.
        match (net, net.network().to_canonical()) {
            (IpNetwork::V6(v6), IpAddr::V4(ip)) => IpNetwork::new(IpAddr::V4(ip), v6.prefix() - 96),
            _ => Ok(net),
        }
    }

    /// Check if an IP is in any of the networks.
    fn contains(&self, ip: &IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.networks.iter().any(|net| net.contains(ip))
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
    fn mapped_addresses_use_the_network_number_after_masking() {
        let addrs = ["192.0.2.8", "::ffff:c000:208", "::fffe:c000:208", "::1"];
        for (prefix, expected) in [
            ("192.0.2.8", [true, true, false, false]),
            ("::ffff:192.0.2.8/120", [true, true, false, false]),
            ("::ffff:192.0.2.8/96", [true, true, false, false]),
            ("::ffff:192.0.2.8/95", [false, false, true, false]),
            ("::/0", [false, false, true, true]),
        ] {
            let op = IpMatchOperator::new(prefix).unwrap();
            assert_eq!(addrs.map(|ip| op.execute(ip).matched), expected, "{prefix}");
        }
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

    #[test]
    fn test_ip_match_comma_separated() {
        // CRS REQUEST-905 uses the comma-separated form, e.g. "127.0.0.1,::1".
        let op = IpMatchOperator::new("127.0.0.1,::1").unwrap();
        assert!(op.execute("127.0.0.1").matched);
        assert!(op.execute("::1").matched);
        assert!(!op.execute("10.0.0.1").matched);
    }

    #[test]
    fn test_ip_match_comma_and_space_mixed() {
        let op = IpMatchOperator::new("10.0.0.0/8, 192.168.0.0/16").unwrap();
        assert!(op.execute("10.1.2.3").matched);
        assert!(op.execute("192.168.1.1").matched);
    }
}
