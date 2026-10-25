//! Zero-DNS client-side IPv4/IPv6, CIDR prefix, and API key validation utilities.

use crate::error::IpScopeError;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Maximum number of IPs allowed in a single `POST /v1/ip/batch` request.
pub const MAX_SINGLE_BATCH_SIZE: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedIp {
    pub canonical_ip: String,
    pub family: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCidr {
    pub address: String,
    pub prefix_length: u8,
    pub family: u8,
    pub canonical_cidr: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBatch {
    pub ordered_ips: Vec<String>,
    pub unique_ips: Vec<String>,
}

/// Validates and trims an IPScope API key, rejecting empty strings and control characters.
pub fn validate_api_key(raw_api_key: &str) -> Result<String, IpScopeError> {
    let trimmed = raw_api_key.trim();
    if trimmed.is_empty() {
        return Err(IpScopeError::Validation {
            field: "api_key",
            message: "API key cannot be empty".to_string(),
        });
    }
    if trimmed.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        return Err(IpScopeError::Validation {
            field: "api_key",
            message: "API key contains invalid control characters".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Validates an IPv4 or IPv6 literal using `std::net::IpAddr` (zero DNS resolution)
/// and returns its canonical lowercase string and family (`4` or `6`).
pub fn validate_ip_address(raw_ip: &str) -> Result<ValidatedIp, IpScopeError> {
    let trimmed = raw_ip.trim();
    if trimmed.is_empty() || trimmed.contains('%') || trimmed.contains('/') {
        return Err(IpScopeError::Validation {
            field: "ip",
            message: format!("Invalid IPv4 or IPv6 address: \"{trimmed}\""),
        });
    }

    let addr = IpAddr::from_str(trimmed).map_err(|_| IpScopeError::Validation {
        field: "ip",
        message: format!("Invalid IPv4 or IPv6 address: \"{trimmed}\""),
    })?;

    let family = match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    };

    Ok(ValidatedIp {
        canonical_ip: addr.to_string().to_lowercase(),
        family,
    })
}

/// Validates a CIDR prefix (`<ip>/<prefixLength>`), masks host bits to the canonical
/// network address, and returns [`ValidatedCidr`].
pub fn validate_cidr_prefix(raw_cidr: &str) -> Result<ValidatedCidr, IpScopeError> {
    let trimmed = raw_cidr.trim();
    let mut parts = trimmed.split('/');
    let Some(addr_part) = parts.next() else {
        return Err(IpScopeError::Validation {
            field: "cidr",
            message: format!("Invalid CIDR notation \"{trimmed}\""),
        });
    };
    let Some(len_part) = parts.next() else {
        return Err(IpScopeError::Validation {
            field: "cidr",
            message: format!(
                "Invalid CIDR notation \"{trimmed}\". Expected \"<ip>/<prefixLength>\" (e.g. \"1.1.1.0/24\")"
            ),
        });
    };
    if parts.next().is_some() {
        return Err(IpScopeError::Validation {
            field: "cidr",
            message: format!("Invalid CIDR notation \"{trimmed}\""),
        });
    }

    let addr = IpAddr::from_str(addr_part.trim()).map_err(|_| IpScopeError::Validation {
        field: "cidr",
        message: format!("Invalid IP address in CIDR \"{trimmed}\""),
    })?;

    let prefix_len: u8 = len_part
        .trim()
        .parse()
        .map_err(|_| IpScopeError::Validation {
            field: "cidr",
            message: format!("Invalid prefix length \"{len_part}\" in CIDR \"{trimmed}\""),
        })?;

    match addr {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return Err(IpScopeError::Validation {
                    field: "cidr",
                    message: format!(
                        "Prefix length {prefix_len} out of range [0..32] for IPv4 CIDR \"{trimmed}\""
                    ),
                });
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            let masked = Ipv4Addr::from(u32::from(v4) & mask);
            let addr_str = masked.to_string();
            Ok(ValidatedCidr {
                canonical_cidr: format!("{addr_str}/{prefix_len}"),
                address: addr_str,
                prefix_length: prefix_len,
                family: 4,
            })
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return Err(IpScopeError::Validation {
                    field: "cidr",
                    message: format!(
                        "Prefix length {prefix_len} out of range [0..128] for IPv6 CIDR \"{trimmed}\""
                    ),
                });
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            let masked = Ipv6Addr::from(u128::from(v6) & mask);
            let addr_str = masked.to_string().to_lowercase();
            Ok(ValidatedCidr {
                canonical_cidr: format!("{addr_str}/{prefix_len}"),
                address: addr_str,
                prefix_length: prefix_len,
                family: 6,
            })
        }
    }
}

/// Validates a slice of `1..=max_batch_size` IPs and returns both the ordered normalized IPs
/// and the deduplicated unique IPs.
pub fn validate_and_deduplicate_batch_ips<S: AsRef<str>>(
    raw_ips: &[S],
    max_batch_size: usize,
) -> Result<ValidatedBatch, IpScopeError> {
    if raw_ips.is_empty() {
        return Err(IpScopeError::Validation {
            field: "ips",
            message: "Batch IPs slice must contain at least 1 IP address".to_string(),
        });
    }
    if max_batch_size > 0 && raw_ips.len() > max_batch_size {
        return Err(IpScopeError::Validation {
            field: "ips",
            message: format!(
                "Batch IPs length ({}) exceeds maximum single-request batch size ({max_batch_size}). Use lookup_batch_chunked() or lookup_batch_stream() for larger lists.",
                raw_ips.len()
            ),
        });
    }

    let mut ordered = Vec::with_capacity(raw_ips.len());
    let mut seen = HashSet::with_capacity(raw_ips.len());
    let mut unique = Vec::with_capacity(raw_ips.len());

    for raw in raw_ips {
        let v = validate_ip_address(raw.as_ref())?;
        if seen.insert(v.canonical_ip.clone()) {
            unique.push(v.canonical_ip.clone());
        }
        ordered.push(v.canonical_ip);
    }

    Ok(ValidatedBatch {
        ordered_ips: ordered,
        unique_ips: unique,
    })
}
