//! Typed error hierarchy for the IPScope Rust Server-Side SDK.

use crate::types::RateLimitMetadata;
use std::fmt;
use std::time::Duration;

/// All errors returned by [`crate::IpScopeClient`] and [`crate::AsyncIpScopeClient`].
#[derive(Debug, Clone)]
pub enum IpScopeError {
    /// Client-side input validation failed before any HTTP request was made.
    Validation {
        field: &'static str,
        message: String,
    },
    /// The HTTP request exceeded the configured timeout.
    Timeout { path: String, timeout: Duration },
    /// HTTP 401 Unauthorized or 403 Forbidden.
    Authentication {
        status: u16,
        path: String,
        code: String,
        message: String,
        rate_limit: Option<RateLimitMetadata>,
    },
    /// HTTP 429 Too Many Requests after retries were exhausted or disabled.
    RateLimit {
        path: String,
        message: String,
        retry_after: Option<Duration>,
        rate_limit: Option<RateLimitMetadata>,
    },
    /// Non-2xx HTTP status or oversized payload (> 2 MiB safety guard).
    Api {
        status: u16,
        path: String,
        code: String,
        message: String,
        rate_limit: Option<RateLimitMetadata>,
    },
    /// Low-level network or JSON serialization/deserialization error.
    Network { path: String, message: String },
}

impl IpScopeError {
    pub fn code(&self) -> &str {
        match self {
            Self::Validation { .. } => "IPSCOPE_VALIDATION_ERROR",
            Self::Timeout { .. } => "IPSCOPE_TIMEOUT_ERROR",
            Self::Authentication { code, .. } => code.as_str(),
            Self::RateLimit { .. } => "IPSCOPE_RATE_LIMITED",
            Self::Api { code, .. } => code.as_str(),
            Self::Network { .. } => "IPSCOPE_NETWORK_ERROR",
        }
    }

    pub fn is_validation(&self) -> bool {
        matches!(self, Self::Validation { .. })
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Authentication { .. })
    }

    pub fn is_rate_limit(&self) -> bool {
        matches!(self, Self::RateLimit { .. })
    }
}

impl fmt::Display for IpScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { field, message } => {
                write!(f, "ipscope validation error ({field}): {message}")
            }
            Self::Timeout { path, timeout } => {
                write!(
                    f,
                    "ipscope request to \"{path}\" timed out after {}ms",
                    timeout.as_millis()
                )
            }
            Self::Authentication {
                status,
                path,
                code,
                message,
                ..
            } => {
                write!(
                    f,
                    "ipscope authentication error ({status} {code}) on {path}: {message}"
                )
            }
            Self::RateLimit { path, message, .. } => {
                write!(f, "ipscope rate limit error (429) on {path}: {message}")
            }
            Self::Api {
                status,
                path,
                code,
                message,
                ..
            } => {
                write!(
                    f,
                    "ipscope api error ({status} {code}) on {path}: {message}"
                )
            }
            Self::Network { path, message } => {
                write!(f, "ipscope network error on {path}: {message}")
            }
        }
    }
}

impl std::error::Error for IpScopeError {}
