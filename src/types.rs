//! Typed models for the IPScope Rust Server-Side SDK.
//!
//! Strictly limited to IP intelligence, network CIDR prefix, dataset metadata,
//! feedback submission, and service status operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Geographic classification and confidence returned in [`IpLookupResponse::geo`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GeoBlock {
    pub country_code: Option<String>,
    #[serde(default)]
    pub subdivision: Option<String>,
    pub city: Option<String>,
    /// Postal / ZIP code when available in the city dataset.
    #[serde(default)]
    pub postal_code: Option<String>,
    /// Representative coordinate latitude (never device GPS).
    #[serde(default)]
    pub latitude: Option<f64>,
    /// Representative coordinate longitude (never device GPS).
    #[serde(default)]
    pub longitude: Option<f64>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default = "default_unknown_string")]
    pub location_type: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub accuracy_radius_km: Option<f64>,
    #[serde(default)]
    pub declared_country_code: Option<String>,
    #[serde(default)]
    pub physical_country_code: Option<String>,
    #[serde(default)]
    pub is_virtual_location: Option<bool>,
}

/// Autonomous System and network operator details returned in [`IpLookupResponse::network`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBlock {
    pub asn: Option<u32>,
    pub organization: Option<String>,
}

/// Security, hosting, and anonymity classification returned in [`IpLookupResponse::security`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityBlock {
    pub is_vpn: Option<bool>,
    pub is_hosting: Option<bool>,
    pub is_tor_exit: Option<bool>,
    pub is_proxy: Option<bool>,
    /// `true` for a published consumer privacy-relay egress (e.g. Apple iCloud Private Relay).
    /// Relay users are not reported as VPN, proxy or hosting. `None` when unknown.
    #[serde(default)]
    pub is_relay: Option<bool>,
    #[serde(default = "default_unknown_string")]
    pub anonymizer_type: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

/// Optional connection context block returned when licensed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionBlock {
    #[serde(default = "default_unknown_string")]
    pub connection_type: String,
    pub is_residential: Option<bool>,
    pub is_mobile: Option<bool>,
    pub is_business: Option<bool>,
    pub is_hosting: Option<bool>,
}

/// Optional security extensions telemetry block returned when licensed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityExtensionsBlock {
    /// Abuse reputation / velocity score on a `0..=100` scale (integer on the wire), or `None`.
    ///
    /// Typed as `f64` so older fractional (`0.0..=1.0`) payloads still parse.
    #[serde(default)]
    pub abuse_velocity_score: Option<f64>,
    #[serde(default)]
    pub is_known_scanner: Option<bool>,
    #[serde(default)]
    pub observation_recency_hours: Option<f64>,
}

/// Canonical single IP lookup response (`GET /v1/ip/:ip` and `GET /v1/ip/me`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpLookupResponse {
    pub ip: String,
    pub ip_version: u8,
    pub matched_network: Option<String>,
    pub geo: GeoBlock,
    pub network: NetworkBlock,
    pub security: SecurityBlock,
    #[serde(default)]
    pub connection: Option<ConnectionBlock>,
    #[serde(default)]
    pub security_extensions: Option<SecurityExtensionsBlock>,
    pub dataset_version: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Batch IP lookup response (`POST /v1/ip/batch`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchLookupResponse {
    #[serde(default)]
    pub dataset_version: String,
    pub count: usize,
    pub results: Vec<IpLookupResponse>,
}

/// Canonical network prefix record returned in `GET /v1/networks/:prefix/:length`.
///
/// The API serializes this record in camelCase (`countryCode`, `isVpn`, ...); both camelCase
/// and snake_case keys are accepted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalNetworkPrefixRecord {
    pub prefix: String,
    #[serde(default)]
    pub family: u8,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default, alias = "countryCode")]
    pub country_code: Option<String>,
    #[serde(default)]
    pub subdivision: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default, alias = "postalCode")]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub latitude: Option<f64>,
    #[serde(default)]
    pub longitude: Option<f64>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default, alias = "locationType")]
    pub location_type: Option<String>,
    #[serde(default, alias = "geoConfidence")]
    pub geo_confidence: Option<f64>,
    #[serde(default, alias = "accuracyRadiusKm")]
    pub accuracy_radius_km: Option<f64>,
    #[serde(default, alias = "isVirtualLocation")]
    pub is_virtual_location: Option<bool>,
    #[serde(default, alias = "connectionType")]
    pub connection_type: Option<String>,
    #[serde(default, alias = "isVpn")]
    pub is_vpn: Option<bool>,
    #[serde(default, alias = "isHosting")]
    pub is_hosting: Option<bool>,
    #[serde(default, alias = "isTorExit")]
    pub is_tor_exit: Option<bool>,
    #[serde(default, alias = "isProxy")]
    pub is_proxy: Option<bool>,
    #[serde(default, alias = "isRelay")]
    pub is_relay: Option<bool>,
    #[serde(default, alias = "anonymizerType")]
    pub anonymizer_type: Option<String>,
    #[serde(default, alias = "securityConfidence")]
    pub security_confidence: Option<f64>,
    /// Abuse velocity score on a `0..=100` scale, or `None`.
    #[serde(default, alias = "abuseVelocityScore")]
    pub abuse_velocity_score: Option<f64>,
    #[serde(default, alias = "isKnownScanner")]
    pub is_known_scanner: Option<bool>,
    #[serde(default, alias = "reasonCodes")]
    pub reason_codes: Vec<String>,
    #[serde(default, alias = "updatedAt")]
    pub updated_at: Option<String>,
}

/// Network CIDR prefix lookup response (`GET /v1/networks/:prefix/:length`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkPrefixLookupResponse {
    pub queried_cidr: String,
    /// Most-specific matched CIDR prefix in the active snapshot.
    #[serde(default)]
    pub matched_network: Option<String>,
    pub family: u8,
    /// Prefix length of [`Self::matched_network`].
    #[serde(default)]
    pub bgp_prefix_length: Option<u8>,
    pub dataset_version: String,
    #[serde(default)]
    pub record: Option<CanonicalNetworkPrefixRecord>,
    /// Full IP lookup response for the prefix's base address.
    #[serde(default)]
    pub lookup: Option<IpLookupResponse>,
}

/// Dataset snapshot summary entry returned in `GET /v1/metadata/datasets`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetSnapshotSummary {
    pub snapshot_version: String,
    pub digest: String,
    pub ruleset_version: String,
    pub published_at: String,
    pub ipv4_prefix_count: u64,
    pub ipv6_prefix_count: u64,
}

/// Datasets metadata response (`GET /v1/metadata/datasets`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetsMetadataResponse {
    pub active_version: String,
    pub previous_version: Option<String>,
    #[serde(default)]
    pub snapshots: Vec<DatasetSnapshotSummary>,
}

/// Reporter roles accepted by `POST /v1/feedback` (`role`).
pub const FEEDBACK_ROLES: [&str; 3] = ["network_owner", "user", "researcher"];

/// Issue classifications accepted by `POST /v1/feedback` (`issue_type`).
pub const FEEDBACK_ISSUE_TYPES: [&str; 7] = [
    "wrong_country",
    "wrong_city",
    "false_positive_vpn",
    "false_positive_hosting",
    "false_positive_tor",
    "virtual_location_mismatch",
    "other",
];

/// Input payload for submitting IP/prefix correction feedback (`POST /v1/feedback`).
///
/// `role` must be one of [`FEEDBACK_ROLES`] and `issue_type` one of [`FEEDBACK_ISSUE_TYPES`].
/// Prefer [`FeedbackSubmissionInput::new`] plus the `with_*` helpers, or struct-update syntax
/// with `..Default::default()`, so future optional fields do not break your code.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSubmissionInput {
    pub prefix_or_ip: String,
    pub role: String,
    pub issue_type: String,
    pub requested_correction: HashMap<String, serde_json::Value>,
    /// Public URL to Geofeed / RDAP / traceroute evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,
    /// Whether the reporter consents to follow-up contact (server default `false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_consent: Option<bool>,
    /// Contact email for follow-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// Deprecated: the API accepts a single `evidence_url`. When `evidence_url` is `None`,
    /// the first entry here is sent as `evidence_url`; the list itself is never sent.
    #[deprecated(
        since = "1.1.0",
        note = "use `evidence_url`; the API accepts a single URL"
    )]
    #[serde(skip)]
    pub evidence_urls: Option<Vec<String>>,
}

impl FeedbackSubmissionInput {
    /// Creates a feedback payload with the four required fields.
    pub fn new(
        prefix_or_ip: impl Into<String>,
        role: impl Into<String>,
        issue_type: impl Into<String>,
        requested_correction: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            prefix_or_ip: prefix_or_ip.into(),
            role: role.into(),
            issue_type: issue_type.into(),
            requested_correction,
            ..Default::default()
        }
    }

    /// Sets the public evidence URL (Geofeed / RDAP / traceroute).
    pub fn with_evidence_url(mut self, url: impl Into<String>) -> Self {
        self.evidence_url = Some(url.into());
        self
    }

    /// Sets the follow-up contact email and consent flag.
    pub fn with_contact(mut self, email: impl Into<String>, consent: bool) -> Self {
        self.contact_email = Some(email.into());
        self.contact_consent = Some(consent);
        self
    }

    /// Returns the evidence URL that will be sent: `evidence_url`, else the first deprecated
    /// `evidence_urls` entry.
    #[allow(deprecated)]
    pub fn effective_evidence_url(&self) -> Option<String> {
        self.evidence_url.clone().or_else(|| {
            self.evidence_urls
                .as_ref()
                .and_then(|urls| urls.iter().find(|u| !u.trim().is_empty()).cloned())
        })
    }
}

/// Response returned when submitting IP/prefix correction feedback (`POST /v1/feedback`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSubmissionResponse {
    pub id: String,
    pub prefix_or_ip: String,
    pub role: String,
    pub issue_type: String,
    #[serde(default)]
    pub requested_correction: HashMap<String, serde_json::Value>,
    /// Accepts both `createdAt` (current API) and `created_at`.
    #[serde(default, alias = "createdAt")]
    pub created_at: String,
    pub status: String,
    #[serde(default)]
    pub evidence_urls: Option<Vec<String>>,
    #[serde(default)]
    pub evidence_url: Option<String>,
    #[serde(default)]
    pub contact_consent: Option<bool>,
    #[serde(default)]
    pub contact_email: Option<String>,
}

/// Snapshot version block nested inside `GET /v1/status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSnapshotInfo {
    #[serde(rename = "currentVersion")]
    pub current_version: Option<String>,
    #[serde(rename = "previousVersion")]
    pub previous_version: Option<String>,
}

/// Public service health and active snapshot status (`GET /v1/status`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatusResponse {
    pub status: String,
    #[serde(default)]
    pub snapshot: Option<ServiceSnapshotInfo>,
}

impl ServiceStatusResponse {
    pub fn current_version(&self) -> Option<&str> {
        self.snapshot
            .as_ref()
            .and_then(|s| s.current_version.as_deref())
    }

    pub fn previous_version(&self) -> Option<&str> {
        self.snapshot
            .as_ref()
            .and_then(|s| s.previous_version.as_deref())
    }
}

/// Parsed user-scoped rate-limit headers (`X-RateLimit-Limit`, `-Remaining`, `-Reset`, `-Scope`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RateLimitMetadata {
    /// `X-RateLimit-Limit`: requests allowed per window (per minute).
    pub limit_per_minute: Option<u32>,
    /// `X-RateLimit-Remaining`: requests left in the current window.
    pub remaining: Option<u32>,
    /// `X-RateLimit-Reset`: seconds until the current window resets (relative, not an epoch).
    pub reset_after_seconds: Option<u64>,
    /// Deprecated alias of [`Self::reset_after_seconds`]; holds the same relative seconds value.
    /// It was never a Unix epoch.
    #[deprecated(
        since = "1.1.0",
        note = "X-RateLimit-Reset is seconds until reset, not an epoch; use `reset_after_seconds`"
    )]
    pub reset_epoch_seconds: Option<u64>,
    /// `X-RateLimit-Scope`: currently always `user`.
    pub scope: Option<String>,
    /// Deprecated: the API sends no burst header; always `None`.
    #[deprecated(
        since = "1.1.0",
        note = "the API does not send a burst header; always None"
    )]
    pub burst_capacity: Option<u32>,
    /// Deprecated: the API sends no RPS header; always `None`.
    #[deprecated(
        since = "1.1.0",
        note = "the API does not send an RPS header; always None"
    )]
    pub rate_limit_rps: Option<u32>,
}

impl RateLimitMetadata {
    /// Builds metadata from the four headers the API sends.
    #[allow(deprecated)]
    pub fn new(
        limit_per_minute: Option<u32>,
        remaining: Option<u32>,
        reset_after_seconds: Option<u64>,
        scope: Option<String>,
    ) -> Self {
        Self {
            limit_per_minute,
            remaining,
            reset_after_seconds,
            reset_epoch_seconds: reset_after_seconds,
            scope,
            burst_capacity: None,
            rate_limit_rps: None,
        }
    }
}

/// Envelope containing both the typed API response data and HTTP/rate-limit metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct IpScopeResultWithMeta<T> {
    pub data: T,
    pub status: u16,
    pub rate_limit: RateLimitMetadata,
    pub from_cache: bool,
}

/// Telemetry for the in-memory O(1) LRU + TTL cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub enabled: bool,
    pub size: usize,
    pub max_entries: usize,
    pub ttl: Duration,
    pub hits: u64,
    pub misses: u64,
    pub coalesced_in_flight_hits: u64,
}

/// Retry policy configuration for transient network, 5xx, and 429 errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryOptions {
    pub max_retries: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub retry_on_rate_limit: bool,
}

impl Default for RetryOptions {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay: Duration::from_millis(150),
            max_delay: Duration::from_secs(3),
            retry_on_rate_limit: true,
        }
    }
}

/// In-memory O(1) LRU + TTL cache configuration (`< 400 KB` default RAM ceiling).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheOptions {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl: Duration,
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 512,
            ttl: Duration::from_secs(60),
        }
    }
}

/// Per-request options for cache bypass and custom headers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestOptions {
    pub bypass_cache: bool,
    pub headers: HashMap<String, String>,
}

impl RequestOptions {
    pub fn with_bypass_cache() -> Self {
        Self {
            bypass_cache: true,
            headers: HashMap::new(),
        }
    }
}

fn default_unknown_string() -> String {
    "unknown".to_string()
}
