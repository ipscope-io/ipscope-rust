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
    pub abuse_velocity_score: Option<f64>,
    pub is_known_scanner: Option<bool>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalNetworkPrefixRecord {
    pub prefix: String,
    pub family: u8,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    #[serde(alias = "countryCode")]
    pub country_code: Option<String>,
    pub city: Option<String>,
    #[serde(alias = "locationType")]
    pub location_type: Option<String>,
    #[serde(alias = "isVpn")]
    pub is_vpn: Option<bool>,
    #[serde(alias = "isHosting")]
    pub is_hosting: Option<bool>,
    #[serde(alias = "isTorExit")]
    pub is_tor_exit: Option<bool>,
    #[serde(alias = "isProxy")]
    pub is_proxy: Option<bool>,
    #[serde(alias = "anonymizerType")]
    pub anonymizer_type: Option<String>,
}

/// Network CIDR prefix lookup response (`GET /v1/networks/:prefix/:length`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPrefixLookupResponse {
    pub queried_cidr: String,
    pub family: u8,
    pub dataset_version: String,
    pub record: Option<CanonicalNetworkPrefixRecord>,
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

/// Input payload for submitting IP/prefix correction feedback (`POST /v1/feedback`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSubmissionInput {
    pub prefix_or_ip: String,
    pub role: String,
    pub issue_type: String,
    pub requested_correction: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_urls: Option<Vec<String>>,
}

/// Response returned when submitting IP/prefix correction feedback (`POST /v1/feedback`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSubmissionResponse {
    pub id: String,
    pub prefix_or_ip: String,
    pub role: String,
    pub issue_type: String,
    pub requested_correction: HashMap<String, serde_json::Value>,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    pub status: String,
    #[serde(default)]
    pub evidence_urls: Option<Vec<String>>,
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

/// Parsed user-scoped rate-limit headers returned by `@ipscope/api`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RateLimitMetadata {
    pub limit_per_minute: Option<u32>,
    pub remaining: Option<u32>,
    pub reset_epoch_seconds: Option<u64>,
    pub scope: Option<String>,
    pub burst_capacity: Option<u32>,
    pub rate_limit_rps: Option<u32>,
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
