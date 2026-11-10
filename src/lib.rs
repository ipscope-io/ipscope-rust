//! Official, memory-safe Sync (`IpScopeClient`) and Async (`AsyncIpScopeClient`) Rust Server-Side SDK
//! for the IPScope IP Intelligence Platform.
//!
//! > **Scope Notice:** Strictly limited to IP intelligence, network CIDR prefix,
//! > dataset metadata, feedback submission, and service status operations. Contains
//! > zero account, wallet, or billing operations.

#![forbid(unsafe_code)]

/// Compiles every README example as a doctest so published docs stay in sync with the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

pub mod cache;
pub mod client;
pub mod error;
pub mod transport;
pub mod types;
pub mod validation;

pub use client::{AsyncIpScopeClient, IpScopeClient, IpScopeClientBuilder};
pub use error::IpScopeError;
pub use transport::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES, SDK_USER_AGENT};
pub use types::{
    BatchLookupResponse, CacheOptions, CacheStats, CanonicalNetworkPrefixRecord, ConnectionBlock,
    DatasetSnapshotSummary, DatasetsMetadataResponse, FeedbackSubmissionInput,
    FeedbackSubmissionResponse, GeoBlock, IpLookupResponse, IpScopeResultWithMeta, NetworkBlock,
    NetworkPrefixLookupResponse, RateLimitMetadata, RequestOptions, RetryOptions, SecurityBlock,
    SecurityExtensionsBlock, ServiceSnapshotInfo, ServiceStatusResponse, FEEDBACK_ISSUE_TYPES,
    FEEDBACK_ROLES,
};
pub use validation::{
    validate_and_deduplicate_batch_ips, validate_api_key, validate_cidr_prefix,
    validate_ip_address, ValidatedBatch, ValidatedCidr, ValidatedIp, MAX_SINGLE_BATCH_SIZE,
};
