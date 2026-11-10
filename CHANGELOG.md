# Changelog

All notable changes to the `ipscope` crate are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-10

### Added
- `GeoBlock`: `latitude`, `longitude`, `postal_code`.
- `SecurityBlock`: `is_relay` (consumer privacy relays such as iCloud Private Relay; not reported as VPN/proxy/hosting).
- `NetworkPrefixLookupResponse`: `matched_network`, `bgp_prefix_length`, `lookup` (full `IpLookupResponse` for the prefix base address).
- `CanonicalNetworkPrefixRecord`: `subdivision`, `postal_code`, `latitude`, `longitude`, `timezone`, `geo_confidence`,
  `accuracy_radius_km`, `is_virtual_location`, `connection_type`, `is_relay`, `security_confidence`,
  `abuse_velocity_score`, `is_known_scanner`, `reason_codes`, `updated_at` (camelCase and snake_case keys accepted).
- `FeedbackSubmissionInput`: `evidence_url`, `contact_consent`, `contact_email`, plus `new()`, `with_evidence_url()`,
  `with_contact()` and `Default`.
- `FeedbackSubmissionResponse`: `evidence_url`, `contact_consent`, `contact_email`.
- `FEEDBACK_ROLES` and `FEEDBACK_ISSUE_TYPES` constants listing the values the API accepts.
- `RateLimitMetadata::reset_after_seconds` and `RateLimitMetadata::new()`.
- README examples are compiled as doctests (`cargo test --doc`, also in CI).

### Fixed
- Feedback evidence was sent as `evidence_urls` (array), which the API silently dropped. The SDK now sends
  `evidence_url` (single string).
- `X-RateLimit-Reset` is seconds until reset, not a Unix epoch. 429 retry delays derived from it were wrong; they now
  use the relative value.
- Network record fields were only partly mapped from the API's camelCase record.
- `abuse_velocity_score` is documented as a 0-100 score (integer on the wire); fractional legacy values still parse.
- `User-Agent` is now `ipscope-rust/1.1.0` (taken from the crate version).

### Deprecated
- `FeedbackSubmissionInput::evidence_urls`: never sent; when `evidence_url` is unset the first entry is sent as `evidence_url`.
- `RateLimitMetadata::reset_epoch_seconds`: same relative seconds value as `reset_after_seconds`.
- `RateLimitMetadata::burst_capacity` and `rate_limit_rps`: the API sends no such headers; always `None`.

### Compatibility notes
- New public fields were added to plain structs. Code that builds `FeedbackSubmissionInput`, `RateLimitMetadata` or
  response structs with a full struct literal must add the new fields or use `..Default::default()` /
  `FeedbackSubmissionInput::new(...)`.
- `NetworkPrefixLookupResponse` and `CanonicalNetworkPrefixRecord` no longer implement `Eq` (they now hold `f64`
  fields); `PartialEq` is still implemented.

## [1.0.0]

- Initial release.
