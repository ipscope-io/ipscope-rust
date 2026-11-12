<div align="center">
  <br />
  <a href="https://ipscope.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" />
      <img alt="ipscope" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" height="32" />
    </picture>
  </a>
  <h1>ipscope for Rust</h1>
  <p><strong>Official async (Tokio) and synchronous Rust server SDK for ipscope — IP geolocation, BGP ASN, and VPN/proxy detection</strong></p>
  <p>
    <a href="https://crates.io/crates/ipscope"><img src="https://img.shields.io/crates/v/ipscope.svg?style=flat-square&label=crates.io&color=0f172a" alt="crates.io version" /></a>
    <a href="https://docs.rs/ipscope"><img src="https://img.shields.io/badge/docs.rs-ipscope-0f172a?style=flat-square" alt="docs.rs" /></a>
    <img src="https://img.shields.io/badge/rust-%3E%3D1.75-0f172a?style=flat-square" alt="Rust >= 1.75" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-0f172a?style=flat-square" alt="MIT licence" /></a>
    <a href="https://ipscope.io/docs/sdks/rust"><img src="https://img.shields.io/badge/docs-ipscope.io-0f172a?style=flat-square" alt="Documentation" /></a>
  </p>
  <br />
  <a href="https://ipscope.io">
    <img alt="ipscope Rust SDK" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/banner.webp" width="100%" />
  </a>
</div>

<br />

## What is this

`ipscope` is the official, memory-safe asynchronous (`AsyncIpScopeClient`) and synchronous (`BlockingIpScopeClient`) Rust server SDK for [ipscope](https://ipscope.io). Built on `reqwest` (`rustls-tls`), `serde`, and `tokio`, it queries the [ipscope REST API](https://ipscope.io/products/api) for physical and declared [IP geolocation](https://ipscope.io/products/geolocation), [BGP origin ASN and prefix routing](https://ipscope.io/products/network), and [VPN, residential proxy, Tor exit, and relay detection](https://ipscope.io/products/privacy).

Every client instance includes a bounded `O(1)` LRU + TTL cache (`max_entries = 512` default, `< 400 KB` heap footprint), singleflight request coalescing via `tokio::sync::Notify`, a hard `2 MiB` streaming chunk guard, and constant-RAM batch streaming for 10,000+ IPs. For sub-microsecond offline lookups in Rust, see our [downloadable MMDB databases](https://ipscope.io/docs/databases/mmdb).

---

## Getting started

### 1. Get an API key

Create a free account at [dashboard.ipscope.io](https://dashboard.ipscope.io/auth/login) and copy your server API key (`<public>:<private>`).

### 2. Add the crate

```toml
[dependencies]
ipscope = "1.1.0"
tokio = { version = "1", features = ["full"] }
```

### 3. Look up an IP address

```rust
use ipscope::{AsyncIpScopeClient, IpScopeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("IPSCOPE_API_KEY")?; // "<public>:<private>"
    let client = AsyncIpScopeClient::new(IpScopeConfig::new(api_key)?)?;

    let info = client.lookup_ip("8.8.8.8").await?;
    println!("{} {:?} {:?}", info.ip, info.geo.country_code, info.network.asn);
    Ok(())
}
```

---

## Contents

- [Asynchronous lookups (`tokio`)](#asynchronous-lookups-tokio)
- [Synchronous lookups (`BlockingIpScopeClient`)](#synchronous-lookups-blockingipscopeclient)
- [Network CIDR prefix lookups](#network-cidr-prefix-lookups)
- [Reading the response](#reading-the-response)
- [Rate-limit metadata](#rate-limit-metadata)
- [Submitting feedback](#submitting-feedback)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Help](#help)
- [Licence](#licence)

---

## Asynchronous lookups (`tokio`)

```rust
use ipscope::{AsyncIpScopeClient, IpScopeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AsyncIpScopeClient::new(IpScopeConfig::new("<public>:<private>")?)?;

    // 1. Single IPv4 or IPv6 lookup (cached in LRU & singleflight-coalesced)
    let ip_info = client.lookup_ip("8.8.8.8").await?;

    // 2. Caller IP lookup (GET /v1/ip/me)
    let caller = client.lookup_caller_ip().await?;

    // 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
    let batch = client
        .lookup_batch(&["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
        .await?;
    for record in &batch.results {
        println!("{} -> {:?}", record.ip, record.network.organization);
    }

    // 4. Chunked batch lookup for >100 IPs with bounded async concurrency (default: 4)
    let large_batch = client
        .lookup_batch_chunked(&["8.8.8.8", "1.1.1.1", "9.9.9.9"], 4)
        .await?;

    // 5. Constant-RAM streaming batch lookup for 10,000+ IPs
    let large_ip_list: Vec<String> = (1..=254).map(|i| format!("192.0.2.{i}")).collect();
    client
        .lookup_batch_stream(&large_ip_list, |chunk| {
            for record in &chunk.results {
                println!("{}", record.ip);
            }
            Ok(())
        })
        .await?;

    Ok(())
}
```

---

## Synchronous lookups (`BlockingIpScopeClient`)

Use `BlockingIpScopeClient` in synchronous CLI tools, system daemons, or FFI bindings without requiring a Tokio runtime in user code:

```rust
use ipscope::{BlockingIpScopeClient, IpScopeConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = BlockingIpScopeClient::new(IpScopeConfig::new("<public>:<private>")?)?;

    let ip_info = client.lookup_ip("1.1.1.1")?;
    println!("{} -> {:?}", ip_info.ip, ip_info.network.organization);

    let batch = client.lookup_batch(&["8.8.8.8", "1.1.1.1"])?;
    for record in &batch.results {
        println!("{}", record.ip);
    }
    Ok(())
}
```

---

## Network CIDR prefix lookups

Inspect the longest-matching routed BGP prefix and its base address intelligence via `lookup_network`:

```rust
let prefix = client.lookup_network("8.8.8.0/24").await?;
println!(
    "{} matched {} (/{:?}) in {}",
    prefix.queried_cidr, prefix.matched_network, prefix.bgp_prefix_length, prefix.dataset_version
);
if let Some(ref rec) = prefix.record {
    println!("record: {:?} hosting={:?}", rec.country_code, rec.is_hosting);
}
if let Some(ref base) = prefix.lookup {
    println!("base address city: {:?}", base.geo.city);
}
```

---

## Reading the response

```rust
let info = client.lookup_ip("8.8.8.8").await?;

// Representative coordinates (never device GPS) and postal code; None when unknown
println!("{:?}, {:?} {:?}", info.geo.latitude, info.geo.longitude, info.geo.postal_code);

// Consumer privacy relays (e.g. iCloud Private Relay) are flagged separately from VPN/proxy
println!("relay={:?} vpn={:?}", info.security.is_relay, info.security.is_vpn);

// Abuse velocity score on a 0-100 scale (present when security_extensions is licensed)
if let Some(ext) = &info.security_extensions {
    println!("abuse score: {:?}", ext.abuse_velocity_score);
}
```

---

## Rate-limit metadata

Use `lookup_ip_with_meta` (or any `*_with_meta` method) to inspect the parsed `X-RateLimit-*` headers:

```rust
let res = client.lookup_ip_with_meta("1.1.1.1").await?;
let rl = &res.rate_limit;
println!(
    "{:?}/{:?} left, resets in {:?}s (scope {:?})",
    rl.remaining, rl.limit_per_minute, rl.reset_after_seconds, rl.scope
);
```

---

## Submitting feedback

Report outdated geolocation or anonymity classifications directly via `submit_feedback`:

```rust
use ipscope::FeedbackSubmissionInput;
use serde_json::json;
use std::collections::BTreeMap;

let mut correction = BTreeMap::new();
correction.insert("country_code".to_string(), json!("DE"));

let mut feedback = FeedbackSubmissionInput::new(
    "203.0.113.0/24",
    "network_owner", // VALID_FEEDBACK_ROLES: network_owner | user | researcher
    "wrong_country", // VALID_FEEDBACK_ISSUE_TYPES
    correction,
);
feedback.evidence_url = Some("https://example.net/geofeed.csv".to_string());
feedback.contact_consent = Some(true);
feedback.contact_email = Some("noc@example.net".to_string());

let receipt = client.submit_feedback(&feedback).await?;
println!("{} {} {}", receipt.id, receipt.status, receipt.created_at);
```

---

## Requirements

- Rust 1.75 or later (`edition = "2021"`).

---

## Documentation

| Topic | Link |
| :--- | :--- |
| Rust SDK guide | [ipscope.io/docs/sdks/rust](https://ipscope.io/docs/sdks/rust) |
| REST API overview | [ipscope.io/docs/api/overview](https://ipscope.io/docs/api/overview) |
| Single & batch IP lookups | [ipscope.io/docs/api/single-ip](https://ipscope.io/docs/api/single-ip) |
| Network CIDR prefix lookups | [ipscope.io/docs/api/network-prefix](https://ipscope.io/docs/api/network-prefix) |
| Errors & rate limits | [ipscope.io/docs/api/errors](https://ipscope.io/docs/api/errors) |
| Downloadable MMDB databases | [ipscope.io/docs/databases/mmdb](https://ipscope.io/docs/databases/mmdb) |

---

## Help

- Bugs and feature requests: [open an issue](https://github.com/ipscope-io/ipscope-rust/issues)
- Account, billing and integration questions: [contact@ipscope.io](mailto:contact@ipscope.io)
- Security vulnerabilities: see the [security policy](https://github.com/ipscope-io/.github/blob/main/SECURITY.md)

---

## Licence

[MIT](LICENSE). Made by [ipscope](https://ipscope.io).
