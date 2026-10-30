# `ipscope` - Official IPScope Server-Side Rust SDK

Official memory-safe (`#![forbid(unsafe_code)]`), strictly typed server-side **Rust SDK** (`ipscope`) for the **IPScope IP Intelligence Platform**, supporting both **Asynchronous (`AsyncIpScopeClient`)** and **Synchronous (`IpScopeClient`)** execution.

> **Scope Notice:** This SDK is intentionally scoped strictly to **IP intelligence, network prefix, dataset metadata, feedback, and health operations**. It contains **zero account, billing, wallet, or key-management operations**, making it safe to deploy in production backend microservices, workers, and API gateways.

---

## Features

- **`#![forbid(unsafe_code)]` & 100% Type-Safe**: Strongly typed `serde` models (`IpLookupResponse`, `GeoBlock`, `NetworkBlock`, `SecurityBlock`, `ConnectionBlock`, `SecurityExtensionsBlock`, `BatchLookupResponse`, `NetworkPrefixLookupResponse`, `DatasetsMetadataResponse`, `FeedbackSubmissionResponse`, `ServiceStatusResponse`).
- **Both Async & Sync Clients**:
  - `AsyncIpScopeClient`: Powered by `tokio` and `reqwest::Client` with persistent connection pooling, singleflight request coalescing (`tokio::sync::watch` + RAII drop guard), and bounded batch concurrency (`tokio::sync::Semaphore`).
  - `IpScopeClient`: Blocking client powered by `reqwest::blocking::Client` with `lookup_batch_stream` lazy `Iterator` support.
- **Low-RAM & Zero Memory Leaks**:
  - Thread-safe O(1) LRU + TTL cache (`max_entries: 512` default, `< 400 KB` heap footprint).
  - Hard `2 MiB` (`MAX_RESPONSE_BYTES`) streaming response ceiling aborts oversized responses before allocating > 2 MiB on the heap.
  - Zero-DNS IPv4/IPv6 & CIDR validation via `std::net::IpAddr`.

---

## Installation

```toml
[dependencies]
ipscope = "1.0.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

---

## Quick Start (Asynchronous Client)

```rust
use ipscope::{AsyncIpScopeClient, RequestOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AsyncIpScopeClient::new("<public>:<private>")?;

    // 1. Single IPv4 or IPv6 lookup (cached in LRU cache & singleflight-coalesced)
    let ip_info = client.lookup_ip("8.8.8.8").await?;
    println!(
        "{} {:?} {:?}",
        ip_info.ip, ip_info.geo.country_code, ip_info.network.asn
    );

    // 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
    let batch = client
        .lookup_batch(&["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
        .await?;
    for record in &batch.results {
        println!("{} -> {:?}", record.ip, record.network.organization);
    }

    // 3. Chunked batch lookup for >100 IPs with bounded async concurrency (max 4 in-flight)
    let large_batch = client
        .lookup_batch_chunked(&["8.8.8.8", "1.1.1.1", "9.9.9.9"], 4, &RequestOptions::default())
        .await?;
    println!("Resolved: {}", large_batch.count);

    // 4. Network CIDR prefix lookup
    let prefix = client.lookup_network("8.8.8.0/24").await?;
    println!("{} ({})", prefix.queried_cidr, prefix.dataset_version);

    Ok(())
}
```

---

## Quick Start (Synchronous Client)

```rust
use ipscope::{IpScopeClient, RequestOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = IpScopeClient::new("<public>:<private>")?;

    let ip_info = client.lookup_ip("1.1.1.1")?;
    println!("{} -> {:?}", ip_info.ip, ip_info.network.organization);

    // Constant-RAM lazy iterator for large IP slices
    for chunk in client.lookup_batch_stream(&["8.8.8.8", "1.1.1.1"], &RequestOptions::default()) {
        let batch = chunk?;
        println!("Chunk count: {}", batch.count);
    }

    Ok(())
}
```
