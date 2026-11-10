use ipscope::{
    validate_and_deduplicate_batch_ips, validate_api_key, validate_cidr_prefix,
    validate_ip_address, AsyncIpScopeClient, CacheOptions, FeedbackSubmissionInput,
    FeedbackSubmissionResponse, IpLookupResponse, IpScopeClient, IpScopeError,
    NetworkPrefixLookupResponse, RequestOptions, RetryOptions, FEEDBACK_ISSUE_TYPES,
    FEEDBACK_ROLES, MAX_RESPONSE_BYTES, SDK_USER_AGENT,
};
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn make_mock_ip_record(ip: &str) -> serde_json::Value {
    let version = if ip.contains(':') { 6 } else { 4 };
    let cidr = if version == 6 {
        "2001:4860:4860::/48"
    } else {
        "8.8.8.0/24"
    };
    json!({
        "ip": ip,
        "ip_version": version,
        "matched_network": cidr,
        "geo": {
            "country_code": "US",
            "subdivision": "California",
            "city": "Mountain View",
            "postal_code": "94043",
            "latitude": 37.422,
            "longitude": -122.085,
            "timezone": "America/Los_Angeles",
            "location_type": "anycast",
            "confidence": 0.96,
            "accuracy_radius_km": 20.0,
            "declared_country_code": "US",
            "physical_country_code": "US",
            "is_virtual_location": false
        },
        "network": {
            "asn": 15169,
            "organization": "Google LLC"
        },
        "security": {
            "is_vpn": false,
            "is_hosting": true,
            "is_tor_exit": false,
            "is_proxy": false,
            "is_relay": false,
            "anonymizer_type": "none",
            "confidence": 0.99,
            "reason_codes": ["ASN_HOSTING"]
        },
        "connection": {
            "connection_type": "hosting",
            "is_residential": false,
            "is_mobile": false,
            "is_business": false,
            "is_hosting": true
        },
        "security_extensions": {
            "abuse_velocity_score": 80,
            "is_known_scanner": false,
            "observation_recency_hours": 1.5
        },
        "dataset_version": "2026.10.25-001",
        "updated_at": "2026-10-25T00:00:00Z"
    })
}

fn spawn_mock_http_server<F>(handler: F) -> String
where
    F: Fn(String, String, Vec<u8>) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let h = Arc::clone(&handler);
            thread::spawn(move || {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = Vec::with_capacity(4096);
                let mut temp = [0u8; 4096];
                let mut header_end = None;

                while header_end.is_none() {
                    match stream.read(&mut temp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&temp[..n]);
                            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                        }
                    }
                }

                let Some(hdr_idx) = header_end else {
                    return;
                };
                let hdr_str = String::from_utf8_lossy(&buf[..hdr_idx]).to_string();
                let mut lines = hdr_str.lines();
                let req_line = lines.next().unwrap_or("");
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("GET").to_string();
                let path = parts.next().unwrap_or("/").to_string();

                let mut content_len = 0usize;
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }

                let body_start = hdr_idx + 4;
                while buf.len() < body_start + content_len {
                    match stream.read(&mut temp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&temp[..n]),
                    }
                }
                let body = if buf.len() >= body_start + content_len {
                    buf[body_start..body_start + content_len].to_vec()
                } else {
                    Vec::new()
                };

                let (status, extra_headers, resp_body) = h(method, path, body);
                let reason = match status {
                    200 => "OK",
                    201 => "Created",
                    401 => "Unauthorized",
                    429 => "Too Many Requests",
                    503 => "Service Unavailable",
                    _ => "Error",
                };

                let mut resp_head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-RateLimit-Limit: 1000\r\nX-RateLimit-Remaining: 998\r\nX-RateLimit-Reset: 42\r\nX-RateLimit-Scope: user\r\n",
                    resp_body.len()
                );
                for (k, v) in extra_headers {
                    resp_head.push_str(&format!("{k}: {v}\r\n"));
                }
                resp_head.push_str("\r\n");

                let _ = stream.write_all(resp_head.as_bytes());
                let _ = stream.write_all(&resp_body);
                let _ = stream.flush();
            });
        }
    });

    format!("http://127.0.0.1:{}", addr.port())
}

#[test]
fn test_validation_and_strict_scope() {
    assert_eq!(
        validate_api_key("  ips_live_secret_12345 ").unwrap(),
        "ips_live_secret_12345"
    );
    assert!(validate_api_key("   ").unwrap_err().is_validation());
    assert!(validate_api_key("ips_live_bad\nheader")
        .unwrap_err()
        .is_validation());

    let v4 = validate_ip_address(" 8.8.8.8 ").unwrap();
    assert_eq!(v4.canonical_ip, "8.8.8.8");
    assert_eq!(v4.family, 4);

    let v6 = validate_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
    assert_eq!(v6.canonical_ip, "2001:db8::1");
    assert_eq!(v6.family, 6);

    assert!(validate_ip_address("999.999.999.999")
        .unwrap_err()
        .is_validation());

    let cidr = validate_cidr_prefix("8.8.8.99/24").unwrap();
    assert_eq!(cidr.address, "8.8.8.0");
    assert_eq!(cidr.prefix_length, 24);
    assert_eq!(cidr.canonical_cidr, "8.8.8.0/24");

    let batch =
        validate_and_deduplicate_batch_ips(&["8.8.8.8", "1.1.1.1", "8.8.8.8"], 100).unwrap();
    assert_eq!(batch.ordered_ips, vec!["8.8.8.8", "1.1.1.1", "8.8.8.8"]);
    assert_eq!(batch.unique_ips, vec!["8.8.8.8", "1.1.1.1"]);
}

#[tokio::test]
async fn test_async_singleflight_batch_and_endpoints() {
    let single_hits = Arc::new(AtomicUsize::new(0));
    let sent_batches: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));

    let feedback_bodies: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));

    let hits_clone = Arc::clone(&single_hits);
    let batches_clone = Arc::clone(&sent_batches);
    let feedback_bodies_clone = Arc::clone(&feedback_bodies);

    let base_url = spawn_mock_http_server(move |_method, path, body| {
        if path == "/v1/ip/8.8.8.8" {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(25));
            return (
                200,
                vec![],
                serde_json::to_vec(&make_mock_ip_record("8.8.8.8")).unwrap(),
            );
        }
        if path == "/v1/ip/batch" {
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ips: Vec<String> = parsed["ips"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            batches_clone.lock().unwrap().push(ips.clone());
            let results: Vec<serde_json::Value> =
                ips.iter().map(|ip| make_mock_ip_record(ip)).collect();
            return (
                200,
                vec![],
                serde_json::to_vec(&json!({
                    "dataset_version": "2026.10.25-001",
                    "count": results.len(),
                    "results": results
                }))
                .unwrap(),
            );
        }
        if path == "/v1/networks/8.8.8.0/24" {
            return (
                200,
                vec![],
                serde_json::to_vec(&json!({
                    "queried_cidr": "8.8.8.0/24",
                    "matched_network": "8.8.8.0/24",
                    "family": 4,
                    "bgp_prefix_length": 24,
                    "dataset_version": "2026.10.25-001",
                    "record": {
                        "family": 4,
                        "prefix": "8.8.8.0/24",
                        "asn": 15169,
                        "organization": "Google LLC",
                        "locations": {},
                        "countryCode": "US",
                        "subdivision": "California",
                        "city": "Mountain View",
                        "postalCode": "94043",
                        "latitude": 37.422,
                        "longitude": -122.085,
                        "timezone": "America/Los_Angeles",
                        "locationType": "declared",
                        "geoConfidence": 0.85,
                        "accuracyRadiusKm": 300,
                        "isVirtualLocation": null,
                        "connectionType": "hosting",
                        "isHosting": true,
                        "isVpn": false,
                        "isTorExit": false,
                        "isProxy": false,
                        "anonymizerType": "none",
                        "securityConfidence": 0.85,
                        "abuseVelocityScore": 80,
                        "isKnownScanner": false,
                        "reasonCodes": ["KNOWN_HOSTING_INFRASTRUCTURE_RANGE"],
                        "sourceIds": ["bgp"],
                        "licensePolicyIds": ["cc0"],
                        "updatedAt": "2026-11-10T03:02:07.437Z"
                    },
                    "lookup": make_mock_ip_record("8.8.8.0")
                }))
                .unwrap(),
            );
        }
        if path == "/v1/ip/me" {
            return (
                200,
                vec![],
                serde_json::to_vec(&make_mock_ip_record("203.0.113.42")).unwrap(),
            );
        }
        if path == "/v1/metadata/datasets" {
            return (
                200,
                vec![],
                serde_json::to_vec(&json!({
                    "active_version": "2026.10.25-001",
                    "previous_version": "2026.10.24-001",
                    "snapshots": [{
                        "snapshot_version": "2026.10.25-001",
                        "digest": "sha256:abc123",
                        "ruleset_version": "v1",
                        "published_at": "2026-10-25T00:00:00Z",
                        "ipv4_prefix_count": 950000,
                        "ipv6_prefix_count": 220000
                    }]
                }))
                .unwrap(),
            );
        }
        if path == "/v1/feedback" {
            let mut parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            feedback_bodies_clone.lock().unwrap().push(parsed.clone());
            // Echo the payload the way the API does: dto spread + id, camelCase createdAt, status.
            let obj = parsed.as_object_mut().unwrap();
            obj.insert("id".to_string(), json!("fb_rust_999"));
            obj.insert("createdAt".to_string(), json!("2026-10-25T10:00:00Z"));
            obj.insert("status".to_string(), json!("pending_review"));
            return (201, vec![], serde_json::to_vec(&parsed).unwrap());
        }
        if path == "/v1/status" {
            return (
                200,
                vec![],
                serde_json::to_vec(&json!({
                    "status": "ok",
                    "snapshot": {
                        "currentVersion": "2026.10.25-001",
                        "previousVersion": "2026.10.24-001"
                    }
                }))
                .unwrap(),
            );
        }
        (404, vec![], b"{}".to_vec())
    });

    let client = AsyncIpScopeClient::builder("ips_live_valid_key_12345")
        .base_url(&base_url)
        .build_async()
        .unwrap();

    // 1. Concurrent singleflight coalescing (20 tasks -> 1 HTTP call)
    let mut handles = Vec::new();
    for _ in 0..20 {
        let c = client.clone();
        handles.push(tokio::spawn(async move { c.lookup_ip("8.8.8.8").await }));
    }
    for h in handles {
        let res = h.await.unwrap().unwrap();
        assert_eq!(res.ip, "8.8.8.8");
        assert_eq!(res.geo.country_code.as_deref(), Some("US"));
        assert_eq!(res.network.asn, Some(15169));
    }
    assert_eq!(single_hits.load(Ordering::SeqCst), 1);
    assert!(client.get_cache_stats().coalesced_in_flight_hits > 0);
    let rl = client.get_last_rate_limit().unwrap();
    assert_eq!(rl.limit_per_minute, Some(1000));
    assert_eq!(rl.remaining, Some(998));
    assert_eq!(rl.reset_after_seconds, Some(42));
    assert_eq!(rl.scope.as_deref(), Some("user"));
    #[allow(deprecated)]
    {
        assert_eq!(rl.reset_epoch_seconds, Some(42));
        assert_eq!(rl.burst_capacity, None);
        assert_eq!(rl.rate_limit_rps, None);
    }

    let one = client.lookup_ip("8.8.8.8").await.unwrap();
    assert_eq!(one.geo.latitude, Some(37.422));
    assert_eq!(one.geo.longitude, Some(-122.085));
    assert_eq!(one.geo.postal_code.as_deref(), Some("94043"));
    assert_eq!(one.security.is_relay, Some(false));
    assert_eq!(
        one.security_extensions
            .as_ref()
            .unwrap()
            .abuse_velocity_score,
        Some(80.0)
    );

    // 2. Batch deduplication & cache reuse
    let batch = client
        .lookup_batch(&["8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9"])
        .await
        .unwrap();
    assert_eq!(batch.count, 5);
    assert_eq!(
        sent_batches.lock().unwrap()[0],
        vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]
    );

    // 3. Chunked async batch (>100 IPs)
    let large_ips: Vec<String> = (1..=250).map(|i| format!("10.0.0.{i}")).collect();
    let chunked = client
        .lookup_batch_chunked(&large_ips, 3, &RequestOptions::with_bypass_cache())
        .await
        .unwrap();
    assert_eq!(chunked.count, 250);

    // 4. Network, Caller IP, Datasets, Feedback, Status
    let net = client.lookup_network("8.8.8.0/24").await.unwrap();
    assert_eq!(net.queried_cidr, "8.8.8.0/24");
    assert_eq!(net.matched_network.as_deref(), Some("8.8.8.0/24"));
    assert_eq!(net.bgp_prefix_length, Some(24));
    assert_eq!(net.lookup.as_ref().unwrap().ip, "8.8.8.0");
    assert_eq!(net.lookup.as_ref().unwrap().geo.latitude, Some(37.422));
    let record = net.record.unwrap();
    assert_eq!(record.asn, Some(15169));
    assert_eq!(record.country_code.as_deref(), Some("US"));
    assert_eq!(record.postal_code.as_deref(), Some("94043"));
    assert_eq!(record.latitude, Some(37.422));
    assert_eq!(record.location_type.as_deref(), Some("declared"));
    assert_eq!(record.geo_confidence, Some(0.85));
    assert_eq!(record.accuracy_radius_km, Some(300.0));
    assert_eq!(record.connection_type.as_deref(), Some("hosting"));
    assert_eq!(record.is_hosting, Some(true));
    assert_eq!(record.is_vpn, Some(false));
    assert_eq!(record.anonymizer_type.as_deref(), Some("none"));
    assert_eq!(record.abuse_velocity_score, Some(80.0));
    assert_eq!(
        record.reason_codes,
        vec!["KNOWN_HOSTING_INFRASTRUCTURE_RANGE"]
    );
    assert_eq!(
        record.updated_at.as_deref(),
        Some("2026-11-10T03:02:07.437Z")
    );

    let caller = client.lookup_caller_ip().await.unwrap();
    assert_eq!(caller.ip, "203.0.113.42");

    let meta = client.get_datasets_metadata().await.unwrap();
    assert_eq!(meta.active_version, "2026.10.25-001");

    let mut corr = HashMap::new();
    corr.insert("country_code".to_string(), json!("US"));
    let fb = client
        .submit_feedback(
            FeedbackSubmissionInput::new("8.8.8.8", "network_owner", "wrong_country", corr.clone())
                .with_evidence_url("https://example.net/geofeed.csv")
                .with_contact("noc@example.net", true),
        )
        .await
        .unwrap();
    assert_eq!(fb.id, "fb_rust_999");
    assert_eq!(fb.created_at, "2026-10-25T10:00:00Z");
    assert_eq!(fb.role, "network_owner");
    assert_eq!(
        fb.evidence_url.as_deref(),
        Some("https://example.net/geofeed.csv")
    );
    assert_eq!(fb.contact_consent, Some(true));
    assert_eq!(fb.contact_email.as_deref(), Some("noc@example.net"));
    {
        let bodies = feedback_bodies.lock().unwrap();
        let sent = &bodies[0];
        assert_eq!(
            sent["evidence_url"],
            json!("https://example.net/geofeed.csv")
        );
        assert_eq!(sent["contact_consent"], json!(true));
        assert_eq!(sent["contact_email"], json!("noc@example.net"));
        assert!(sent.get("evidence_urls").is_none());
    }

    // Deprecated `evidence_urls` still works: first entry is sent as `evidence_url`.
    #[allow(deprecated)]
    let legacy = FeedbackSubmissionInput {
        evidence_urls: Some(vec!["https://example.net/rdap".to_string()]),
        ..FeedbackSubmissionInput::new("8.8.8.0/24", "researcher", "other", corr)
    };
    client.submit_feedback(legacy).await.unwrap();
    {
        let bodies = feedback_bodies.lock().unwrap();
        let sent = &bodies[1];
        assert_eq!(sent["evidence_url"], json!("https://example.net/rdap"));
        assert!(sent.get("evidence_urls").is_none());
        assert!(sent.get("contact_email").is_none());
        assert!(sent.get("contact_consent").is_none());
    }

    let status = client.get_status().await.unwrap();
    assert_eq!(status.status, "ok");
    assert_eq!(status.current_version(), Some("2026.10.25-001"));
}

#[test]
fn test_sync_client_retries_errors_and_memory_bounds() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);

    let base_url = spawn_mock_http_server(move |_method, path, body| {
        if path == "/v1/ip/1.1.1.1" {
            let n = attempts_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                return (
                    429,
                    vec![("Retry-After".to_string(), "0.005".to_string())],
                    b"{\"message\":\"Rate limited\"}".to_vec(),
                );
            }
            if n == 2 {
                return (503, vec![], b"{\"message\":\"Unavailable\"}".to_vec());
            }
            return (
                200,
                vec![],
                serde_json::to_vec(&make_mock_ip_record("1.1.1.1")).unwrap(),
            );
        }
        if path == "/v1/ip/8.8.4.4" {
            return (401, vec![], b"{\"message\":\"Invalid API key\"}".to_vec());
        }
        if path == "/v1/ip/9.9.9.9" {
            return (200, vec![], vec![b'x'; MAX_RESPONSE_BYTES + 128]);
        }
        if path == "/v1/ip/batch" {
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ips: Vec<String> = parsed["ips"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let results: Vec<serde_json::Value> =
                ips.iter().map(|ip| make_mock_ip_record(ip)).collect();
            return (
                200,
                vec![],
                serde_json::to_vec(&json!({
                    "dataset_version": "2026.10.25-001",
                    "count": results.len(),
                    "results": results
                }))
                .unwrap(),
            );
        }
        let ip = path.rsplit('/').next().unwrap_or("10.0.0.1");
        (
            200,
            vec![],
            serde_json::to_vec(&make_mock_ip_record(ip)).unwrap(),
        )
    });

    let client = IpScopeClient::builder("ips_live_valid_key_12345")
        .base_url(&base_url)
        .retry(RetryOptions {
            max_retries: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            retry_on_rate_limit: true,
        })
        .cache(CacheOptions {
            enabled: true,
            max_entries: 3,
            ttl: Duration::from_secs(60),
        })
        .build_sync()
        .unwrap();

    // 1. Retries on 429 & 503 then succeeds
    let rec = client.lookup_ip("1.1.1.1").unwrap();
    assert_eq!(rec.ip, "1.1.1.1");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);

    // 2. 401 Auth Error
    let auth_err = client.lookup_ip("8.8.4.4").unwrap_err();
    assert!(auth_err.is_auth());

    // 3. Oversized > 2 MiB response guard
    let size_err = client.lookup_ip("9.9.9.9").unwrap_err();
    assert_eq!(size_err.code(), "IPSCOPE_RESPONSE_TOO_LARGE");

    // 4. Bounded LRU cache eviction (max_entries = 3)
    for i in 1..=12 {
        let _ = client.lookup_ip(&format!("10.0.0.{i}")).unwrap();
    }
    assert!(client.get_cache_stats().size <= 3);

    // 5. Sync streaming batch iterator
    let stream_ips: Vec<String> = (1..=250).map(|i| format!("172.16.0.{i}")).collect();
    let opts = RequestOptions::with_bypass_cache();
    let mut streamed_total = 0usize;
    for chunk_res in client.lookup_batch_stream(&stream_ips, &opts) {
        streamed_total += chunk_res.unwrap().count;
    }
    assert_eq!(streamed_total, 250);
    let _ = IpScopeError::Validation {
        field: "ip",
        message: "check".to_string(),
    };
}

#[test]
fn test_wire_compatibility_of_new_fields() {
    // abuse_velocity_score: integer 0-100 (new) and legacy fraction both parse.
    let mut rec = make_mock_ip_record("146.75.164.1");
    rec["security_extensions"]["abuse_velocity_score"] = json!(0.14);
    let parsed: IpLookupResponse = serde_json::from_value(rec.clone()).unwrap();
    assert_eq!(
        parsed.security_extensions.unwrap().abuse_velocity_score,
        Some(0.14)
    );
    rec["security_extensions"]["abuse_velocity_score"] = json!(null);
    let parsed: IpLookupResponse = serde_json::from_value(rec.clone()).unwrap();
    assert_eq!(
        parsed.security_extensions.unwrap().abuse_velocity_score,
        None
    );

    // Older payloads without the new optional fields still parse.
    let geo = rec["geo"].as_object_mut().unwrap();
    geo.remove("latitude");
    geo.remove("longitude");
    geo.remove("postal_code");
    rec["security"].as_object_mut().unwrap().remove("is_relay");
    let parsed: IpLookupResponse = serde_json::from_value(rec).unwrap();
    assert_eq!(parsed.geo.latitude, None);
    assert_eq!(parsed.security.is_relay, None);

    // Feedback response accepts snake_case created_at too.
    let fb: FeedbackSubmissionResponse = serde_json::from_value(json!({
        "id": "fb_1",
        "prefix_or_ip": "8.8.8.8",
        "role": "user",
        "issue_type": "wrong_city",
        "requested_correction": {},
        "created_at": "2026-10-25T10:00:00Z",
        "status": "pending_review"
    }))
    .unwrap();
    assert_eq!(fb.created_at, "2026-10-25T10:00:00Z");

    // Network record still accepts snake_case keys, and a null record.
    let net: NetworkPrefixLookupResponse = serde_json::from_value(json!({
        "queried_cidr": "10.0.0.0/8",
        "family": 4,
        "dataset_version": "v",
        "record": {"prefix": "10.0.0.0/8", "family": 4, "asn": null, "organization": null,
                   "country_code": "ZZ", "city": null, "is_vpn": false}
    }))
    .unwrap();
    assert_eq!(
        net.record.as_ref().unwrap().country_code.as_deref(),
        Some("ZZ")
    );
    assert_eq!(net.matched_network, None);
    assert!(net.lookup.is_none());

    assert!(FEEDBACK_ROLES.contains(&"network_owner"));
    assert!(FEEDBACK_ISSUE_TYPES.contains(&"virtual_location_mismatch"));
    assert_eq!(SDK_USER_AGENT, "ipscope-rust/1.1.0");
}
