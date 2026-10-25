//! Resilient Async (`reqwest::Client`) and Sync (`reqwest::blocking::Client`) HTTP transports.

use crate::error::IpScopeError;
use crate::types::{RateLimitMetadata, RetryOptions};
use crate::validation::validate_api_key;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_BASE_URL: &str = "https://api.ipscope.io";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard 2 MiB response body ceiling to protect Rust heap memory.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const SDK_USER_AGENT: &str = "ipscope-rust/1.0.0";

pub(crate) struct TransportResponse<T> {
    pub data: T,
    pub status: u16,
    pub rate_limit: RateLimitMetadata,
}

#[derive(Clone)]
pub(crate) struct AsyncHttpTransport {
    api_key: String,
    base_url: String,
    timeout: Duration,
    retry: RetryOptions,
    user_agent: String,
    client: reqwest::Client,
    last_rate_limit: Arc<RwLock<Option<RateLimitMetadata>>>,
}

impl AsyncHttpTransport {
    pub(crate) fn new(
        api_key: &str,
        base_url: &str,
        timeout: Duration,
        retry: RetryOptions,
        user_agent: Option<&str>,
        custom_client: Option<reqwest::Client>,
    ) -> Result<Self, IpScopeError> {
        let valid_key = validate_api_key(api_key)?;
        let normalized_base = normalize_base_url(base_url);
        let effective_timeout = if timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };
        let ua = match user_agent.map(str::trim).filter(|s| !s.is_empty()) {
            Some(prefix) => format!("{prefix} {SDK_USER_AGENT}"),
            None => SDK_USER_AGENT.to_string(),
        };

        let client = match custom_client {
            Some(c) => c,
            None => reqwest::Client::builder()
                .timeout(effective_timeout)
                .pool_max_idle_per_host(10)
                .pool_idle_timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| IpScopeError::Network {
                    path: "/".to_string(),
                    message: format!("Failed to initialize HTTP client: {e}"),
                })?,
        };

        Ok(Self {
            api_key: valid_key,
            base_url: normalized_base,
            timeout: effective_timeout,
            retry,
            user_agent: ua,
            client,
            last_rate_limit: Arc::new(RwLock::new(None)),
        })
    }

    pub(crate) fn get_last_rate_limit(&self) -> Option<RateLimitMetadata> {
        self.last_rate_limit.read().ok().and_then(|g| g.clone())
    }

    pub(crate) async fn request<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        extra_headers: &HashMap<String, String>,
        requires_auth: bool,
    ) -> Result<TransportResponse<T>, IpScopeError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = format!("{}{path}", self.base_url);
        let body_bytes = match body {
            Some(b) => Some(serde_json::to_vec(b).map_err(|e| IpScopeError::Validation {
                field: "body",
                message: format!("Failed to serialize request JSON: {e}"),
            })?),
            None => None,
        };

        let max_retries = self.retry.max_retries;

        for attempt in 0..=max_retries {
            let mut req = self
                .client
                .request(method.clone(), &url)
                .timeout(self.timeout)
                .header(ACCEPT, "application/json")
                .header(USER_AGENT, &self.user_agent);

            if requires_auth {
                req = req
                    .header("x-api-key", &self.api_key)
                    .header(AUTHORIZATION, format!("Bearer {}", self.api_key));
            }

            for (k, v) in extra_headers {
                if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                    req = req.header(hn, hv);
                }
            }

            if let Some(ref payload) = body_bytes {
                req = req
                    .header(CONTENT_TYPE, "application/json")
                    .body(payload.clone());
            }

            let mut resp = match req.send().await {
                Ok(r) => r,
                Err(err) => {
                    if err.is_timeout() {
                        return Err(IpScopeError::Timeout {
                            path: path.to_string(),
                            timeout: self.timeout,
                        });
                    }
                    if attempt < max_retries {
                        tokio::time::sleep(compute_backoff(attempt, &self.retry)).await;
                        continue;
                    }
                    return Err(IpScopeError::Network {
                        path: path.to_string(),
                        message: format!("Network request to \"{path}\" failed: {err}"),
                    });
                }
            };

            let status = resp.status().as_u16();
            let headers = resp.headers().clone();

            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES as u64 {
                    return Err(IpScopeError::Api {
                        status,
                        path: path.to_string(),
                        code: "IPSCOPE_RESPONSE_TOO_LARGE".to_string(),
                        message: format!(
                            "IPScope response payload ({cl} bytes) exceeds 2 MiB safety limit"
                        ),
                        rate_limit: None,
                    });
                }
            }

            let mut buf = Vec::with_capacity(1024);
            while let Some(chunk) = resp.chunk().await.map_err(|e| {
                if e.is_timeout() {
                    IpScopeError::Timeout {
                        path: path.to_string(),
                        timeout: self.timeout,
                    }
                } else {
                    IpScopeError::Network {
                        path: path.to_string(),
                        message: format!("Failed reading response stream from \"{path}\": {e}"),
                    }
                }
            })? {
                if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(IpScopeError::Api {
                        status,
                        path: path.to_string(),
                        code: "IPSCOPE_RESPONSE_TOO_LARGE".to_string(),
                        message: "IPScope response payload exceeds 2 MiB safety limit".to_string(),
                        rate_limit: None,
                    });
                }
                buf.extend_from_slice(&chunk);
            }

            let rl = parse_rate_limit_headers(&headers);
            if let Ok(mut guard) = self.last_rate_limit.write() {
                *guard = Some(rl.clone());
            }

            if (200..300).contains(&status) {
                let parsed: T =
                    serde_json::from_slice(&buf).map_err(|e| IpScopeError::Network {
                        path: path.to_string(),
                        message: format!(
                            "Failed to deserialize response JSON from \"{path}\": {e}"
                        ),
                    })?;
                return Ok(TransportResponse {
                    data: parsed,
                    status,
                    rate_limit: rl,
                });
            }

            let err_msg = extract_error_message(&buf, status, path);

            if status == 401 || status == 403 {
                return Err(IpScopeError::Authentication {
                    status,
                    path: path.to_string(),
                    code: if status == 401 {
                        "IPSCOPE_UNAUTHORIZED".to_string()
                    } else {
                        "IPSCOPE_FORBIDDEN_SCOPE".to_string()
                    },
                    message: err_msg,
                    rate_limit: Some(rl),
                });
            }

            if status == 429 {
                let retry_after = compute_retry_after(&headers, &rl);
                if self.retry.retry_on_rate_limit && attempt < max_retries {
                    let delay = retry_after
                        .map(|ra| ra.min(self.retry.max_delay))
                        .unwrap_or_else(|| compute_backoff(attempt, &self.retry));
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(IpScopeError::RateLimit {
                    path: path.to_string(),
                    message: err_msg,
                    retry_after,
                    rate_limit: Some(rl),
                });
            }

            if matches!(status, 502 | 503 | 504) && attempt < max_retries {
                tokio::time::sleep(compute_backoff(attempt, &self.retry)).await;
                continue;
            }

            return Err(IpScopeError::Api {
                status,
                path: path.to_string(),
                code: format!("IPSCOPE_HTTP_{status}"),
                message: err_msg,
                rate_limit: Some(rl),
            });
        }

        Err(IpScopeError::Api {
            status: 0,
            path: path.to_string(),
            code: "IPSCOPE_RETRY_EXHAUSTED".to_string(),
            message: format!("Exhausted {max_retries} retries for \"{path}\""),
            rate_limit: None,
        })
    }
}

pub(crate) struct SyncHttpTransport {
    api_key: String,
    base_url: String,
    timeout: Duration,
    retry: RetryOptions,
    user_agent: String,
    client: reqwest::blocking::Client,
    last_rate_limit: Arc<RwLock<Option<RateLimitMetadata>>>,
}

impl SyncHttpTransport {
    pub(crate) fn new(
        api_key: &str,
        base_url: &str,
        timeout: Duration,
        retry: RetryOptions,
        user_agent: Option<&str>,
    ) -> Result<Self, IpScopeError> {
        let valid_key = validate_api_key(api_key)?;
        let normalized_base = normalize_base_url(base_url);
        let effective_timeout = if timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };
        let ua = match user_agent.map(str::trim).filter(|s| !s.is_empty()) {
            Some(prefix) => format!("{prefix} {SDK_USER_AGENT}"),
            None => SDK_USER_AGENT.to_string(),
        };

        let client = reqwest::blocking::Client::builder()
            .timeout(effective_timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| IpScopeError::Network {
                path: "/".to_string(),
                message: format!("Failed to initialize blocking HTTP client: {e}"),
            })?;

        Ok(Self {
            api_key: valid_key,
            base_url: normalized_base,
            timeout: effective_timeout,
            retry,
            user_agent: ua,
            client,
            last_rate_limit: Arc::new(RwLock::new(None)),
        })
    }

    pub(crate) fn get_last_rate_limit(&self) -> Option<RateLimitMetadata> {
        self.last_rate_limit.read().ok().and_then(|g| g.clone())
    }

    pub(crate) fn request<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        extra_headers: &HashMap<String, String>,
        requires_auth: bool,
    ) -> Result<TransportResponse<T>, IpScopeError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = format!("{}{path}", self.base_url);
        let body_bytes = match body {
            Some(b) => Some(serde_json::to_vec(b).map_err(|e| IpScopeError::Validation {
                field: "body",
                message: format!("Failed to serialize request JSON: {e}"),
            })?),
            None => None,
        };

        let max_retries = self.retry.max_retries;

        for attempt in 0..=max_retries {
            let mut req = self
                .client
                .request(method.clone(), &url)
                .timeout(self.timeout)
                .header(ACCEPT, "application/json")
                .header(USER_AGENT, &self.user_agent);

            if requires_auth {
                req = req
                    .header("x-api-key", &self.api_key)
                    .header(AUTHORIZATION, format!("Bearer {}", self.api_key));
            }

            for (k, v) in extra_headers {
                if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                    req = req.header(hn, hv);
                }
            }

            if let Some(ref payload) = body_bytes {
                req = req
                    .header(CONTENT_TYPE, "application/json")
                    .body(payload.clone());
            }

            let resp = match req.send() {
                Ok(r) => r,
                Err(err) => {
                    if err.is_timeout() {
                        return Err(IpScopeError::Timeout {
                            path: path.to_string(),
                            timeout: self.timeout,
                        });
                    }
                    if attempt < max_retries {
                        std::thread::sleep(compute_backoff(attempt, &self.retry));
                        continue;
                    }
                    return Err(IpScopeError::Network {
                        path: path.to_string(),
                        message: format!("Network request to \"{path}\" failed: {err}"),
                    });
                }
            };

            let status = resp.status().as_u16();
            let headers = resp.headers().clone();

            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES as u64 {
                    return Err(IpScopeError::Api {
                        status,
                        path: path.to_string(),
                        code: "IPSCOPE_RESPONSE_TOO_LARGE".to_string(),
                        message: format!(
                            "IPScope response payload ({cl} bytes) exceeds 2 MiB safety limit"
                        ),
                        rate_limit: None,
                    });
                }
            }

            let mut buf = Vec::with_capacity(1024);
            let mut limited = resp.take((MAX_RESPONSE_BYTES + 1) as u64);
            limited
                .read_to_end(&mut buf)
                .map_err(|e| IpScopeError::Network {
                    path: path.to_string(),
                    message: format!("Failed reading response stream from \"{path}\": {e}"),
                })?;

            if buf.len() > MAX_RESPONSE_BYTES {
                return Err(IpScopeError::Api {
                    status,
                    path: path.to_string(),
                    code: "IPSCOPE_RESPONSE_TOO_LARGE".to_string(),
                    message: "IPScope response payload exceeds 2 MiB safety limit".to_string(),
                    rate_limit: None,
                });
            }

            let rl = parse_rate_limit_headers(&headers);
            if let Ok(mut guard) = self.last_rate_limit.write() {
                *guard = Some(rl.clone());
            }

            if (200..300).contains(&status) {
                let parsed: T =
                    serde_json::from_slice(&buf).map_err(|e| IpScopeError::Network {
                        path: path.to_string(),
                        message: format!(
                            "Failed to deserialize response JSON from \"{path}\": {e}"
                        ),
                    })?;
                return Ok(TransportResponse {
                    data: parsed,
                    status,
                    rate_limit: rl,
                });
            }

            let err_msg = extract_error_message(&buf, status, path);

            if status == 401 || status == 403 {
                return Err(IpScopeError::Authentication {
                    status,
                    path: path.to_string(),
                    code: if status == 401 {
                        "IPSCOPE_UNAUTHORIZED".to_string()
                    } else {
                        "IPSCOPE_FORBIDDEN_SCOPE".to_string()
                    },
                    message: err_msg,
                    rate_limit: Some(rl),
                });
            }

            if status == 429 {
                let retry_after = compute_retry_after(&headers, &rl);
                if self.retry.retry_on_rate_limit && attempt < max_retries {
                    let delay = retry_after
                        .map(|ra| ra.min(self.retry.max_delay))
                        .unwrap_or_else(|| compute_backoff(attempt, &self.retry));
                    std::thread::sleep(delay);
                    continue;
                }
                return Err(IpScopeError::RateLimit {
                    path: path.to_string(),
                    message: err_msg,
                    retry_after,
                    rate_limit: Some(rl),
                });
            }

            if matches!(status, 502 | 503 | 504) && attempt < max_retries {
                std::thread::sleep(compute_backoff(attempt, &self.retry));
                continue;
            }

            return Err(IpScopeError::Api {
                status,
                path: path.to_string(),
                code: format!("IPSCOPE_HTTP_{status}"),
                message: err_msg,
                rate_limit: Some(rl),
            });
        }

        Err(IpScopeError::Api {
            status: 0,
            path: path.to_string(),
            code: "IPSCOPE_RETRY_EXHAUSTED".to_string(),
            message: format!("Exhausted {max_retries} retries for \"{path}\""),
            rate_limit: None,
        })
    }
}

fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        DEFAULT_BASE_URL.to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_rate_limit_headers(headers: &HeaderMap) -> RateLimitMetadata {
    let parse_u32 = |name: &str| -> Option<u32> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
    };
    let parse_u64 = |name: &str| -> Option<u64> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
    };
    let parse_str = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    RateLimitMetadata {
        limit_per_minute: parse_u32("x-ratelimit-limit"),
        remaining: parse_u32("x-ratelimit-remaining"),
        reset_epoch_seconds: parse_u64("x-ratelimit-reset"),
        scope: parse_str("x-ratelimit-scope"),
        burst_capacity: parse_u32("x-ratelimit-burst"),
        rate_limit_rps: parse_u32("x-ratelimit-rps"),
    }
}

fn extract_error_message(body_bytes: &[u8], status: u16, path: &str) -> String {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        if let Some(msg) = val.get("message") {
            if let Some(s) = msg.as_str() {
                if !s.trim().is_empty() {
                    return s.trim().to_string();
                }
            } else if let Some(arr) = msg.as_array() {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                if !parts.is_empty() {
                    return parts.join("; ");
                }
            }
        }
    }
    format!("IPScope API error ({status}) on {path}")
}

fn compute_retry_after(headers: &HeaderMap, rl: &RateLimitMetadata) -> Option<Duration> {
    if let Some(raw) = headers.get("retry-after").and_then(|v| v.to_str().ok()) {
        if let Ok(secs) = raw.trim().parse::<f64>() {
            if secs >= 0.0 {
                return Some(Duration::from_secs_f64(secs));
            }
        }
    }
    if let Some(reset_epoch) = rl.reset_epoch_seconds {
        if let Ok(now_dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
            if reset_epoch > now_dur.as_secs() {
                return Some(Duration::from_secs(reset_epoch - now_dur.as_secs()));
            }
        }
    }
    None
}

fn compute_backoff(attempt: usize, retry: &RetryOptions) -> Duration {
    let shift = attempt.min(10) as u32;
    let base_ms = retry.base_delay.as_millis().max(1) as u64;
    let max_ms = retry.max_delay.as_millis().max(base_ms as u128) as u64;
    let exp_ms = base_ms.saturating_mul(1u64 << shift).min(max_ms);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(17);
    let jitter_bound = (exp_ms / 4).max(5);
    let jitter_ms = nanos % jitter_bound;
    Duration::from_millis((exp_ms + jitter_ms).min(max_ms))
}
