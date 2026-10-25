//! Official Async (`AsyncIpScopeClient`) and Sync (`IpScopeClient`) Rust Server-Side Clients.
//!
//! Strictly limited to IP intelligence, network CIDR prefix, dataset metadata,
//! feedback submission, and service status operations.

use crate::cache::LruTtlCache;
use crate::error::IpScopeError;
use crate::transport::{AsyncHttpTransport, SyncHttpTransport, DEFAULT_BASE_URL, DEFAULT_TIMEOUT};
use crate::types::{
    BatchLookupResponse, CacheOptions, CacheStats, DatasetsMetadataResponse,
    FeedbackSubmissionInput, FeedbackSubmissionResponse, IpLookupResponse, IpScopeResultWithMeta,
    NetworkPrefixLookupResponse, RateLimitMetadata, RequestOptions, RetryOptions,
    ServiceStatusResponse,
};
use crate::validation::{
    validate_and_deduplicate_batch_ips, validate_cidr_prefix, validate_ip_address,
    MAX_SINGLE_BATCH_SIZE,
};
use reqwest::Method;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Builder for configuring an [`AsyncIpScopeClient`] or [`IpScopeClient`].
#[derive(Clone, Debug)]
pub struct IpScopeClientBuilder {
    api_key: String,
    base_url: String,
    timeout: Duration,
    retry: RetryOptions,
    cache: CacheOptions,
    user_agent: Option<String>,
    http_client: Option<reqwest::Client>,
}

impl IpScopeClientBuilder {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            retry: RetryOptions::default(),
            cache: CacheOptions::default(),
            user_agent: None,
            http_client: None,
        }
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn retry(mut self, retry: RetryOptions) -> Self {
        self.retry = retry;
        self
    }

    pub fn cache(mut self, cache: CacheOptions) -> Self {
        self.cache = cache;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn build_async(self) -> Result<AsyncIpScopeClient, IpScopeError> {
        let transport = AsyncHttpTransport::new(
            &self.api_key,
            &self.base_url,
            self.timeout,
            self.retry,
            self.user_agent.as_deref(),
            self.http_client,
        )?;
        let net_cache_opts = CacheOptions {
            enabled: self.cache.enabled,
            max_entries: self.cache.max_entries.clamp(1, 128),
            ttl: self.cache.ttl,
        };
        Ok(AsyncIpScopeClient {
            transport,
            ip_cache: Arc::new(LruTtlCache::new(self.cache)),
            network_cache: Arc::new(LruTtlCache::new(net_cache_opts)),
        })
    }

    pub fn build_sync(self) -> Result<IpScopeClient, IpScopeError> {
        let transport = SyncHttpTransport::new(
            &self.api_key,
            &self.base_url,
            self.timeout,
            self.retry,
            self.user_agent.as_deref(),
        )?;
        let net_cache_opts = CacheOptions {
            enabled: self.cache.enabled,
            max_entries: self.cache.max_entries.clamp(1, 128),
            ttl: self.cache.ttl,
        };
        Ok(IpScopeClient {
            transport: Arc::new(transport),
            ip_cache: Arc::new(LruTtlCache::new(self.cache)),
            network_cache: Arc::new(LruTtlCache::new(net_cache_opts)),
        })
    }
}

/// Official Asynchronous Rust Server-Side Client (`tokio` + `reqwest::Client`).
#[derive(Clone)]
pub struct AsyncIpScopeClient {
    transport: AsyncHttpTransport,
    ip_cache: Arc<LruTtlCache<IpLookupResponse>>,
    network_cache: Arc<LruTtlCache<NetworkPrefixLookupResponse>>,
}

impl AsyncIpScopeClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self, IpScopeError> {
        IpScopeClientBuilder::new(api_key).build_async()
    }

    pub fn builder(api_key: impl Into<String>) -> IpScopeClientBuilder {
        IpScopeClientBuilder::new(api_key)
    }

    /// Looks up intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/:ip`).
    /// Concurrent lookups for the same IP are automatically singleflight-coalesced.
    pub async fn lookup_ip(&self, raw_ip: &str) -> Result<IpLookupResponse, IpScopeError> {
        self.lookup_ip_with_options(raw_ip, &RequestOptions::default())
            .await
    }

    pub async fn lookup_ip_with_options(
        &self,
        raw_ip: &str,
        options: &RequestOptions,
    ) -> Result<IpLookupResponse, IpScopeError> {
        Ok(self.lookup_ip_with_meta(raw_ip, options).await?.data)
    }

    /// Looks up a single IPv4 or IPv6 address and returns both data and rate-limit metadata.
    pub async fn lookup_ip_with_meta(
        &self,
        raw_ip: &str,
        options: &RequestOptions,
    ) -> Result<IpScopeResultWithMeta<IpLookupResponse>, IpScopeError> {
        let validated = validate_ip_address(raw_ip)?;
        let ip_str = validated.canonical_ip;

        let (val, from_cache) = self
            .ip_cache
            .get_or_compute_async(&ip_str, options.bypass_cache, || async {
                let path = format!("/v1/ip/{ip_str}");
                let resp = self
                    .transport
                    .request::<IpLookupResponse, ()>(
                        Method::GET,
                        &path,
                        None,
                        &options.headers,
                        true,
                    )
                    .await?;
                let canonical_lower = resp.data.ip.to_lowercase();
                if canonical_lower != ip_str {
                    self.ip_cache.set(&canonical_lower, resp.data.clone());
                }
                Ok(resp.data)
            })
            .await?;

        Ok(IpScopeResultWithMeta {
            data: val,
            status: 200,
            rate_limit: self.transport.get_last_rate_limit().unwrap_or_default(),
            from_cache,
        })
    }

    /// Looks up intelligence for the caller's own server-observed IP (`GET /v1/ip/me`).
    pub async fn lookup_caller_ip(&self) -> Result<IpLookupResponse, IpScopeError> {
        let resp = self
            .transport
            .request::<IpLookupResponse, ()>(Method::GET, "/v1/ip/me", None, &HashMap::new(), true)
            .await?;
        Ok(resp.data)
    }

    /// Performs a batch lookup for `1..=100` IPs (`POST /v1/ip/batch`), deduplicating wire
    /// requests and reusing warm LRU cache entries automatically.
    pub async fn lookup_batch<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
    ) -> Result<BatchLookupResponse, IpScopeError> {
        self.lookup_batch_with_options(raw_ips, &RequestOptions::default())
            .await
    }

    pub async fn lookup_batch_with_options<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
        options: &RequestOptions,
    ) -> Result<BatchLookupResponse, IpScopeError> {
        let batch = validate_and_deduplicate_batch_ips(raw_ips, MAX_SINGLE_BATCH_SIZE)?;

        let mut resolved_by_ip: HashMap<String, IpLookupResponse> =
            HashMap::with_capacity(batch.unique_ips.len());
        let mut missing_ips: Vec<String> = Vec::with_capacity(batch.unique_ips.len());

        if !options.bypass_cache {
            for ip_str in &batch.unique_ips {
                if let Some(cached) = self.ip_cache.get(ip_str) {
                    resolved_by_ip.insert(ip_str.clone(), cached);
                } else {
                    missing_ips.push(ip_str.clone());
                }
            }
        } else {
            missing_ips.extend(batch.unique_ips.iter().cloned());
        }

        let mut dataset_version = String::new();

        if !missing_ips.is_empty() {
            let mut payload = HashMap::with_capacity(1);
            payload.insert("ips", &missing_ips);

            let resp = self
                .transport
                .request::<BatchLookupResponse, _>(
                    Method::POST,
                    "/v1/ip/batch",
                    Some(&payload),
                    &options.headers,
                    true,
                )
                .await?;

            dataset_version = resp.data.dataset_version;
            for (req_ip, item) in missing_ips.iter().zip(resp.data.results.into_iter()) {
                self.ip_cache.set(req_ip, item.clone());
                let canonical_lower = item.ip.to_lowercase();
                if &canonical_lower != req_ip {
                    self.ip_cache.set(&canonical_lower, item.clone());
                }
                resolved_by_ip.insert(req_ip.clone(), item);
            }
        }

        let mut ordered_results = Vec::with_capacity(batch.ordered_ips.len());
        for ip_str in &batch.ordered_ips {
            if let Some(item) = resolved_by_ip.get(ip_str) {
                ordered_results.push(item.clone());
            }
        }

        if dataset_version.is_empty() {
            if let Some(first) = ordered_results.first() {
                dataset_version = first.dataset_version.clone();
            }
        }

        Ok(BatchLookupResponse {
            dataset_version,
            count: ordered_results.len(),
            results: ordered_results,
        })
    }

    /// Performs a chunked batch lookup for `>100` IPs with bounded async concurrency.
    pub async fn lookup_batch_chunked<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
        concurrency: usize,
        options: &RequestOptions,
    ) -> Result<BatchLookupResponse, IpScopeError> {
        let batch = validate_and_deduplicate_batch_ips(raw_ips, 0)?;
        let effective_concurrency = concurrency.clamp(1, 16);
        let sem = Arc::new(Semaphore::new(effective_concurrency));

        let chunks: Vec<Vec<String>> = batch
            .unique_ips
            .chunks(MAX_SINGLE_BATCH_SIZE)
            .map(|c| c.to_vec())
            .collect();

        let resolved_by_ip: Arc<Mutex<HashMap<String, IpLookupResponse>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(batch.unique_ips.len())));
        let dataset_version: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let client = self.clone();
            let sem_clone = Arc::clone(&sem);
            let opts = options.clone();
            let resolved_clone = Arc::clone(&resolved_by_ip);
            let ds_clone = Arc::clone(&dataset_version);

            handles.push(tokio::spawn(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .map_err(|e| IpScopeError::Network {
                        path: "/v1/ip/batch".to_string(),
                        message: e.to_string(),
                    })?;
                let res = client.lookup_batch_with_options(&chunk, &opts).await?;
                if let Ok(mut ds) = ds_clone.lock() {
                    if ds.is_empty() && !res.dataset_version.is_empty() {
                        *ds = res.dataset_version.clone();
                    }
                }
                if let Ok(mut map) = resolved_clone.lock() {
                    for (req_ip, item) in chunk.iter().zip(res.results.into_iter()) {
                        map.insert(req_ip.clone(), item);
                    }
                }
                Ok::<(), IpScopeError>(())
            }));
        }

        for h in handles {
            let join_res = h.await.map_err(|e| IpScopeError::Network {
                path: "/v1/ip/batch".to_string(),
                message: format!("Batch worker task panicked: {e}"),
            })?;
            join_res?;
        }

        let map_guard = resolved_by_ip.lock().map_err(|_| IpScopeError::Network {
            path: "/v1/ip/batch".to_string(),
            message: "Mutex poisoned".to_string(),
        })?;
        let mut ordered_results = Vec::with_capacity(batch.ordered_ips.len());
        for ip_str in &batch.ordered_ips {
            if let Some(item) = map_guard.get(ip_str) {
                ordered_results.push(item.clone());
            }
        }
        let ds_ver = dataset_version
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        Ok(BatchLookupResponse {
            dataset_version: ds_ver,
            count: ordered_results.len(),
            results: ordered_results,
        })
    }

    /// Inspects canonical network prefix intelligence by CIDR notation (`GET /v1/networks/:prefix/:length`).
    pub async fn lookup_network(
        &self,
        raw_cidr: &str,
    ) -> Result<NetworkPrefixLookupResponse, IpScopeError> {
        let v_cidr = validate_cidr_prefix(raw_cidr)?;
        let (val, _) = self
            .network_cache
            .get_or_compute_async(&v_cidr.canonical_cidr, false, || async {
                let path = format!("/v1/networks/{}/{}", v_cidr.address, v_cidr.prefix_length);
                let resp = self
                    .transport
                    .request::<NetworkPrefixLookupResponse, ()>(
                        Method::GET,
                        &path,
                        None,
                        &HashMap::new(),
                        true,
                    )
                    .await?;
                Ok(resp.data)
            })
            .await?;
        Ok(val)
    }

    /// Lists active and historical dataset snapshot versions (`GET /v1/metadata/datasets`).
    pub async fn get_datasets_metadata(&self) -> Result<DatasetsMetadataResponse, IpScopeError> {
        let resp = self
            .transport
            .request::<DatasetsMetadataResponse, ()>(
                Method::GET,
                "/v1/metadata/datasets",
                None,
                &HashMap::new(),
                true,
            )
            .await?;
        Ok(resp.data)
    }

    /// Submits geolocation, ASN, or anonymity correction feedback (`POST /v1/feedback`).
    pub async fn submit_feedback(
        &self,
        mut feedback: FeedbackSubmissionInput,
    ) -> Result<FeedbackSubmissionResponse, IpScopeError> {
        let target = feedback.prefix_or_ip.trim().to_string();
        if target.contains('/') {
            validate_cidr_prefix(&target)?;
        } else {
            validate_ip_address(&target)?;
        }
        feedback.prefix_or_ip = target;

        let resp = self
            .transport
            .request::<FeedbackSubmissionResponse, _>(
                Method::POST,
                "/v1/feedback",
                Some(&feedback),
                &HashMap::new(),
                true,
            )
            .await?;
        Ok(resp.data)
    }

    /// Fetches public service health and active snapshot status (`GET /v1/status`).
    pub async fn get_status(&self) -> Result<ServiceStatusResponse, IpScopeError> {
        let resp = self
            .transport
            .request::<ServiceStatusResponse, ()>(
                Method::GET,
                "/v1/status",
                None,
                &HashMap::new(),
                false,
            )
            .await?;
        Ok(resp.data)
    }

    pub fn get_last_rate_limit(&self) -> Option<RateLimitMetadata> {
        self.transport.get_last_rate_limit()
    }

    pub fn get_cache_stats(&self) -> CacheStats {
        self.ip_cache.stats()
    }

    pub fn clear_cache(&self) {
        self.ip_cache.clear();
        self.network_cache.clear();
    }
}

/// Official Synchronous/Blocking Rust Server-Side Client (`reqwest::blocking::Client`).
#[derive(Clone)]
pub struct IpScopeClient {
    transport: Arc<SyncHttpTransport>,
    ip_cache: Arc<LruTtlCache<IpLookupResponse>>,
    network_cache: Arc<LruTtlCache<NetworkPrefixLookupResponse>>,
}

impl IpScopeClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self, IpScopeError> {
        IpScopeClientBuilder::new(api_key).build_sync()
    }

    pub fn builder(api_key: impl Into<String>) -> IpScopeClientBuilder {
        IpScopeClientBuilder::new(api_key)
    }

    /// Looks up intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/:ip`).
    pub fn lookup_ip(&self, raw_ip: &str) -> Result<IpLookupResponse, IpScopeError> {
        Ok(self
            .lookup_ip_with_meta(raw_ip, &RequestOptions::default())?
            .data)
    }

    pub fn lookup_ip_with_meta(
        &self,
        raw_ip: &str,
        options: &RequestOptions,
    ) -> Result<IpScopeResultWithMeta<IpLookupResponse>, IpScopeError> {
        let validated = validate_ip_address(raw_ip)?;
        let ip_str = validated.canonical_ip;

        if !options.bypass_cache {
            if let Some(cached) = self.ip_cache.get(&ip_str) {
                return Ok(IpScopeResultWithMeta {
                    data: cached,
                    status: 200,
                    rate_limit: self.transport.get_last_rate_limit().unwrap_or_default(),
                    from_cache: true,
                });
            }
        }

        let path = format!("/v1/ip/{ip_str}");
        let resp = self.transport.request::<IpLookupResponse, ()>(
            Method::GET,
            &path,
            None,
            &options.headers,
            true,
        )?;
        self.ip_cache.set(&ip_str, resp.data.clone());
        let canonical_lower = resp.data.ip.to_lowercase();
        if canonical_lower != ip_str {
            self.ip_cache.set(&canonical_lower, resp.data.clone());
        }

        Ok(IpScopeResultWithMeta {
            data: resp.data,
            status: resp.status,
            rate_limit: resp.rate_limit,
            from_cache: false,
        })
    }

    pub fn lookup_caller_ip(&self) -> Result<IpLookupResponse, IpScopeError> {
        let resp = self.transport.request::<IpLookupResponse, ()>(
            Method::GET,
            "/v1/ip/me",
            None,
            &HashMap::new(),
            true,
        )?;
        Ok(resp.data)
    }

    pub fn lookup_batch<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
    ) -> Result<BatchLookupResponse, IpScopeError> {
        self.lookup_batch_with_options(raw_ips, &RequestOptions::default())
    }

    pub fn lookup_batch_with_options<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
        options: &RequestOptions,
    ) -> Result<BatchLookupResponse, IpScopeError> {
        let batch = validate_and_deduplicate_batch_ips(raw_ips, MAX_SINGLE_BATCH_SIZE)?;

        let mut resolved_by_ip: HashMap<String, IpLookupResponse> =
            HashMap::with_capacity(batch.unique_ips.len());
        let mut missing_ips: Vec<String> = Vec::with_capacity(batch.unique_ips.len());

        if !options.bypass_cache {
            for ip_str in &batch.unique_ips {
                if let Some(cached) = self.ip_cache.get(ip_str) {
                    resolved_by_ip.insert(ip_str.clone(), cached);
                } else {
                    missing_ips.push(ip_str.clone());
                }
            }
        } else {
            missing_ips.extend(batch.unique_ips.iter().cloned());
        }

        let mut dataset_version = String::new();

        if !missing_ips.is_empty() {
            let mut payload = HashMap::with_capacity(1);
            payload.insert("ips", &missing_ips);

            let resp = self.transport.request::<BatchLookupResponse, _>(
                Method::POST,
                "/v1/ip/batch",
                Some(&payload),
                &options.headers,
                true,
            )?;

            dataset_version = resp.data.dataset_version;
            for (req_ip, item) in missing_ips.iter().zip(resp.data.results.into_iter()) {
                self.ip_cache.set(req_ip, item.clone());
                let canonical_lower = item.ip.to_lowercase();
                if &canonical_lower != req_ip {
                    self.ip_cache.set(&canonical_lower, item.clone());
                }
                resolved_by_ip.insert(req_ip.clone(), item);
            }
        }

        let mut ordered_results = Vec::with_capacity(batch.ordered_ips.len());
        for ip_str in &batch.ordered_ips {
            if let Some(item) = resolved_by_ip.get(ip_str) {
                ordered_results.push(item.clone());
            }
        }

        if dataset_version.is_empty() {
            if let Some(first) = ordered_results.first() {
                dataset_version = first.dataset_version.clone();
            }
        }

        Ok(BatchLookupResponse {
            dataset_version,
            count: ordered_results.len(),
            results: ordered_results,
        })
    }

    pub fn lookup_batch_chunked<S: AsRef<str>>(
        &self,
        raw_ips: &[S],
        options: &RequestOptions,
    ) -> Result<BatchLookupResponse, IpScopeError> {
        let batch = validate_and_deduplicate_batch_ips(raw_ips, 0)?;
        let mut resolved_by_ip: HashMap<String, IpLookupResponse> =
            HashMap::with_capacity(batch.unique_ips.len());
        let mut dataset_version = String::new();

        for chunk in batch.unique_ips.chunks(MAX_SINGLE_BATCH_SIZE) {
            let res = self.lookup_batch_with_options(chunk, options)?;
            if dataset_version.is_empty() && !res.dataset_version.is_empty() {
                dataset_version = res.dataset_version;
            }
            for (req_ip, item) in chunk.iter().zip(res.results.into_iter()) {
                resolved_by_ip.insert(req_ip.clone(), item);
            }
        }

        let mut ordered_results = Vec::with_capacity(batch.ordered_ips.len());
        for ip_str in &batch.ordered_ips {
            if let Some(item) = resolved_by_ip.get(ip_str) {
                ordered_results.push(item.clone());
            }
        }

        Ok(BatchLookupResponse {
            dataset_version,
            count: ordered_results.len(),
            results: ordered_results,
        })
    }

    /// Constant-RAM lazy iterator yielding [`BatchLookupResponse`] chunks of up to 100 IPs.
    pub fn lookup_batch_stream<'a, S: AsRef<str>>(
        &'a self,
        raw_ips: &'a [S],
        options: &'a RequestOptions,
    ) -> impl Iterator<Item = Result<BatchLookupResponse, IpScopeError>> + 'a {
        let is_empty = raw_ips.is_empty();
        let mut chunks_iter = raw_ips.chunks(MAX_SINGLE_BATCH_SIZE);
        let mut emitted_empty_err = false;

        std::iter::from_fn(move || {
            if is_empty {
                if !emitted_empty_err {
                    emitted_empty_err = true;
                    return Some(Err(IpScopeError::Validation {
                        field: "ips",
                        message: "Batch IPs slice must contain at least 1 IP address".to_string(),
                    }));
                }
                return None;
            }
            let chunk = chunks_iter.next()?;
            Some(self.lookup_batch_with_options(chunk, options))
        })
    }

    pub fn lookup_network(
        &self,
        raw_cidr: &str,
    ) -> Result<NetworkPrefixLookupResponse, IpScopeError> {
        let v_cidr = validate_cidr_prefix(raw_cidr)?;
        if let Some(cached) = self.network_cache.get(&v_cidr.canonical_cidr) {
            return Ok(cached);
        }
        let path = format!("/v1/networks/{}/{}", v_cidr.address, v_cidr.prefix_length);
        let resp = self.transport.request::<NetworkPrefixLookupResponse, ()>(
            Method::GET,
            &path,
            None,
            &HashMap::new(),
            true,
        )?;
        self.network_cache
            .set(&v_cidr.canonical_cidr, resp.data.clone());
        Ok(resp.data)
    }

    pub fn get_datasets_metadata(&self) -> Result<DatasetsMetadataResponse, IpScopeError> {
        let resp = self.transport.request::<DatasetsMetadataResponse, ()>(
            Method::GET,
            "/v1/metadata/datasets",
            None,
            &HashMap::new(),
            true,
        )?;
        Ok(resp.data)
    }

    pub fn submit_feedback(
        &self,
        mut feedback: FeedbackSubmissionInput,
    ) -> Result<FeedbackSubmissionResponse, IpScopeError> {
        let target = feedback.prefix_or_ip.trim().to_string();
        if target.contains('/') {
            validate_cidr_prefix(&target)?;
        } else {
            validate_ip_address(&target)?;
        }
        feedback.prefix_or_ip = target;

        let resp = self.transport.request::<FeedbackSubmissionResponse, _>(
            Method::POST,
            "/v1/feedback",
            Some(&feedback),
            &HashMap::new(),
            true,
        )?;
        Ok(resp.data)
    }

    pub fn get_status(&self) -> Result<ServiceStatusResponse, IpScopeError> {
        let resp = self.transport.request::<ServiceStatusResponse, ()>(
            Method::GET,
            "/v1/status",
            None,
            &HashMap::new(),
            false,
        )?;
        Ok(resp.data)
    }

    pub fn get_last_rate_limit(&self) -> Option<RateLimitMetadata> {
        self.transport.get_last_rate_limit()
    }

    pub fn get_cache_stats(&self) -> CacheStats {
        self.ip_cache.stats()
    }

    pub fn clear_cache(&self) {
        self.ip_cache.clear();
        self.network_cache.clear();
    }
}
