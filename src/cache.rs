//! Concurrency-safe LRU + TTL cache with RAII-guarded singleflight request coalescing.

use crate::error::IpScopeError;
use crate::types::{CacheOptions, CacheStats};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
    generation: u64,
}

struct LruState<V> {
    entries: HashMap<String, CacheEntry<V>>,
    order: VecDeque<(String, u64)>,
    next_gen: u64,
}

impl<V> LruState<V> {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            next_gen: 1,
        }
    }
}

pub(crate) struct LruTtlCache<V: Clone + Send + Sync + 'static> {
    enabled: bool,
    max_entries: usize,
    ttl: Duration,
    state: Mutex<LruState<V>>,
    in_flight: Arc<Mutex<HashMap<String, watch::Receiver<Option<Result<V, IpScopeError>>>>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    coalesced_hits: AtomicU64,
}

struct InFlightGuard<V: Clone + Send + Sync + 'static> {
    key: String,
    in_flight: Arc<Mutex<HashMap<String, watch::Receiver<Option<Result<V, IpScopeError>>>>>>,
}

impl<V: Clone + Send + Sync + 'static> Drop for InFlightGuard<V> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.in_flight.lock() {
            guard.remove(&self.key);
        }
    }
}

impl<V: Clone + Send + Sync + 'static> LruTtlCache<V> {
    pub(crate) fn new(opts: CacheOptions) -> Self {
        let max_entries = opts.max_entries.max(1);
        let ttl = if opts.ttl.is_zero() {
            Duration::from_secs(60)
        } else {
            opts.ttl
        };
        Self {
            enabled: opts.enabled,
            max_entries,
            ttl,
            state: Mutex::new(LruState::new(max_entries.min(512))),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            coalesced_hits: AtomicU64::new(0),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<V> {
        if !self.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let now = Instant::now();
        let mut guard = self.state.lock().ok()?;
        let is_expired = match guard.entries.get(key) {
            Some(entry) => now >= entry.expires_at,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        if is_expired {
            guard.entries.remove(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let gen = guard.next_gen;
        guard.next_gen = guard.next_gen.wrapping_add(1);
        let val = if let Some(entry) = guard.entries.get_mut(key) {
            entry.generation = gen;
            entry.value.clone()
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        guard.order.push_back((key.to_string(), gen));
        Self::compact_queue_if_needed(&mut guard, self.max_entries);
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(val)
    }

    pub(crate) fn set(&self, key: &str, value: V) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let Ok(mut guard) = self.state.lock() else {
            return;
        };

        if !guard.entries.contains_key(key) {
            while guard.entries.len() >= self.max_entries {
                let Some((old_key, old_gen)) = guard.order.pop_front() else {
                    break;
                };
                if let Some(existing) = guard.entries.get(&old_key) {
                    if existing.generation == old_gen || now >= existing.expires_at {
                        guard.entries.remove(&old_key);
                    }
                }
            }
        }

        let gen = guard.next_gen;
        guard.next_gen = guard.next_gen.wrapping_add(1);
        guard.entries.insert(
            key.to_string(),
            CacheEntry {
                value,
                expires_at: now + self.ttl,
                generation: gen,
            },
        );
        guard.order.push_back((key.to_string(), gen));
        Self::compact_queue_if_needed(&mut guard, self.max_entries);
    }

    pub(crate) async fn get_or_compute_async<F, Fut>(
        &self,
        key: &str,
        bypass_cache: bool,
        producer: F,
    ) -> Result<(V, bool), IpScopeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, IpScopeError>>,
    {
        if !bypass_cache {
            if let Some(cached) = self.get(key) {
                return Ok((cached, true));
            }

            let existing_rx = {
                let guard = self.in_flight.lock().ok();
                guard.and_then(|g| g.get(key).cloned())
            };

            if let Some(mut rx) = existing_rx {
                self.coalesced_hits.fetch_add(1, Ordering::Relaxed);
                while rx.borrow().is_none() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                if let Some(res) = rx.borrow().clone() {
                    return res.map(|v| (v, true));
                }
            }

            let (tx, rx) = watch::channel(None);
            if let Ok(mut guard) = self.in_flight.lock() {
                guard.insert(key.to_string(), rx);
            }
            let _cleanup_guard = InFlightGuard {
                key: key.to_string(),
                in_flight: Arc::clone(&self.in_flight),
            };

            let result = producer().await;
            if let Ok(ref val) = result {
                self.set(key, val.clone());
            }
            let _ = tx.send(Some(result.clone()));
            return result.map(|v| (v, false));
        }

        let val = producer().await?;
        Ok((val, false))
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.entries.clear();
            guard.order.clear();
        }
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.clear();
        }
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.coalesced_hits.store(0, Ordering::Relaxed);
    }

    pub(crate) fn stats(&self) -> CacheStats {
        let size = self.state.lock().map(|g| g.entries.len()).unwrap_or(0);
        CacheStats {
            enabled: self.enabled,
            size,
            max_entries: self.max_entries,
            ttl: self.ttl,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            coalesced_in_flight_hits: self.coalesced_hits.load(Ordering::Relaxed),
        }
    }

    fn compact_queue_if_needed(guard: &mut LruState<V>, max_entries: usize) {
        if guard.order.len() > max_entries.saturating_mul(4).max(64) {
            guard.order.retain(|(k, g)| {
                guard
                    .entries
                    .get(k)
                    .map(|e| e.generation == *g)
                    .unwrap_or(false)
            });
        }
    }
}
