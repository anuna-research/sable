//! Bounded transient storage using a monotonic clock.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub(crate) struct TtlCache<T> {
    entries: HashMap<String, (Instant, T)>,
    capacity: usize,
    ttl: Duration,
}

impl<T> TtlCache<T> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self { entries: HashMap::new(), capacity, ttl }
    }

    pub fn insert(&mut self, key: String, value: T) -> Result<(), String> {
        self.retain(|_, _| true);
        if self.entries.len() >= self.capacity || self.entries.contains_key(&key) {
            return Err("Transient storage full or identifier already exists".into());
        }
        self.entries.insert(key, (Instant::now(), value));
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.entries.get(key).filter(|(created, _)| created.elapsed() < self.ttl).map(|(_, value)| value)
    }

    pub fn remove(&mut self, key: &str) -> Option<T> {
        self.entries.remove(key).filter(|(created, _)| created.elapsed() < self.ttl).map(|(_, value)| value)
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&String, &T) -> bool) {
        self.entries.retain(|key, (created, value)| created.elapsed() < self.ttl && keep(key, value));
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn count_prefix(&self, prefix: &str) -> usize {
        self.entries.iter().filter(|(key, (created, _))| key.starts_with(prefix) && created.elapsed() < self.ttl).count()
    }
    pub fn contains_key(&self, key: &str) -> bool { self.get(key).is_some() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[test]
    fn capacity_expiry_and_single_use_are_enforced() {
        let mut cache = TtlCache::new(1, Duration::from_secs(30));
        cache.insert("first".into(), 1).unwrap();
        assert!(cache.insert("second".into(), 2).is_err());
        assert!(cache.insert("first".into(), 3).is_err());
        assert_eq!(cache.remove("first"), Some(1));
        assert_eq!(cache.remove("first"), None);
        cache.insert("second".into(), 2).unwrap();
        cache.entries.get_mut("second").unwrap().0 = Instant::now() - Duration::from_secs(31);
        assert_eq!(cache.get("second"), None);
        assert_eq!(cache.remove("second"), None);
        cache.insert("third".into(), 3).unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn periodic_eviction_drops_sensitive_values() {
        struct Secret(Arc<AtomicUsize>);
        impl Drop for Secret {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut cache = TtlCache::new(1, Duration::ZERO);
        cache.insert("secret".into(), Secret(drops.clone())).unwrap();
        cache.retain(|_, _| true);
        assert_eq!(cache.len(), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
