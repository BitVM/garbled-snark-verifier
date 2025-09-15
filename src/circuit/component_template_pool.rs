use std::{
    collections::HashMap,
    hash::{BuildHasher, Hasher},
};

use slab::Slab;

use super::{component_key::ComponentKey, component_meta::ComponentMetaTemplate};

/// Maximum number of templates to keep in memory.
const DEFAULT_CAPACITY: usize = 5_000;

#[derive(Debug)]
struct Entry {
    key_u64: u64,
    value: ComponentMetaTemplate,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Single-threaded LRU pool for component templates (by entry count).
/// - Keys are 8-byte arrays mapped to `u64` for compact, fast hashing.
/// - Operations are O(1): get promotes to MRU; insert evicts LRU on overflow.
#[derive(Debug)]
pub struct ComponentTemplatePool {
    map: HashMap<u64, usize, IdentityBuildHasher>,
    entries: Slab<Entry>,
    head: Option<usize>, // MRU
    tail: Option<usize>, // LRU
    capacity: usize,
}

impl ComponentTemplatePool {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");
        Self {
            map: HashMap::with_hasher(IdentityBuildHasher),
            entries: Slab::with_capacity(capacity),
            head: None,
            tail: None,
            capacity,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.entries.clear();
        self.head = None;
        self.tail = None;
    }

    /// Get and promote to MRU.
    pub fn get(&mut self, key: &ComponentKey) -> Option<&ComponentMetaTemplate> {
        let k = key_to_u64(*key);
        let idx = *self.map.get(&k)?;
        self.move_to_front(idx);
        // Safe: idx still valid
        Some(&self.entries[idx].value)
    }

    /// Insert or update; returns old value if present.
    pub fn insert(
        &mut self,
        key: ComponentKey,
        value: ComponentMetaTemplate,
    ) -> Option<ComponentMetaTemplate> {
        let k = key_to_u64(key);
        if let Some(&idx) = self.map.get(&k) {
            // Update value, promote to front
            let old = std::mem::replace(&mut self.entries[idx].value, value);
            self.move_to_front(idx);
            return Some(old);
        }

        // Evict if at capacity
        if self.len() >= self.capacity {
            self.evict_lru();
        }

        let idx = self.entries.insert(Entry {
            key_u64: k,
            value,
            prev: None,
            next: None,
        });
        self.attach_to_front(idx);
        self.map.insert(k, idx);
        None
    }

    /// Cache-through: on miss, build via `make` and insert; returns a reference to the value.
    pub fn get_or_insert_with<F>(&mut self, key: ComponentKey, make: F) -> &ComponentMetaTemplate
    where
        F: FnOnce() -> ComponentMetaTemplate,
    {
        let k = key_to_u64(key);
        if let Some(&idx) = self.map.get(&k) {
            self.move_to_front(idx);
            return &self.entries[idx].value;
        }

        if self.len() >= self.capacity {
            self.evict_lru();
        }

        let value = make();
        let idx = self.entries.insert(Entry {
            key_u64: k,
            value,
            prev: None,
            next: None,
        });
        self.attach_to_front(idx);
        self.map.insert(k, idx);
        &self.entries[idx].value
    }

    fn move_to_front(&mut self, idx: usize) {
        // Detach
        let (prev, next);
        {
            let e = &self.entries[idx];
            prev = e.prev;
            next = e.next;
        }

        if prev.is_none() {
            // Already head
            return;
        }

        // Update neighbors
        if let Some(p) = prev {
            self.entries[p].next = next;
        }
        if let Some(n) = next {
            self.entries[n].prev = prev;
        } else {
            // Was tail
            self.tail = prev;
        }

        // Attach to front
        self.entries[idx].prev = None;
        self.entries[idx].next = self.head;
        if let Some(h) = self.head {
            self.entries[h].prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx);
        }
    }

    fn attach_to_front(&mut self, idx: usize) {
        self.entries[idx].prev = None;
        self.entries[idx].next = self.head;
        if let Some(h) = self.head {
            self.entries[h].prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx);
        }
    }

    fn evict_lru(&mut self) {
        if let Some(lru_idx) = self.tail {
            // Detach lru_idx
            let prev = self.entries[lru_idx].prev;
            if let Some(p) = prev {
                self.entries[p].next = None;
            } else {
                // LRU was also head
                self.head = None;
            }
            self.tail = prev;

            let key = self.entries[lru_idx].key_u64;
            self.map.remove(&key);
            self.entries.remove(lru_idx);
        }
    }
}

impl Default for ComponentTemplatePool {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn key_to_u64(k: ComponentKey) -> u64 {
    u64::from_le_bytes(k)
}

// Identity hasher for u64 keys: avoids SipHash overhead on hot path
#[derive(Default, Clone)]
struct IdentityBuildHasher;

struct IdentityHasher(u64);

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;
    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher(0)
    }
}

impl Hasher for IdentityHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // FNV-1a for generic bytes (not used for u64 keys in practice)
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        self.0 = h;
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(i: u64) -> ComponentKey {
        i.to_le_bytes()
    }

    fn tmpl_empty() -> ComponentMetaTemplate {
        // Build an empty template using the public API
        super::super::component_meta::ComponentMetaBuilder::new(0).build(&[])
    }

    #[test]
    fn basic_put_get_and_eviction() {
        let mut pool = ComponentTemplatePool::with_capacity(2);
        pool.insert(make_key(1), tmpl_empty());
        pool.insert(make_key(2), tmpl_empty());
        assert_eq!(pool.len(), 2);

        // Touch 1 to make it MRU
        assert!(pool.get(&make_key(1)).is_some());

        // Insert 3 -> evict LRU (which should be key 2)
        pool.insert(make_key(3), tmpl_empty());
        assert!(pool.get(&make_key(2)).is_none());
        assert!(pool.get(&make_key(1)).is_some());
        assert!(pool.get(&make_key(3)).is_some());
    }

    #[test]
    fn get_or_insert_with_promotes() {
        let mut pool = ComponentTemplatePool::with_capacity(2);
        let _ = pool.get_or_insert_with(make_key(10), tmpl_empty);
        let _ = pool.get_or_insert_with(make_key(11), tmpl_empty);

        // Access 10 so it becomes MRU, then insert 12 and ensure 11 is evicted
        let _ = pool.get(&make_key(10));
        let _ = pool.get_or_insert_with(make_key(12), tmpl_empty);

        assert!(pool.get(&make_key(11)).is_none());
        assert!(pool.get(&make_key(10)).is_some());
        assert!(pool.get(&make_key(12)).is_some());
    }
}
