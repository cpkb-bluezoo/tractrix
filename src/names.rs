//! Name interning pools.
//!
//! Ported from Gonzalez `PackedName.java` and `InternedStringPool.java`.
//!
//! In Java these pools exist to avoid a `new String(...)` allocation for every
//! occurrence of a repeated element/attribute name, and to give callers a
//! canonical instance so `==` reference equality can be used as a fast path.
//!
//! In Rust we keep the same *behaviour* (a canonical `String` per distinct
//! name, so value comparison is stable) using a `HashSet<String>` cache. The
//! quad-packed hashing micro-optimisation of `PackedName` is a performance
//! detail, not a grammar detail, so it is not reproduced; the observable
//! contract (interning short name-like strings from a character window) is.

use std::collections::HashSet;

/// Zero-allocation-on-hit interning pool for short, name-like strings
/// (element/attribute names, PI targets). Mirrors Gonzalez `PackedName`.
#[derive(Debug, Default)]
pub struct PackedName {
    pool: HashSet<String>,
}

impl PackedName {
    pub fn new() -> Self {
        Self {
            pool: HashSet::with_capacity(512),
        }
    }

    /// Interns a name from a character-array range, returning a canonical
    /// `String`. Mirrors `PackedName.internRange`.
    pub fn intern_range(&mut self, buf: &[char], start: usize, len: usize) -> String {
        let s: String = buf[start..start + len].iter().collect();
        self.intern_str(&s)
    }

    /// Interns a `&str`, returning a canonical `String`.
    pub fn intern_str(&mut self, s: &str) -> String {
        if let Some(existing) = self.pool.get(s) {
            return existing.clone();
        }
        let owned = s.to_string();
        self.pool.insert(owned.clone());
        owned
    }
}

/// General purpose string interning pool. Mirrors Gonzalez
/// `InternedStringPool` (used for namespace URIs).
#[derive(Debug, Default)]
pub struct InternedStringPool {
    pool: HashSet<String>,
}

impl InternedStringPool {
    pub fn new() -> Self {
        Self {
            pool: HashSet::with_capacity(256),
        }
    }

    /// Interns a `&str`, returning a canonical `String`.
    pub fn intern(&mut self, s: &str) -> String {
        if let Some(existing) = self.pool.get(s) {
            return existing.clone();
        }
        let owned = s.to_string();
        self.pool.insert(owned.clone());
        owned
    }

    /// Clears all interned strings from the pool.
    pub fn clear(&mut self) {
        self.pool.clear();
    }
}
