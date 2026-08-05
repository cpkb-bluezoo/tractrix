// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Name interning pool.
//!
//! Ported from Gonzalez `PackedName.java`.
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
use std::rc::Rc;

/// Zero-allocation-on-hit interning pool for short, name-like strings
/// (element/attribute names, PI targets). Mirrors Gonzalez `PackedName`.
///
/// Stores `Rc<str>` rather than `String` so a cache hit is a refcount bump,
/// not a full string copy — element/attribute names repeat constantly in
/// real documents, so hits are the common case this is optimizing for.
#[derive(Debug, Default)]
pub struct PackedName {
    pool: HashSet<Rc<str>>,
    /// Reused across `intern_range` calls as the lookup key, so a cache hit
    /// (the common case — names repeat constantly) allocates nothing at
    /// all: only a genuine miss pays for `Rc::from`, which is the one
    /// allocation actually storing a new distinct name.
    scratch: String,
}

impl PackedName {
    pub fn new() -> Self {
        Self {
            pool: HashSet::with_capacity(512),
            scratch: String::new(),
        }
    }

    /// Interns a name from a character-array range, returning a canonical
    /// `Rc<str>`. Mirrors `PackedName.internRange`.
    pub fn intern_range(&mut self, buf: &[char], start: usize, len: usize) -> Rc<str> {
        self.scratch.clear();
        self.scratch.extend(buf[start..start + len].iter().copied());
        if let Some(existing) = self.pool.get(self.scratch.as_str()) {
            return Rc::clone(existing);
        }
        let owned: Rc<str> = Rc::from(self.scratch.as_str());
        self.pool.insert(Rc::clone(&owned));
        owned
    }

    /// Interns a `&str`, returning a canonical `Rc<str>`.
    pub fn intern_str(&mut self, s: &str) -> Rc<str> {
        if let Some(existing) = self.pool.get(s) {
            return Rc::clone(existing);
        }
        let owned: Rc<str> = Rc::from(s);
        self.pool.insert(Rc::clone(&owned));
        owned
    }
}

