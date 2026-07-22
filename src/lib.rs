// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Tractrix — a non-blocking, push-model XML parser.
//!
//! Tractrix is a Rust port of the Gonzalez streaming XML scanner. It accepts
//! document bytes incrementally and emits structural events into an
//! [`XmlHandler`] with no intermediate token stream and minimal allocation.
//!
//! # Pipeline
//!
//! ```text
//! bytes ──▶ ExternalEntityDecoder ──▶ Scanner ──▶ (NamespaceFilter?) ──▶ XmlHandler
//!            (BOM, XML/text decl,        (WF + DTD        (xmlns → namespace
//!             charset, line endings)      + validation)    events)
//! ```
//!
//! The high-level entry point is [`Parser`]. See its docs for a namespace-aware
//! example.
//!
//! # Feature summary
//!
//! - XML 1.0 and XML 1.1 well-formedness
//! - Internal and external DTD subsets, parameter entities, conditional
//!   sections
//! - Optional validation against the DTD (element content models, attribute
//!   types/defaults, ID/IDREF, notations, standalone constraints)
//! - Encoding detection via BOM and XML/text declarations, decoding through
//!   `encoding_rs` (plus manual UTF-32)

pub mod decoder;
pub mod dtd;
pub mod entity;
pub mod error;
pub mod features;
pub mod handler;
pub mod locator;
pub mod names;
pub mod namespace;
pub mod parser;
pub mod scanner;

pub use decoder::ExternalEntityDecoder;
pub use entity::{
    EntityResolver, ExternalId, FileEntityResolver, RefusingEntityResolver, ResolvedEntity,
};
pub use error::{FeatureError, ParseError, ParseResult};
pub use features::{FeatureSet, PropertyValue, ScannerSettings};
pub use handler::{DefaultHandler, XmlHandler};
pub use locator::{DocumentLocator, Locator};
pub use namespace::{NamespaceFilter, NamespaceScopeTracker, XMLNS_NAMESPACE_URI, XML_NAMESPACE_URI};
pub use parser::Parser;
pub use scanner::Scanner;
