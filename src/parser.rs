// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-parser front end wiring the decode/scan pipeline.
//!
//! A [`Parser`] owns an [`ExternalEntityDecoder`] (byte → char, BOM/decl
//! detection, line-ending normalisation) and a [`Scanner`] (char → events).
//! Bytes go in via [`receive`](Parser::receive); [`close`](Parser::close)
//! finalises the document; [`reset`](Parser::reset) prepares for reuse.
//!
//! # Namespaces
//!
//! The [`Scanner`] is namespace-unaware: it reports `xmlns`/`xmlns:prefix` as
//! ordinary attributes. To get namespace events, wrap your handler in a
//! [`NamespaceFilter`](crate::namespace::NamespaceFilter) and pass
//! `&mut filter` as the handler:
//!
//! ```no_run
//! use tractrix::{DefaultHandler, FeatureSet, NamespaceFilter, Parser};
//!
//! let mut app = DefaultHandler;
//! let mut filter = NamespaceFilter::new(&mut app, false);
//! let features = FeatureSet::default();
//! let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
//! # let _ = &mut parser;
//! ```

use bytes::Bytes;

use crate::decoder::ExternalEntityDecoder;
use crate::entity::EntityResolver;
use crate::error::ParseResult;
use crate::features::FeatureSet;
use crate::handler::XmlHandler;
use crate::scanner::Scanner;

/// Streaming XML parser: bytes in, [`XmlHandler`] events out.
pub struct Parser<'a> {
    scanner: Scanner<'a>,
    decoder: ExternalEntityDecoder,
    closed: bool,
}

impl<'a> Parser<'a> {
    /// Builds a parser feeding `handler`.
    ///
    /// `handler` is the head of the event pipeline: pass your application
    /// handler directly for namespace-unaware parsing, or a
    /// [`NamespaceFilter`](crate::namespace::NamespaceFilter) wrapping it for
    /// namespace-aware parsing.
    pub fn new(
        handler: &'a mut dyn XmlHandler,
        features: &FeatureSet,
        entity_resolver: Option<Box<dyn EntityResolver>>,
        public_id: Option<String>,
        system_id: Option<String>,
    ) -> ParseResult<Self> {
        let settings = features.scanner_settings();
        let scanner = Scanner::new(
            handler,
            false,
            entity_resolver,
            public_id,
            system_id,
            features.validation,
            features.namespaces,
            settings,
            true,
        )?;
        Ok(Self {
            scanner,
            decoder: ExternalEntityDecoder::new(false),
            closed: false,
        })
    }

    /// Feeds a chunk of document bytes into the pipeline.
    pub fn receive(&mut self, data: Bytes) -> ParseResult<()> {
        self.decoder.receive(data, &mut self.scanner)
    }

    /// Signals end of input and finalises the document.
    pub fn close(&mut self) -> ParseResult<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.decoder.close(&mut self.scanner)
    }

    /// Resets the pipeline so the parser can be reused for a new document.
    pub fn reset(&mut self) {
        self.decoder.reset();
        self.scanner.reset();
        self.closed = false;
    }

    /// Convenience one-shot parse of a fully-buffered document.
    pub fn parse_all(&mut self, data: impl Into<Bytes>) -> ParseResult<()> {
        self.receive(data.into())?;
        self.close()
    }

    /// The XML version in effect (`"1.0"` or `"1.1"`).
    pub fn xml_version(&self) -> &'static str {
        self.scanner.xml_version()
    }

    /// The detected/declared character encoding, if known yet.
    pub fn encoding(&self) -> Option<&str> {
        self.scanner.get_encoding()
    }

    /// Whether the document declared `standalone="yes"`.
    pub fn is_standalone(&self) -> bool {
        self.scanner.is_standalone()
    }

    /// Exploratory (explore/utf8-byte-path): whether the decoder confirmed
    /// genuine UTF-8. Not public API — an internal hook for milestone-one
    /// detection tests, ahead of anything actually using it.
    #[cfg(test)]
    pub(crate) fn is_utf8_confirmed(&self) -> bool {
        self.scanner.is_utf8_confirmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureSet;
    use crate::handler::DefaultHandler;

    fn detect(bytes: &'static [u8]) -> bool {
        let mut app = DefaultHandler;
        let features = FeatureSet::default();
        let mut parser = Parser::new(&mut app, &features, None, None, None).unwrap();
        parser.parse_all(Bytes::from_static(bytes)).unwrap();
        parser.is_utf8_confirmed()
    }

    #[test]
    fn utf8_confirmed_with_no_signal_at_all() {
        // No BOM, no declaration at all — the XML-spec default is UTF-8.
        assert!(detect(b"<root/>"));
    }

    #[test]
    fn utf8_confirmed_with_explicit_declaration() {
        assert!(detect(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>"));
    }

    #[test]
    fn utf8_confirmed_with_utf8_bom() {
        assert!(detect(b"\xEF\xBB\xBF<root/>"));
    }

    #[test]
    fn utf8_confirmed_false_for_declared_latin1() {
        assert!(!detect(b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root/>"));
    }

    #[test]
    fn utf8_confirmed_false_for_utf16_bom() {
        // UTF-16LE BOM, "<root/>" as UTF-16LE code units.
        let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
        for c in "<root/>".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let mut app = DefaultHandler;
        let features = FeatureSet::default();
        let mut parser = Parser::new(&mut app, &features, None, None, None).unwrap();
        parser.parse_all(Bytes::from(bytes)).unwrap();
        assert!(!parser.is_utf8_confirmed());
    }
}
