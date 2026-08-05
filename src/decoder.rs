// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Byte-to-character decoding for the scanner input pipeline.
//!
//! Ported from Gonzalez `BOM.java`, `ReadResult.java`, `DeclParser.java`,
//! `XMLDeclParser.java`, `TextDeclParser.java`, `ExternalEntityDecoder.java`,
//! and `XmlDeclUtil.java`.
//!
//! Charset decoding uses `encoding_rs` for everything it supports; UTF-32
//! (which `encoding_rs` does not implement) is decoded manually.

use std::borrow::Cow;

use bytes::Bytes;
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8};

use crate::error::ParseResult;
use crate::scanner::Scanner;

// ===== BOM =====

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bom {
    None,
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Bom {
    #[allow(dead_code)]
    fn bytes_per_char(self) -> usize {
        match self {
            Bom::None | Bom::Utf8 => 1,
            Bom::Utf16Le | Bom::Utf16Be => 2,
            Bom::Utf32Le | Bom::Utf32Be => 4,
        }
    }

    fn requires_charset_validation(self) -> bool {
        self != Bom::None
    }
}

/// One 7-bit ASCII read result from a declaration byte stream.
enum Rc {
    Ch(u8),
    Underflow,
    NonAscii,
}

/// Reads the next 7-bit ASCII character starting at `bytes[pos]`, advancing
/// `pos`. Mirrors `BOM.nextChar`.
fn read_char(bytes: &[u8], pos: &mut usize, bom: Bom) -> Rc {
    let len = bytes.len();
    match bom {
        Bom::None | Bom::Utf8 => {
            if *pos >= len {
                return Rc::Underflow;
            }
            let b = bytes[*pos];
            *pos += 1;
            if b > 0x7F {
                Rc::NonAscii
            } else {
                Rc::Ch(b)
            }
        }
        Bom::Utf16Le => {
            if *pos + 2 > len {
                return Rc::Underflow;
            }
            let lo = bytes[*pos];
            let hi = bytes[*pos + 1];
            *pos += 2;
            if hi != 0 || lo > 0x7F {
                Rc::NonAscii
            } else {
                Rc::Ch(lo)
            }
        }
        Bom::Utf16Be => {
            if *pos + 2 > len {
                return Rc::Underflow;
            }
            let hi = bytes[*pos];
            let lo = bytes[*pos + 1];
            *pos += 2;
            if hi != 0 || lo > 0x7F {
                Rc::NonAscii
            } else {
                Rc::Ch(lo)
            }
        }
        Bom::Utf32Le => {
            if *pos + 4 > len {
                return Rc::Underflow;
            }
            let b0 = bytes[*pos];
            let b1 = bytes[*pos + 1];
            let b2 = bytes[*pos + 2];
            let b3 = bytes[*pos + 3];
            *pos += 4;
            if b1 != 0 || b2 != 0 || b3 != 0 || b0 > 0x7F {
                Rc::NonAscii
            } else {
                Rc::Ch(b0)
            }
        }
        Bom::Utf32Be => {
            if *pos + 4 > len {
                return Rc::Underflow;
            }
            let b0 = bytes[*pos];
            let b1 = bytes[*pos + 1];
            let b2 = bytes[*pos + 2];
            let b3 = bytes[*pos + 3];
            *pos += 4;
            if b0 != 0 || b1 != 0 || b2 != 0 || b3 > 0x7F {
                Rc::NonAscii
            } else {
                Rc::Ch(b3)
            }
        }
    }
}

// ===== Declaration parsing =====

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadResult {
    Ok,
    Failure,
    Underflow,
}

#[derive(Default)]
struct DeclInfo {
    version: Option<String>,
    encoding: Option<String>,
    standalone: Option<bool>,
    bytes_consumed: usize,
}

fn is_ws(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r' || c == b'\n'
}

fn is_invalid_in_decl_value(c: u8) -> bool {
    is_ws(c) || c == b'<' || c == b'>' || c == b'?'
}

fn try_read(bytes: &[u8], pos: &mut usize, bom: Bom, test: &str) -> ReadResult {
    for expected in test.bytes() {
        match read_char(bytes, pos, bom) {
            Rc::NonAscii => return ReadResult::Failure,
            Rc::Underflow => return ReadResult::Underflow,
            Rc::Ch(c) => {
                if c != expected {
                    return ReadResult::Failure;
                }
            }
        }
    }
    ReadResult::Ok
}

fn peek_char(bytes: &[u8], pos: usize, bom: Bom) -> Rc {
    let mut p = pos;
    read_char(bytes, &mut p, bom)
}

fn require_whitespace(bytes: &[u8], pos: &mut usize, bom: Bom) -> ReadResult {
    match peek_char(bytes, *pos, bom) {
        Rc::NonAscii => return ReadResult::Failure,
        Rc::Underflow => return ReadResult::Underflow,
        Rc::Ch(c) => {
            if !is_ws(c) {
                return ReadResult::Failure;
            }
        }
    }
    read_char(bytes, pos, bom); // consume first
    loop {
        match peek_char(bytes, *pos, bom) {
            Rc::Ch(c) if is_ws(c) => {
                read_char(bytes, pos, bom);
            }
            _ => return ReadResult::Ok,
        }
    }
}

fn ignore_whitespace(bytes: &[u8], pos: &mut usize, bom: Bom) {
    loop {
        match peek_char(bytes, *pos, bom) {
            Rc::Ch(c) if is_ws(c) => {
                read_char(bytes, pos, bom);
            }
            _ => return,
        }
    }
}

fn try_read_attribute(
    bytes: &[u8],
    pos: &mut usize,
    bom: Bom,
    name: &str,
    out: &mut Option<String>,
) -> ReadResult {
    let saved = *pos;
    match require_whitespace(bytes, pos, bom) {
        ReadResult::Underflow => return ReadResult::Underflow,
        ReadResult::Failure => {
            *pos = saved;
            return ReadResult::Failure;
        }
        ReadResult::Ok => {}
    }
    match try_read(bytes, pos, bom, name) {
        ReadResult::Underflow => return ReadResult::Underflow,
        ReadResult::Failure => {
            *pos = saved;
            return ReadResult::Failure;
        }
        ReadResult::Ok => {}
    }
    ignore_whitespace(bytes, pos, bom);
    match try_read(bytes, pos, bom, "=") {
        ReadResult::Underflow => return ReadResult::Underflow,
        ReadResult::Failure => {
            *pos = saved;
            return ReadResult::Failure;
        }
        ReadResult::Ok => {}
    }
    ignore_whitespace(bytes, pos, bom);
    let quote = match read_char(bytes, pos, bom) {
        Rc::NonAscii => {
            *pos = saved;
            return ReadResult::Failure;
        }
        Rc::Underflow => return ReadResult::Underflow,
        Rc::Ch(c) => c,
    };
    if quote != b'"' && quote != b'\'' {
        *pos = saved;
        return ReadResult::Failure;
    }
    let other = if quote == b'"' { b'\'' } else { b'"' };
    let mut val = String::new();
    loop {
        let c = match read_char(bytes, pos, bom) {
            Rc::NonAscii => {
                *pos = saved;
                return ReadResult::Failure;
            }
            Rc::Underflow => return ReadResult::Underflow,
            Rc::Ch(c) => c,
        };
        if c == quote {
            *out = Some(val);
            return ReadResult::Ok;
        } else if c == other || is_invalid_in_decl_value(c) {
            *pos = saved;
            return ReadResult::Failure;
        } else {
            val.push(c as char);
        }
    }
}

fn is_valid_version_number(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    let dot = match v.find('.') {
        Some(i) => i,
        None => return false,
    };
    if dot == 0 || dot >= v.len() - 1 {
        return false;
    }
    v[..dot].bytes().all(|c| c.is_ascii_digit()) && v[dot + 1..].bytes().all(|c| c.is_ascii_digit())
}

/// Parses an XML declaration (document entity). Mirrors `XMLDeclParser`.
fn parse_xml_decl(bytes: &[u8], bom: Bom) -> (ReadResult, DeclInfo) {
    let mut info = DeclInfo::default();
    let mut pos = 0usize;
    match try_read(bytes, &mut pos, bom, "<?xml") {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    match try_read_attribute(bytes, &mut pos, bom, "version", &mut info.version) {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    if try_read_attribute(bytes, &mut pos, bom, "encoding", &mut info.encoding) == ReadResult::Underflow { return (ReadResult::Underflow, info) }
    let mut sd: Option<String> = None;
    if try_read_attribute(bytes, &mut pos, bom, "standalone", &mut sd) == ReadResult::Underflow { return (ReadResult::Underflow, info) }
    ignore_whitespace(bytes, &mut pos, bom);
    match try_read(bytes, &mut pos, bom, "?>") {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    let version = match &info.version {
        None => return (ReadResult::Failure, info),
        Some(v) => v.clone(),
    };
    if !is_valid_version_number(&version) || !version.starts_with("1.") {
        return (ReadResult::Failure, info);
    }
    if let Some(s) = &sd {
        if s != "yes" && s != "no" {
            return (ReadResult::Failure, info);
        }
        info.standalone = Some(s == "yes");
    }
    info.bytes_consumed = pos;
    (ReadResult::Ok, info)
}

/// Parses a text declaration (external parsed entity). Mirrors `TextDeclParser`.
fn parse_text_decl(bytes: &[u8], bom: Bom) -> (ReadResult, DeclInfo) {
    let mut info = DeclInfo::default();
    let mut pos = 0usize;
    match try_read(bytes, &mut pos, bom, "<?xml") {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    if try_read_attribute(bytes, &mut pos, bom, "version", &mut info.version) == ReadResult::Underflow { return (ReadResult::Underflow, info) }
    match try_read_attribute(bytes, &mut pos, bom, "encoding", &mut info.encoding) {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    ignore_whitespace(bytes, &mut pos, bom);
    match try_read(bytes, &mut pos, bom, "?>") {
        ReadResult::Failure => return (ReadResult::Failure, info),
        ReadResult::Underflow => return (ReadResult::Underflow, info),
        ReadResult::Ok => {}
    }
    if let Some(v) = &info.version {
        if !is_valid_version_number(v) || !v.starts_with("1.") {
            return (ReadResult::Failure, info);
        }
    }
    if info.encoding.is_none() {
        return (ReadResult::Failure, info);
    }
    info.bytes_consumed = pos;
    (ReadResult::Ok, info)
}

// ===== Charset engine =====

enum Charset {
    Enc(&'static Encoding),
    Utf32Le,
    Utf32Be,
    Utf16Le,
    Utf16Be,
    Latin1,
}

impl Charset {
    fn name(&self) -> String {
        match self {
            Charset::Enc(e) => e.name().to_string(),
            Charset::Utf32Le => "UTF-32LE".to_string(),
            Charset::Utf32Be => "UTF-32BE".to_string(),
            Charset::Utf16Le => "UTF-16LE".to_string(),
            Charset::Utf16Be => "UTF-16BE".to_string(),
            Charset::Latin1 => "ISO-8859-1".to_string(),
        }
    }
}

enum DecodeEngine {
    Enc(encoding_rs::Decoder),
    Utf32 { little_endian: bool, rem: Vec<u8> },
    Latin1,
}

fn charset_for_label(name: &str) -> Option<Charset> {
    let normalized: String = name
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .collect();
    if normalized == "UTF32LE" {
        return Some(Charset::Utf32Le);
    }
    if normalized == "UTF32BE" {
        return Some(Charset::Utf32Be);
    }
    // encoding_rs maps ISO-8859-1 to windows-1252 per WHATWG, but XML requires
    // true Latin-1 (byte N → U+00N) so that C1 controls remain distinct.
    if normalized == "ISO88591" || normalized == "LATIN1" || normalized == "L1"
        || normalized == "CSISOLATIN1" || normalized == "ISOIR100"
    {
        return Some(Charset::Latin1);
    }
    Encoding::for_label(name.as_bytes()).map(Charset::Enc)
}

// ===== ExternalEntityDecoder =====

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    SeenBom,
    Content,
    Closed,
}

/// Decodes a streaming byte source into characters and feeds a [`Scanner`].
///
/// Ported from `ExternalEntityDecoder.java`. The caller (see
/// [`crate::parser::Parser`]) owns both this decoder and the scanner and
/// passes the scanner into [`receive`](Self::receive)/[`close`](Self::close).
pub struct ExternalEntityDecoder {
    charset: Option<Charset>,
    bom: Bom,
    is_external_entity: bool,
    xml11: bool,
    state: State,
    /// Accumulated bytes not yet consumed while detecting BOM/declaration.
    prelude: Vec<u8>,
    engine: Option<DecodeEngine>,
    last_char: char,
    had_incomplete: bool,
}

impl ExternalEntityDecoder {
    pub fn new(is_external_entity: bool) -> Self {
        Self {
            charset: None,
            bom: Bom::None,
            is_external_entity,
            xml11: false,
            state: State::Init,
            prelude: Vec::new(),
            engine: None,
            last_char: '\u{0}',
            had_incomplete: false,
        }
    }

    pub fn reset(&mut self) {
        self.charset = None;
        self.bom = Bom::None;
        self.xml11 = false;
        self.state = State::Init;
        self.prelude.clear();
        self.engine = None;
        self.last_char = '\u{0}';
        self.had_incomplete = false;
    }

    pub fn receive(&mut self, data: Bytes, scanner: &mut Scanner<'_>) -> ParseResult<()> {
        if self.state == State::Closed {
            return Err(scanner.fatal_error("Decoder is closed"));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.advance(&data, false, scanner)
    }

    pub fn close(&mut self, scanner: &mut Scanner<'_>) -> ParseResult<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        // Flush: finalize BOM/decl detection with whatever we have, then
        // flush the decoder.
        let empty = Bytes::new();
        self.advance(&empty, true, scanner)?;
        if self.had_incomplete {
            let name = self
                .charset
                .as_ref()
                .map(|c| c.name())
                .unwrap_or_else(|| "unknown".to_string());
            return Err(scanner.fatal_error(&format!(
                "Unexpected end of input: incomplete byte sequence in encoding {name} at end of stream"
            )));
        }
        scanner.close()?;
        self.state = State::Closed;
        Ok(())
    }

    fn advance(&mut self, data: &[u8], is_final: bool, scanner: &mut Scanner<'_>) -> ParseResult<()> {
        if self.state == State::Init || self.state == State::SeenBom {
            self.prelude.extend_from_slice(data);
            // BOM detection
            if self.state == State::Init
                && !self.parse_bom(is_final) {
                    return Ok(());
                }
            // Declaration parsing
            if self.state == State::SeenBom {
                if !self.parse_declaration(is_final, scanner)? {
                    return Ok(());
                }
                // Now in CONTENT; feed leftover prelude.
                let leftover = std::mem::take(&mut self.prelude);
                return self.feed_content(&leftover, is_final, scanner);
            }
            return Ok(());
        }
        // CONTENT
        self.feed_content(data, is_final, scanner)
    }

    /// Mirrors `parseBOM`; returns true when detection is complete.
    fn parse_bom(&mut self, is_final: bool) -> bool {
        let b = &self.prelude;
        let n = b.len();
        let consumed;
        if n < 2 {
            if !is_final {
                return false;
            }
            // Not enough for a BOM; treat as none.
            self.bom = Bom::None;
            self.state = State::SeenBom;
            return true;
        }
        let b0 = b[0];
        let b1 = b[1];
        if b0 == 0xFE && b1 == 0xFF {
            self.bom = Bom::Utf16Be;
            consumed = 2;
        } else if b0 == 0xFF && b1 == 0xFE {
            if n < 4 {
                if !is_final {
                    return false;
                }
                self.bom = Bom::Utf16Le;
                consumed = 2;
            } else if b[2] == 0x00 && b[3] == 0x00 {
                self.bom = Bom::Utf32Le;
                consumed = 4;
            } else {
                self.bom = Bom::Utf16Le;
                consumed = 2;
            }
        } else if b0 == 0x00 && b1 == 0x00 {
            if n < 4 {
                if !is_final {
                    return false;
                }
                self.bom = Bom::None;
                consumed = 0;
            } else if b[2] == 0xFE && b[3] == 0xFF {
                self.bom = Bom::Utf32Be;
                consumed = 4;
            } else {
                self.bom = Bom::None;
                consumed = 0;
            }
        } else if b0 == 0xEF && b1 == 0xBB {
            if n < 3 {
                if !is_final {
                    return false;
                }
                self.bom = Bom::None;
                consumed = 0;
            } else if b[2] == 0xBF {
                self.bom = Bom::Utf8;
                consumed = 3;
            } else {
                self.bom = Bom::None;
                consumed = 0;
            }
        } else {
            self.bom = Bom::None;
            consumed = 0;
        }
        self.prelude.drain(..consumed);
        self.state = State::SeenBom;
        true
    }

    /// Mirrors `parseDeclaration`; returns true when parsing is complete
    /// (declaration consumed or confirmed absent), false if more data needed.
    fn parse_declaration(&mut self, is_final: bool, scanner: &mut Scanner<'_>) -> ParseResult<bool> {
        let bytes = self.prelude.clone();
        let (result, info) = if self.is_external_entity {
            parse_text_decl(&bytes, self.bom)
        } else {
            parse_xml_decl(&bytes, self.bom)
        };
        match result {
            ReadResult::Underflow => {
                if !is_final {
                    return Ok(false);
                }
                // No declaration; use default charset.
                self.setup_charset_decoder(None, scanner)?;
                self.state = State::Content;
                Ok(true)
            }
            ReadResult::Failure => {
                self.setup_charset_decoder(None, scanner)?;
                self.state = State::Content;
                Ok(true)
            }
            ReadResult::Ok => {
                if let Some(v) = &info.version {
                    let entity_xml11 = v == "1.1";
                    self.xml11 = entity_xml11;
                    scanner.set_xml11(entity_xml11);
                }
                if let Some(sd) = info.standalone {
                    scanner.set_standalone(sd);
                }
                self.setup_charset_decoder(info.encoding.as_deref(), scanner)?;
                self.prelude.drain(..info.bytes_consumed);
                self.state = State::Content;
                Ok(true)
            }
        }
    }

    fn setup_charset_decoder(
        &mut self,
        decl_encoding: Option<&str>,
        scanner: &mut Scanner<'_>,
    ) -> ParseResult<()> {
        let charset: Charset = if let Some(name) = decl_encoding {
            let mut cs = match charset_for_label(name) {
                Some(c) => c,
                None => {
                    return Err(
                        scanner.fatal_error(&format!("Invalid or unsupported encoding: {name}"))
                    );
                }
            };
            if self.bom.requires_charset_validation() {
                self.validate_bom_encoding_compat(name, scanner)?;
                let normalized: String = name
                    .to_ascii_uppercase()
                    .chars()
                    .filter(|c| *c != '-' && *c != '_')
                    .collect();
                if !normalized.ends_with("LE") && !normalized.ends_with("BE") {
                    cs = self.bom_default_charset();
                }
            }
            cs
        } else {
            self.bom_default_charset()
        };
        scanner.set_encoding(&charset.name());
        self.engine = Some(match &charset {
            Charset::Utf16Le => DecodeEngine::Enc(UTF_16LE.new_decoder_without_bom_handling()),
            Charset::Utf16Be => DecodeEngine::Enc(UTF_16BE.new_decoder_without_bom_handling()),
            Charset::Enc(e) => DecodeEngine::Enc(e.new_decoder_without_bom_handling()),
            Charset::Utf32Le => DecodeEngine::Utf32 {
                little_endian: true,
                rem: Vec::new(),
            },
            Charset::Utf32Be => DecodeEngine::Utf32 {
                little_endian: false,
                rem: Vec::new(),
            },
            Charset::Latin1 => DecodeEngine::Latin1,
        });
        self.charset = Some(charset);
        Ok(())
    }

    fn bom_default_charset(&self) -> Charset {
        match self.bom {
            Bom::None | Bom::Utf8 => Charset::Enc(UTF_8),
            Bom::Utf16Le => Charset::Utf16Le,
            Bom::Utf16Be => Charset::Utf16Be,
            Bom::Utf32Le => Charset::Utf32Le,
            Bom::Utf32Be => Charset::Utf32Be,
        }
    }

    fn validate_bom_encoding_compat(&self, decl: &str, scanner: &mut Scanner<'_>) -> ParseResult<()> {
        let n: String = decl
            .to_ascii_uppercase()
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .collect();
        let bad = match self.bom {
            Bom::Utf16Be | Bom::Utf16Le => !n.contains("UTF16"),
            Bom::Utf32Be | Bom::Utf32Le => !n.contains("UTF32"),
            Bom::Utf8 => n.starts_with("UTF16") || n.starts_with("UTF32"),
            Bom::None => false,
        };
        if bad {
            return Err(scanner.fatal_error(&format!(
                "Encoding '{decl}' is incompatible with the detected BOM"
            )));
        }
        Ok(())
    }

    fn feed_content(&mut self, bytes: &[u8], last: bool, scanner: &mut Scanner<'_>) -> ParseResult<()> {
        let mut decoded = String::new();
        match self.engine.as_mut().unwrap() {
            DecodeEngine::Enc(dec) => {
                // Reserve a generous capacity; decode in one shot (encoding_rs
                // buffers partial trailing sequences internally across calls).
                // decode_to_string appends rather than replacing, and
                // `decoded` starts empty, so decoding straight into it is
                // equivalent to the old decode-into-`out`-then-push_str —
                // minus a full copy of every chunk's content.
                decoded.reserve(bytes.len() + 16);
                let (_res, _read, had_errors) = dec.decode_to_string(bytes, &mut decoded, last);
                if had_errors {
                    if last {
                        // Incomplete trailing sequence at EOF.
                        self.had_incomplete = true;
                    } else {
                        return Err(scanner
                            .fatal_error("Malformed byte sequence in the document's character encoding"));
                    }
                }
            }
            DecodeEngine::Utf32 { little_endian, rem } => {
                let le = *little_endian;
                rem.extend_from_slice(bytes);
                let full_groups = rem.len() / 4;
                for i in 0..full_groups {
                    let g = &rem[i * 4..i * 4 + 4];
                    let cp = if le {
                        u32::from_le_bytes([g[0], g[1], g[2], g[3]])
                    } else {
                        u32::from_be_bytes([g[0], g[1], g[2], g[3]])
                    };
                    match char::from_u32(cp) {
                        Some(c) => decoded.push(c),
                        None => {
                            return Err(scanner.fatal_error(&format!(
                                "Invalid UTF-32 code point U+{cp:X}"
                            )));
                        }
                    }
                }
                rem.drain(..full_groups * 4);
                if last && !rem.is_empty() {
                    self.had_incomplete = true;
                }
            }
            DecodeEngine::Latin1 => {
                decoded.reserve(bytes.len());
                for &b in bytes {
                    decoded.push(b as char);
                }
            }
        }
        if decoded.is_empty() {
            return Ok(());
        }
        let normalized = self.normalize_line_endings(&decoded);
        if !normalized.is_empty() {
            scanner.receive(&normalized)?;
        }
        Ok(())
    }

    fn normalize_line_endings<'s>(&mut self, s: &'s str) -> Cow<'s, str> {
        // The overwhelmingly common case is a chunk with no '\r' (and, in
        // non-XML-1.1 documents, no NEL/LS either) and no CR/LF pair split
        // across the previous chunk boundary — nothing to rewrite, so skip
        // building a whole new String and hand the input straight through.
        let crlf_split_at_boundary = self.last_char == '\r' && s.starts_with('\n');
        let needs_rewrite = crlf_split_at_boundary
            || s.contains('\r')
            || (self.xml11 && (s.contains('\u{85}') || s.contains('\u{2028}')));
        if !needs_rewrite {
            if let Some(c) = s.chars().next_back() {
                self.last_char = c;
            }
            return Cow::Borrowed(s);
        }
        let mut out = String::with_capacity(s.len());
        let mut last = self.last_char;
        for c in s.chars() {
            if c == '\r' {
                out.push('\n');
            } else if c == '\n' && last == '\r' {
                // CR LF pair: drop the LF (CR already converted).
            } else if self.xml11 && (c == '\u{85}' || c == '\u{2028}') {
                out.push('\n');
            } else {
                out.push(c);
            }
            last = c;
        }
        self.last_char = last;
        Cow::Owned(out)
    }
}

// ===== XmlDeclUtil equivalents (one-shot, fully-buffered) =====

/// One-shot BOM + declared-encoding aware decode of a fully-buffered external
/// resource. Mirrors `XmlDeclUtil.decodeBytes`.
pub fn decode_bytes(bytes: &[u8], encoding_hint: Option<&str>) -> Vec<char> {
    let (charset, bom_len): (Charset, usize) = if bytes.len() >= 3
        && bytes[0] == 0xEF
        && bytes[1] == 0xBB
        && bytes[2] == 0xBF
    {
        (Charset::Enc(UTF_8), 3)
    } else if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0xFE && bytes[3] == 0xFF {
        (Charset::Utf32Be, 4)
    } else if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xFE && bytes[2] == 0x00 && bytes[3] == 0x00 {
        (Charset::Utf32Le, 4)
    } else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        (Charset::Utf16Be, 2)
    } else if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        (Charset::Utf16Le, 2)
    } else {
        let declared = sniff_declared_encoding(bytes);
        let cs = declared
            .and_then(|d| charset_for_label(&d))
            .or_else(|| encoding_hint.and_then(charset_for_label))
            .unwrap_or(Charset::Enc(UTF_8));
        (cs, 0)
    };
    let body = &bytes[bom_len..];
    let s = match &charset {
        Charset::Latin1 => {
            body.iter().map(|&b| b as char).collect::<String>()
        }
        Charset::Enc(e) => e.decode(body).0.into_owned(),
        Charset::Utf16Le | Charset::Utf16Be => {
            let be = matches!(charset, Charset::Utf16Be);
            let mut out = String::with_capacity(body.len() / 2);
            let mut i = 0;
            while i + 1 < body.len() {
                let cu = if be {
                    u16::from_be_bytes([body[i], body[i + 1]])
                } else {
                    u16::from_le_bytes([body[i], body[i + 1]])
                };
                i += 2;
                if (0xD800..=0xDBFF).contains(&cu) {
                    if i + 1 < body.len() {
                        let lo = if be {
                            u16::from_be_bytes([body[i], body[i + 1]])
                        } else {
                            u16::from_le_bytes([body[i], body[i + 1]])
                        };
                        if (0xDC00..=0xDFFF).contains(&lo) {
                            i += 2;
                            let cp = 0x10000 + ((cu as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00);
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        } else {
                            out.push('\u{FFFD}');
                        }
                    } else {
                        out.push('\u{FFFD}');
                    }
                } else if (0xDC00..=0xDFFF).contains(&cu) {
                    out.push('\u{FFFD}');
                } else {
                    out.push(char::from_u32(cu as u32).unwrap_or('\u{FFFD}'));
                }
            }
            out
        }
        Charset::Utf32Le | Charset::Utf32Be => {
            let le = matches!(charset, Charset::Utf32Le);
            let mut out = String::with_capacity(body.len() / 4);
            let groups = body.len() / 4;
            for i in 0..groups {
                let g = &body[i * 4..i * 4 + 4];
                let cp = if le {
                    u32::from_le_bytes([g[0], g[1], g[2], g[3]])
                } else {
                    u32::from_be_bytes([g[0], g[1], g[2], g[3]])
                };
                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            }
            out
        }
    };
    s.chars().collect()
}

fn sniff_declared_encoding(bytes: &[u8]) -> Option<String> {
    let limit = bytes.len().min(200);
    let prefix: String = bytes[..limit].iter().map(|&b| b as char).collect();
    if !prefix.starts_with("<?xml") {
        return None;
    }
    let decl = match prefix.find("?>") {
        Some(i) => &prefix[..i],
        None => &prefix[..],
    };
    let idx = decl.find("encoding")?;
    let eq = decl[idx..].find('=')? + idx;
    let after = &decl[eq + 1..];
    let after = after.trim_start();
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Extracts the `version` pseudo-attribute of a leading `<?xml ...?>`.
/// Mirrors `XmlDeclUtil.extractVersionNum`.
pub fn extract_version_num(chars: &[char]) -> Option<String> {
    let limit = chars.len().min(200);
    let prefix: String = chars[..limit].iter().collect();
    if !prefix.starts_with("<?xml") {
        return None;
    }
    let decl = match prefix.find("?>") {
        Some(i) => &prefix[..i],
        None => &prefix[..],
    };
    let idx = index_of_pseudo_attribute(decl, "version")?;
    let eq = decl[idx..].find('=')? + idx;
    let after = decl[eq + 1..].trim_start();
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn index_of_pseudo_attribute(decl: &str, name: &str) -> Option<usize> {
    let bytes: Vec<char> = decl.chars().collect();
    let name_chars: Vec<char> = name.chars().collect();
    let mut idx = 0usize;
    let s: String = bytes.iter().collect();
    while let Some(found) = s[idx..].find(name) {
        let pos = idx + found;
        // Convert byte position to char index within `bytes` for boundary checks.
        let char_pos = s[..pos].chars().count();
        let preceded_ok = char_pos == 0 || bytes[char_pos - 1].is_whitespace();
        let after = char_pos + name_chars.len();
        let followed_ok =
            after >= bytes.len() || bytes[after].is_whitespace() || bytes[after] == '=';
        if preceded_ok && followed_ok {
            return Some(char_pos);
        }
        idx = pos + name.len();
    }
    None
}

/// Strips a leading `<?xml ...?>` text declaration from a fetched external
/// entity/DTD subset. Mirrors `XmlDeclUtil.stripXmlDeclaration`.
///
/// Returns `Err(message)` on a malformed/illegal declaration; the caller
/// reports it as a fatal error.
pub fn strip_xml_declaration(all: &[char]) -> Result<Vec<char>, String> {
    let mut start = 0usize;
    if all.len() > 5
        && all[0] == '<'
        && all[1] == '?'
        && all[2] == 'x'
        && all[3] == 'm'
        && all[4] == 'l'
    {
        let mut j = 5usize;
        while j + 1 < all.len() && !(all[j] == '?' && all[j + 1] == '>') {
            j += 1;
        }
        if j + 1 >= all.len() {
            return Err("Malformed XML declaration: missing closing \"?>\"".to_string());
        }
        let span: String = all[5..j].iter().collect();
        if index_of_pseudo_attribute(&span, "standalone").is_some() {
            return Err("A text declaration may not have a \"standalone\" pseudo-attribute - that is only legal on the main document's own XML declaration".to_string());
        }
        let version_idx = index_of_pseudo_attribute(&span, "version");
        let encoding_idx = index_of_pseudo_attribute(&span, "encoding");
        if encoding_idx.is_none() {
            return Err("A text declaration must have an \"encoding\" pseudo-attribute (TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>')".to_string());
        }
        if let (Some(vi), Some(ei)) = (version_idx, encoding_idx) {
            if ei < vi {
                return Err("A text declaration's \"version\" pseudo-attribute, if present, must come before \"encoding\" (TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>')".to_string());
            }
        }
        start = j + 2;
        while start < all.len() && (all[start] == '\n' || all[start] == '\r') {
            start += 1;
        }
    }
    Ok(all[start..].to_vec())
}
