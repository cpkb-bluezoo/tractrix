// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hot-path XML scanner.
//!
//! Ported from Gonzalez `Scanner.java`. Recognises element start/end tags,
//! attributes, text, character/entity references, comments, PIs, CDATA, and
//! DOCTYPE declarations (internal and external subsets), emitting directly
//! into an [`XmlHandler`] with no intermediate token stream.
//!
//! Byte-to-char decoding/line-ending normalisation happen upstream in
//! [`crate::decoder`]; namespace resolution happens downstream in
//! [`crate::namespace`]. This scanner is namespace-unaware: it always reports
//! `xmlns` as a plain attribute.

use std::collections::{HashMap, HashSet};
use std::ops::{Index, IndexMut, Range};
use std::rc::Rc;

use bytes::{Buf, BufMut, BytesMut};

use crate::decoder;
use crate::dtd::{
    ContentModel, ContentModelValidator, ContentType, DtdModel, ElementDeclaration, Mode, NodeType,
    Occurrence,
};
use crate::entity::{EntityResolver, ExternalId};
use crate::error::{ParseError, ParseResult};
use crate::features::{DoctypeHandling, ScannerSettings};
use crate::handler::XmlHandler;
use crate::locator::DocumentLocator;
use crate::names::PackedName;

const INITIAL_CAPACITY: usize = 8192;

/// Exploratory (explore/utf8-byte-path): the scanner's canonical input
/// storage. Which variant is active is decided once, at charset-detection
/// time (`ExternalEntityDecoder::setup_charset_decoder`), and never
/// changes mid-document — `self.pos`/`self.limit` are byte offsets when
/// `Bytes` is active, char indices when `Chars` is active.
///
/// `Index`/`IndexMut` are implemented directly on this type so every
/// existing `self.buf[i]`/`self.buf[a..b]` call site in the current
/// char-based scanning code keeps compiling completely unchanged — only
/// the non-indexing operations (`.len()`, `.resize()`, buffer swaps, etc.)
/// need to go through `as_chars()`/`as_chars_mut()` explicitly. New
/// byte-native sibling functions go through `as_bytes()`/`as_bytes_mut()`
/// instead.
enum ScanBuffer {
    /// Confirmed genuine UTF-8: raw bytes, scanned directly, no decode
    /// pass. `BytesMut` (not `Vec<u8>`) specifically because its `reserve`
    /// only shifts/reallocates when actually necessary — unlike the
    /// current char path's `append`, which shifts unconditionally — and
    /// growing it never needs a zero-fill the way `Vec<char>` does (`u8`
    /// has no invalid bit pattern; `char` does).
    Bytes(BytesMut),
    /// Any other charset: already decoded by `ExternalEntityDecoder`,
    /// exactly as today.
    Chars(Vec<char>),
}

impl ScanBuffer {
    fn as_chars(&self) -> &Vec<char> {
        match self {
            ScanBuffer::Chars(c) => c,
            ScanBuffer::Bytes(_) => unreachable!("scanner is in byte mode"),
        }
    }

    fn as_chars_mut(&mut self) -> &mut Vec<char> {
        match self {
            ScanBuffer::Chars(c) => c,
            ScanBuffer::Bytes(_) => unreachable!("scanner is in byte mode"),
        }
    }

    #[allow(dead_code)]
    fn as_bytes(&self) -> &BytesMut {
        match self {
            ScanBuffer::Bytes(b) => b,
            ScanBuffer::Chars(_) => unreachable!("scanner is in char mode"),
        }
    }

    #[allow(dead_code)]
    fn as_bytes_mut(&mut self) -> &mut BytesMut {
        match self {
            ScanBuffer::Bytes(b) => b,
            ScanBuffer::Chars(_) => unreachable!("scanner is in char mode"),
        }
    }
}

impl Index<usize> for ScanBuffer {
    type Output = char;
    fn index(&self, i: usize) -> &char {
        &self.as_chars()[i]
    }
}

impl IndexMut<usize> for ScanBuffer {
    fn index_mut(&mut self, i: usize) -> &mut char {
        &mut self.as_chars_mut()[i]
    }
}

impl Index<Range<usize>> for ScanBuffer {
    type Output = [char];
    fn index(&self, r: Range<usize>) -> &[char] {
        &self.as_chars()[r]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KwResult {
    Match,
    NoMatch,
    NeedMore,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
enum RefResult {
    NeedMore,
    Decoded(String),
    General(String),
}

/// External general entity identifiers: `(publicId, systemId, ndataName)`.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
struct ExtEntity {
    public_id: Option<String>,
    system_id: Option<String>,
    ndata: Option<String>,
}

/// External parameter entity identifiers: `(publicId, systemId, declBase)`.
#[derive(Clone, Debug)]
struct ExtPe {
    public_id: Option<String>,
    system_id: Option<String>,
    decl_base: Option<String>,
}

/// The four "pending" declaration maps threaded through DTD parsing, mirroring
/// the Java method parameters of the same names.
#[derive(Default)]
struct PendingDecls {
    entities: HashMap<String, Rc<[char]>>,
    external_names: HashMap<String, ExtEntity>,
    param_entities: HashMap<String, Rc<[char]>>,
    param_external_names: HashMap<String, ExtPe>,
}

// Markup keyword literals.
const DOCTYPE_MARKER: &str = "<!DOCTYPE";
const SYSTEM_MARKER: &str = "SYSTEM";
const PUBLIC_MARKER: &str = "PUBLIC";
const NDATA_MARKER: &str = "NDATA";
const ENTITY_MARKER: &str = "<!ENTITY";
const ATTLIST_MARKER: &str = "<!ATTLIST";
const ELEMENT_MARKER: &str = "<!ELEMENT";
const EMPTY_MARKER: &str = "EMPTY";
const ANY_MARKER: &str = "ANY";
const PCDATA_MARKER: &str = "#PCDATA";
const REQUIRED_MARKER: &str = "#REQUIRED";
const IMPLIED_MARKER: &str = "#IMPLIED";
const FIXED_MARKER: &str = "#FIXED";
const INCLUDE_MARKER: &str = "INCLUDE";
const IGNORE_MARKER: &str = "IGNORE";
const NOTATION_MARKER: &str = "<!NOTATION";
const CDATA_MARKER: &str = "<![CDATA[";

/// Streaming XML scanner. See module docs.
pub struct Scanner<'a> {
    handler: &'a mut dyn XmlHandler,
    locator: DocumentLocator,
    encoding: Option<String>,
    /// Set once the decoder has confirmed the document's bytes are genuine
    /// UTF-8 (explicit `encoding="UTF-8"`, a UTF-8 BOM, or no signal at all
    /// — the XML-spec default) — see ExternalEntityDecoder::setup_charset_decoder.
    /// Exploratory: not yet acted on by the scanner itself, this is step
    /// one of the parallel UTF-8 byte-path work (see explore/utf8-byte-path).
    utf8_confirmed: bool,
    document_started: bool,
    defer_document_start_until_encoding: bool,

    buf: ScanBuffer,
    pos: usize,
    limit: usize,
    /// Reused across `slice_and` calls to avoid a fresh allocation for
    /// every text/attribute-value/comment/PI/CDATA chunk.
    scratch: String,

    in_start_tag: bool,
    in_attribute_value: bool,
    pending_quote: char,
    attr_value_run_open: bool,

    normalizing_current_attribute: bool,
    collapse_current_attr_value: bool,
    normalize_builder: String,
    current_attr_element_name: String,
    current_attr_name: String,
    current_attr_type: String,

    content_run_open: bool,
    content_run_is_whitespace: bool,
    content_bracket_run: i32,

    element_stack: Vec<Rc<str>>,
    validator_stack: Option<Vec<ContentModelValidator>>,

    seen_attribute_names: Vec<Rc<str>>,

    name_pool: PackedName,

    root_started: bool,
    root_ended: bool,
    doctype_seen: bool,
    doctype_name: Option<String>,

    in_doctype: bool,
    doctype_subset_closed: bool,
    doctype_name_pending: Option<String>,
    doctype_pending: Option<PendingDecls>,

    // `DoctypeHandling::Skip` resumable state (see skip_doctype_subset_inner).
    in_skipped_declaration: bool,
    skip_decl_quote: Option<char>,

    doctype_external_public_id: Option<String>,
    doctype_external_system_id: Option<String>,
    doctype_public_id: Option<String>,
    doctype_system_id: Option<String>,

    general_entities: HashMap<String, Rc<[char]>>,
    /// Memoizes `expand_general_entity_in_attribute_value`'s result per
    /// entity name: a general entity's normalized attribute-value text
    /// (nested references resolved, whitespace collapsed) is identical on
    /// every reference, so recomputing it from scratch each time is pure
    /// waste — for an entity nested N levels deep, that waste compounds
    /// multiplicatively with the number of references at the outermost
    /// level. `check_entity_referenceable` (including its expansion-count
    /// limit and recursive-reference check) still runs on every reference,
    /// cached or not — only the expensive recursive rebuild is skipped.
    attribute_entity_cache: HashMap<String, Rc<str>>,
    /// Memoizes whether a general entity's content-context expansion
    /// (nested references resolved, but NOT character-legality-checked --
    /// the real recursive scan still does that, over this precomputed
    /// text instead of the raw declared text) can be fully flattened to
    /// plain text ahead of time. `None` means "contains markup (or is
    /// external, or otherwise not flattenable) -- always use the real
    /// per-reference recursive scan for this entity." Only populated for
    /// `!self.xml11` documents (see `flatten_content_entity_cached`'s doc
    /// comment for why XML 1.1 opts out).
    content_entity_cache: HashMap<String, Option<Rc<[char]>>>,
    /// Byte-path counterpart to `content_entity_cache`: caches the same
    /// flattened text pre-*encoded* to UTF-8, so a byte-mode document
    /// referencing the same entity repeatedly skips the chars -> UTF-8
    /// encode step too, not just the nested-reference resolution that
    /// `content_entity_cache` already avoids redoing. Built lazily off of
    /// `content_entity_cache` (encoded once, on first byte-path use of a
    /// given name), not populated in lockstep with it.
    content_entity_byte_cache: HashMap<String, Option<Rc<str>>>,
    external_entity_names: HashMap<String, ExtEntity>,
    parameter_entities: HashMap<String, Rc<[char]>>,
    parameter_entity_external_ids: HashMap<String, ExtPe>,

    parameter_entity_expansion_stack: Vec<String>,
    entity_expansion_stack: Vec<String>,
    entity_stack_floors: Vec<usize>,
    entity_expansion_count: i64,

    parsing_external_content: bool,
    xml11: bool,

    entity_resolver: Option<Box<dyn EntityResolver>>,
    base_system_id: Option<String>,

    validation_enabled: bool,
    namespace_aware: bool,
    settings: ScannerSettings,

    standalone: bool,

    restricted_char_entities: HashSet<String>,
    externally_declared_general_entities: HashSet<String>,
    allow_restricted_char_in_content: bool,

    last_literal_contained_restricted_char: bool,
    last_char_ref_code_point: u32,

    last_external_id_public_id: Option<String>,
    last_external_id_system_id: Option<String>,

    declared_notations: HashSet<String>,
    notation_external_ids: HashMap<String, ExternalId>,

    dtd_model: DtdModel,

    last_enumeration_values: Option<Vec<String>>,

    // Content model parse cursor.
    cm_pos: usize,
    cm_end: usize,

    in_pi: bool,
    in_comment: bool,
    in_cdata: bool,
    cdata_run_open: bool,

    saw_internal_subset_parameter_entity_reference: bool,

    last_resolved_system_id: Option<String>,

    last_pe_reference_end: usize,
    last_splice_end: i64,
    saw_splice_since_declaration_start: bool,
    last_param_entity_was_external: bool,

    declared_ids: Option<HashSet<String>>,
    pending_idrefs: Option<Vec<String>>,
}

// ===== Character classification =====

/// Exploratory (explore/utf8-byte-path): outcome of one byte-native
/// content-run scan. See `Scanner::scan_content_run_bytes`.
#[derive(Debug, PartialEq, Eq)]
enum ContentRunBytes {
    /// Reached a structural stop byte (`<` or `&`).
    Stop,
    /// No more buffered bytes, or a trailing multi-byte sequence that
    /// isn't fully buffered yet — wait for the next chunk.
    NeedMore,
    /// Ill-formed UTF-8, or a codepoint that isn't a legal literal XML
    /// character and isn't covered by the restricted-char-in-content
    /// carve-out.
    Illegal,
}

/// Exploratory (explore/utf8-byte-path): outcome of one byte-native
/// attribute-value run scan. See `Scanner::scan_attr_value_run_bytes`.
#[derive(Debug, PartialEq, Eq)]
enum AttrValueRunBytes {
    /// Reached the closing quote.
    Quote,
    /// Reached `&` — an entity/character reference to resolve.
    Amp,
    /// No more buffered bytes, or a trailing multi-byte sequence that
    /// isn't fully buffered yet.
    NeedMore,
    /// `<` appeared in the attribute value (always a fatal WF error),
    /// ill-formed UTF-8, or an illegal literal character.
    Illegal,
}

/// Exploratory (explore/utf8-byte-path): outcome of one call to
/// `Scanner::scan_attribute_value_streaming_bytes`.
#[derive(Debug, PartialEq, Eq)]
enum AttrValueScanBytes {
    /// Reached the closing quote; the full value has been emitted to the
    /// handler already.
    Done,
    /// No more buffered bytes; wait for the next chunk.
    NeedMore,
}

/// Exploratory (explore/utf8-byte-path): outcome of one call to
/// `Scanner::scan_name_chars_bytes`.
#[derive(Debug, PartialEq, Eq)]
enum NameScanBytes {
    /// Ran off the end of a legal NameChar run; the `usize` is the
    /// position just past it (mirrors `p` in the char-based loops).
    End(usize),
    /// No more buffered bytes; wait for the next chunk.
    NeedMore,
    /// Hit invalid UTF-8 mid-name.
    Illegal,
}

/// Exploratory (explore/utf8-byte-path): outcome of one call to
/// `Scanner::scan_until_byte_bytes`, carrying the position reached either
/// way (unlike `ContentRunBytes`/`AttrValueRunBytes`, callers here need
/// the in-progress position on `NeedMore` too, to emit a partial run).
#[derive(Debug, PartialEq, Eq)]
enum LiteralUntilBytes {
    Stop(usize),
    NeedMore(usize),
}

/// Exploratory (explore/utf8-byte-path): total byte length of the UTF-8
/// sequence starting with lead byte `b` (2-4), or 0 if `b` isn't a valid
/// lead byte (e.g. a stray continuation byte).
#[allow(dead_code)]
fn utf8_seq_len(b: u8) -> usize {
    if b & 0b1110_0000 == 0b1100_0000 {
        2
    } else if b & 0b1111_0000 == 0b1110_0000 {
        3
    } else if b & 0b1111_1000 == 0b1111_0000 {
        4
    } else {
        0
    }
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

fn is_restricted_char_xml11(c: char) -> bool {
    let u = c as u32;
    (0x1..=0x8).contains(&u)
        || (0xB..=0xC).contains(&u)
        || (0xE..=0x1F).contains(&u)
        || (0x7F..=0x84).contains(&u)
        || (0x86..=0x9F).contains(&u)
}

fn is_legal_literal_char_xml10(c: char) -> bool {
    let u = c as u32;
    u == 0x9
        || u == 0xA
        || u == 0xD
        || (0x20..=0xD7FF).contains(&u)
        || (0xE000..=0xFFFD).contains(&u)
        || (0x10000..=0x10FFFF).contains(&u)
}

fn is_legal_literal_char_xml11(c: char) -> bool {
    let u = c as u32;
    if (0x1..=0xD7FF).contains(&u) {
        return !is_restricted_char_xml11(c);
    }
    (0xE000..=0xFFFD).contains(&u) || (0x10000..=0x10FFFF).contains(&u)
}

fn is_name_start_char(c: char) -> bool {
    // ASCII names (letters, plus ':'/'_') are overwhelmingly the common
    // case, and every character below this range is definitionally
    // excluded from all the ranges checked below — so for any ASCII
    // input, whether it matches or not, there's nothing left to check.
    if c.is_ascii() {
        return c == ':' || c == '_' || c.is_ascii_alphabetic();
    }
    let u = c as u32;
    (0xC0..=0xD6).contains(&u)
        || (0xD8..=0xF6).contains(&u)
        || (0xF8..=0x2FF).contains(&u)
        || (0x370..=0x37D).contains(&u)
        || (0x37F..=0x1FFF).contains(&u)
        || (0x200C..=0x200D).contains(&u)
        || (0x2070..=0x218F).contains(&u)
        || (0x2C00..=0x2FEF).contains(&u)
        || (0x3001..=0xD7FF).contains(&u)
        || (0xF900..=0xFDCF).contains(&u)
        || (0xFDF0..=0xFFFD).contains(&u)
        || (0x10000..=0xEFFFF).contains(&u)
}

fn is_name_char(c: char) -> bool {
    if c.is_ascii() {
        return c == ':' || c == '_' || c == '-' || c == '.' || c.is_ascii_alphanumeric();
    }
    if is_name_start_char(c) {
        return true;
    }
    let u = c as u32;
    u == 0xB7
        || (0x0300..=0x036F).contains(&u)
        || (0x203F..=0x2040).contains(&u)
}

fn is_legal_char_ref_code_point(cp: u32, xml11: bool) -> bool {
    if xml11 {
        (0x1..=0xD7FF).contains(&cp)
            || (0xE000..=0xFFFD).contains(&cp)
            || (0x10000..=0x10FFFF).contains(&cp)
    } else {
        cp == 0x9
            || cp == 0xA
            || cp == 0xD
            || (0x20..=0xD7FF).contains(&cp)
            || (0xE000..=0xFFFD).contains(&cp)
            || (0x10000..=0x10FFFF).contains(&cp)
    }
}

fn is_pubid_char(c: char) -> bool {
    if c.is_ascii_alphanumeric() {
        return true;
    }
    matches!(
        c,
        ' ' | '\r'
            | '\n'
            | '-'
            | '\''
            | '('
            | ')'
            | '+'
            | ','
            | '.'
            | '/'
            | ':'
            | '='
            | '?'
            | ';'
            | '!'
            | '*'
            | '#'
            | '@'
            | '$'
            | '_'
            | '%'
    )
}

fn match_predefined(arr: &[char], start: usize, len: usize) -> Option<&'static str> {
    let s = &arr[start..start + len];
    if len == 3 && s[0] == 'a' && s[1] == 'm' && s[2] == 'p' {
        Some("&")
    } else if len == 2 && s[0] == 'l' && s[1] == 't' {
        Some("<")
    } else if len == 2 && s[0] == 'g' && s[1] == 't' {
        Some(">")
    } else if len == 4 && s[0] == 'a' && s[1] == 'p' && s[2] == 'o' && s[3] == 's' {
        Some("'")
    } else if len == 4 && s[0] == 'q' && s[1] == 'u' && s[2] == 'o' && s[3] == 't' {
        Some("\"")
    } else {
        None
    }
}

/// Exploratory (explore/utf8-byte-path): byte-native counterpart to
/// `match_predefined`. The five predefined entity names are all pure
/// ASCII, so this is a direct byte-slice comparison — no decoding
/// involved regardless of which path is calling it.
#[allow(dead_code)]
fn match_predefined_bytes(name: &[u8]) -> Option<&'static str> {
    match name {
        b"amp" => Some("&"),
        b"lt" => Some("<"),
        b"gt" => Some(">"),
        b"apos" => Some("'"),
        b"quot" => Some("\""),
        _ => None,
    }
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !out.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

fn matches_name_production(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        None => return false,
        Some(c) => {
            if !is_name_start_char(c) {
                return false;
            }
        }
    }
    chars.all(is_name_char)
}

fn matches_nmtoken_production(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_name_char)
}

fn split_tokens(value: &str) -> Vec<String> {
    value
        .split(' ')
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

impl<'a> Scanner<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handler: &'a mut dyn XmlHandler,
        xml11: bool,
        entity_resolver: Option<Box<dyn EntityResolver>>,
        public_id: Option<String>,
        base_system_id: Option<String>,
        validation_enabled: bool,
        namespace_aware: bool,
        settings: ScannerSettings,
        defer_document_start_until_encoding: bool,
    ) -> ParseResult<Self> {
        let locator = DocumentLocator {
            public_id: public_id.clone(),
            system_id: base_system_id.clone(),
            line: -1,
            column: -1,
        };
        let mut s = Scanner {
            handler,
            locator,
            encoding: None,
            utf8_confirmed: false,
            document_started: false,
            defer_document_start_until_encoding,
            buf: ScanBuffer::Chars(vec!['\u{0}'; INITIAL_CAPACITY]),
            pos: 0,
            limit: 0,
            scratch: String::new(),
            in_start_tag: false,
            in_attribute_value: false,
            pending_quote: '\u{0}',
            attr_value_run_open: false,
            normalizing_current_attribute: false,
            collapse_current_attr_value: false,
            normalize_builder: String::new(),
            current_attr_element_name: String::new(),
            current_attr_name: String::new(),
            current_attr_type: String::new(),
            content_run_open: false,
            content_run_is_whitespace: false,
            content_bracket_run: 0,
            element_stack: Vec::new(),
            validator_stack: None,
            seen_attribute_names: Vec::new(),
            name_pool: PackedName::new(),
            root_started: false,
            root_ended: false,
            doctype_seen: false,
            doctype_name: None,
            in_doctype: false,
            doctype_subset_closed: false,
            doctype_name_pending: None,
            doctype_pending: None,
            in_skipped_declaration: false,
            skip_decl_quote: None,
            doctype_external_public_id: None,
            doctype_external_system_id: None,
            doctype_public_id: None,
            doctype_system_id: None,
            general_entities: HashMap::new(),
            attribute_entity_cache: HashMap::new(),
            content_entity_cache: HashMap::new(),
            content_entity_byte_cache: HashMap::new(),
            external_entity_names: HashMap::new(),
            parameter_entities: HashMap::new(),
            parameter_entity_external_ids: HashMap::new(),
            parameter_entity_expansion_stack: Vec::new(),
            entity_expansion_stack: Vec::new(),
            entity_stack_floors: Vec::new(),
            entity_expansion_count: 0,
            parsing_external_content: false,
            xml11,
            entity_resolver,
            base_system_id,
            validation_enabled,
            namespace_aware,
            settings,
            standalone: false,
            restricted_char_entities: HashSet::new(),
            externally_declared_general_entities: HashSet::new(),
            allow_restricted_char_in_content: false,
            last_literal_contained_restricted_char: false,
            last_char_ref_code_point: 0,
            last_external_id_public_id: None,
            last_external_id_system_id: None,
            declared_notations: HashSet::new(),
            notation_external_ids: HashMap::new(),
            dtd_model: DtdModel::new(),
            last_enumeration_values: None,
            cm_pos: 0,
            cm_end: 0,
            in_pi: false,
            in_comment: false,
            in_cdata: false,
            cdata_run_open: false,
            saw_internal_subset_parameter_entity_reference: false,
            last_resolved_system_id: None,
            last_pe_reference_end: 0,
            last_splice_end: -1,
            saw_splice_since_declaration_start: false,
            last_param_entity_was_external: false,
            declared_ids: None,
            pending_idrefs: None,
        };
        if !defer_document_start_until_encoding {
            s.start_document()?;
        }
        Ok(s)
    }

    // ===== Public API used by the decoder/parser =====

    pub fn set_encoding(&mut self, encoding: &str) {
        self.encoding = Some(encoding.to_string());
        if self.defer_document_start_until_encoding && !self.document_started {
            // start_document only errors if the handler errors; ignore is not
            // an option, so surface via a stored path is unnecessary here -
            // the handler's start_document rarely fails, and if it does the
            // next receive() will also fail. Best effort:
            let _ = self.start_document();
        }
    }

    pub fn get_encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }

    /// Exploratory (explore/utf8-byte-path): records whether the decoder
    /// confirmed genuine UTF-8 bytes (explicit `encoding="UTF-8"`, a UTF-8
    /// BOM, or no signal at all — the XML-spec default). Not yet acted on;
    /// this is the milestone-one detection hook, verified by unit tests
    /// against `is_utf8_confirmed()` before anything is built on top of it.
    pub(crate) fn set_utf8_confirmed(&mut self, confirmed: bool) {
        self.utf8_confirmed = confirmed;
    }

    pub(crate) fn is_utf8_confirmed(&self) -> bool {
        self.utf8_confirmed
    }

    /// Resets all streaming/parse state so the scanner can parse a fresh
    /// document with the same handler, resolver, and settings.
    pub fn reset(&mut self) {
        self.encoding = None;
        self.utf8_confirmed = false;
        self.document_started = false;
        // A prior document may have switched this scanner into byte mode
        // (see `switch_to_bytes_mode`); reassigning outright — rather than
        // clearing/resizing the existing buffer in place — is what
        // actually discards that and returns to the char-mode buffer this
        // scanner starts with, regardless of which variant it's currently
        // in.
        self.buf = ScanBuffer::Chars(vec!['\u{0}'; INITIAL_CAPACITY]);
        self.pos = 0;
        self.limit = 0;
        self.in_start_tag = false;
        self.in_attribute_value = false;
        self.pending_quote = '\u{0}';
        self.attr_value_run_open = false;
        self.normalizing_current_attribute = false;
        self.collapse_current_attr_value = false;
        self.normalize_builder.clear();
        self.current_attr_element_name.clear();
        self.current_attr_name.clear();
        self.current_attr_type.clear();
        self.content_run_open = false;
        self.content_run_is_whitespace = false;
        self.content_bracket_run = 0;
        self.element_stack.clear();
        self.validator_stack = None;
        self.seen_attribute_names.clear();
        self.name_pool = PackedName::new();
        self.root_started = false;
        self.root_ended = false;
        self.doctype_seen = false;
        self.doctype_name = None;
        self.in_doctype = false;
        self.doctype_subset_closed = false;
        self.doctype_name_pending = None;
        self.doctype_pending = None;
        self.in_skipped_declaration = false;
        self.skip_decl_quote = None;
        self.doctype_external_public_id = None;
        self.doctype_external_system_id = None;
        self.doctype_public_id = None;
        self.doctype_system_id = None;
        self.general_entities.clear();
        self.attribute_entity_cache.clear();
        self.content_entity_cache.clear();
        self.content_entity_byte_cache.clear();
        self.external_entity_names.clear();
        self.parameter_entities.clear();
        self.parameter_entity_external_ids.clear();
        self.parameter_entity_expansion_stack.clear();
        self.entity_expansion_stack.clear();
        self.entity_stack_floors.clear();
        self.entity_expansion_count = 0;
        self.parsing_external_content = false;
        self.standalone = false;
        self.restricted_char_entities.clear();
        self.externally_declared_general_entities.clear();
        self.allow_restricted_char_in_content = false;
        self.last_literal_contained_restricted_char = false;
        self.last_char_ref_code_point = 0;
        self.last_external_id_public_id = None;
        self.last_external_id_system_id = None;
        self.declared_notations.clear();
        self.notation_external_ids.clear();
        self.dtd_model = DtdModel::new();
        self.last_enumeration_values = None;
        self.cm_pos = 0;
        self.cm_end = 0;
        self.in_pi = false;
        self.in_comment = false;
        self.in_cdata = false;
        self.cdata_run_open = false;
        self.saw_internal_subset_parameter_entity_reference = false;
        self.last_resolved_system_id = None;
        self.last_pe_reference_end = 0;
        self.last_splice_end = -1;
        self.saw_splice_since_declaration_start = false;
        self.last_param_entity_was_external = false;
        self.declared_ids = None;
        self.pending_idrefs = None;
    }

    pub fn xml_version(&self) -> &'static str {
        if self.xml11 {
            "1.1"
        } else {
            "1.0"
        }
    }

    pub fn set_xml11(&mut self, xml11: bool) {
        self.xml11 = xml11;
        self.handler.set_xml11(xml11);
    }

    pub fn set_standalone(&mut self, standalone: bool) {
        self.standalone = standalone;
    }

    pub fn is_standalone(&self) -> bool {
        self.standalone
    }

    pub fn has_doctype(&self) -> bool {
        self.doctype_seen
    }

    pub fn doctype_name(&self) -> Option<&str> {
        self.doctype_name.as_deref()
    }

    pub fn fatal_error(&mut self, message: &str) -> ParseError {
        self.fatal(message)
    }

    fn start_document(&mut self) -> ParseResult<()> {
        // Disjoint field borrows: handler (mut) + locator (shared).
        self.handler.set_locator(&self.locator);
        self.handler.start_document()?;
        self.document_started = true;
        Ok(())
    }

    pub fn receive(&mut self, data: &str) -> ParseResult<()> {
        self.append(data);
        self.scan()?;
        self.handler.save_buffers()
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `receive`, called by `ExternalEntityDecoder` once it has switched
    /// this scanner into byte mode. The decoder still normalizes line
    /// endings (CR/CRLF -> LF) before calling this, on raw UTF-8 bytes
    /// rather than decoded chars — see
    /// `ExternalEntityDecoder::normalize_line_endings_bytes`. Byte mode is
    /// only ever entered for XML 1.0 documents (see
    /// `setup_charset_decoder`'s `use_bytes_mode` computation), so this
    /// path never needs to recognize NEL/LS as line endings — only XML 1.1
    /// does, and that document class simply never switches to byte mode.
    pub(crate) fn receive_bytes(&mut self, data: &[u8]) -> ParseResult<()> {
        self.append_bytes(data);
        self.scan_bytes()?;
        self.handler.save_buffers()
    }

    /// Exploratory (explore/utf8-byte-path): true when the scanner is in
    /// byte mode and `self.pos` sits at a multi-byte UTF-8 lead byte whose
    /// continuation bytes never fully arrived. Every byte-native scan
    /// function advances `self.pos` as far as legally possible before
    /// reporting `NeedMore`, so if that outcome was specifically "waiting
    /// on more bytes of this one sequence" (as opposed to any other reason
    /// to pause, e.g. waiting for a closing quote or `>`), `self.pos` is
    /// left exactly at that sequence's first byte. Checked only at
    /// `close()`, mirroring how the char path's `had_incomplete` is only
    /// surfaced there too.
    pub(crate) fn has_incomplete_trailing_bytes(&self) -> bool {
        if !matches!(self.buf, ScanBuffer::Bytes(_)) || self.pos >= self.limit {
            return false;
        }
        let b = self.buf.as_bytes()[self.pos];
        if b < 0x80 {
            return false;
        }
        let seq_len = utf8_seq_len(b);
        seq_len == 0 || self.pos + seq_len > self.limit
    }

    pub fn close(&mut self) -> ParseResult<()> {
        if !self.document_started {
            self.start_document()?;
        }
        if self.in_start_tag
            || self.in_attribute_value
            || self.in_doctype
            || !self.element_stack.is_empty()
        {
            return Err(self.fatal("Document ended unexpectedly (unclosed element or tag)"));
        }
        if !self.root_started {
            return Err(self.fatal("Document must contain a root element"));
        }
        self.check_entity_values_do_not_reference_unparsed_entities()?;
        if self.validation_enabled {
            self.check_pending_idrefs()?;
            self.check_unparsed_entity_notations_declared()?;
            self.check_attlist_notation_names_declared()?;
        }
        self.handler.end_document()
    }

    // ===== Error helper =====

    fn fatal(&mut self, message: &str) -> ParseError {
        match self.handler.fatal_error(message) {
            Err(e) => e,
            Ok(()) => ParseError::new(message),
        }
    }

    // ===== Buffer management =====

    fn append(&mut self, data: &str) {
        if self.pos > 0 {
            let remaining = self.limit - self.pos;
            if remaining > 0 {
                self.buf.as_chars_mut().copy_within(self.pos..self.limit, 0);
            }
            self.limit = remaining;
            self.pos = 0;
        }
        // `data.len()` (bytes) is always >= its char count, so it's a safe
        // upper bound for the resize check — this avoids a full decode-and-
        // count pass over `data` just to learn a number the write loop
        // below produces for free as a side effect. Worst case (all-ASCII)
        // it matches exactly; multi-byte input just over-reserves a little,
        // which the amortized doubling below already tolerates fine.
        if self.limit + data.len() > self.buf.as_chars().len() {
            let mut newcap = self.buf.as_chars().len().max(1) * 2;
            while newcap < self.limit + data.len() {
                newcap *= 2;
            }
            self.buf.as_chars_mut().resize(newcap, '\u{0}');
        }
        let mut i = self.limit;
        for c in data.chars() {
            self.buf[i] = c;
            i += 1;
        }
        self.limit = i;
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `append`. Not yet reachable from `ExternalEntityDecoder` — that
    /// wiring (skipping the decode-to-`Vec<char>` step entirely when UTF-8
    /// is confirmed) is a later milestone. `BytesMut::advance` drops the
    /// consumed prefix without necessarily shifting memory, and `reserve`
    /// only shifts/reallocates when it's actually short on room — no
    /// unconditional copy_within, no zero-fill (see `ScanBuffer::Bytes`'s
    /// doc comment for why both of those are real costs on the char path).
    #[allow(dead_code)]
    fn append_bytes(&mut self, data: &[u8]) {
        if self.pos > 0 {
            self.buf.as_bytes_mut().advance(self.pos);
            self.pos = 0;
        }
        let buf = self.buf.as_bytes_mut();
        buf.reserve(data.len());
        buf.put_slice(data);
        self.limit = buf.len();
    }

    /// Exploratory (explore/utf8-byte-path): switches the scanner from its
    /// default char-mode buffer to an empty byte-mode buffer. Called for
    /// real by `ExternalEntityDecoder::setup_charset_decoder` once UTF-8 is
    /// confirmed (and, for now, the document isn't XML 1.1 — see
    /// `receive_bytes`'s doc comment); also doubles as test setup for the
    /// byte-native scanning primitives above.
    pub(crate) fn switch_to_bytes_mode(&mut self) {
        self.buf = ScanBuffer::Bytes(BytesMut::new());
        self.pos = 0;
        self.limit = 0;
    }

    fn slice(&self, start: usize, end: usize) -> String {
        self.buf[start..end].iter().collect()
    }

    /// Hot-path equivalent of `slice` for callers that only need the text
    /// transiently (text runs, attribute-value chunks, comment/PI/CDATA
    /// data): reuses `self.scratch`'s allocation across calls instead of
    /// allocating a fresh `String` every time.
    fn slice_and<F>(&mut self, start: usize, end: usize, f: F) -> ParseResult<()>
    where
        F: FnOnce(&mut Self, &str) -> ParseResult<()>,
    {
        self.scratch.clear();
        self.scratch.extend(self.buf[start..end].iter().copied());
        // `chunk` is a plain local once taken out of `self` (mem::take is
        // O(1), no allocation), so `f(self, &chunk)` has no overlapping
        // borrows even though `f` takes `&mut Self`. Putting it back after
        // preserves its capacity for the next call.
        let chunk = std::mem::take(&mut self.scratch);
        let result = f(self, &chunk);
        self.scratch = chunk;
        result
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `slice_and`. `emit_attribute_value_content` and friends never touch
    /// `self.buf` themselves — they only operate on the `&str` chunk
    /// they're handed — so reusing them from the byte path needs nothing
    /// more than a valid `&str` view over a byte range. `push_str` here is
    /// a raw memcpy of bytes already known to be well-formed UTF-8 (the
    /// byte-native scanners only ever advance `pos` past ranges they've
    /// validated), not a per-char encode like `slice_and`'s `extend` — so
    /// this does strictly less work per call, copy included.
    #[allow(dead_code)]
    fn slice_and_bytes<F>(&mut self, start: usize, end: usize, f: F) -> ParseResult<()>
    where
        F: FnOnce(&mut Self, &str) -> ParseResult<()>,
    {
        self.scratch.clear();
        // SAFETY: [start, end) was only ever advanced past by
        // scan_content_run_bytes/scan_attr_value_run_bytes, both of which
        // validate every non-ASCII sequence via `std::str::from_utf8`
        // before accepting it — this range is already known-valid UTF-8.
        let bytes = &self.buf.as_bytes()[start..end];
        self.scratch.push_str(unsafe { std::str::from_utf8_unchecked(bytes) });
        let chunk = std::mem::take(&mut self.scratch);
        let result = f(self, &chunk);
        self.scratch = chunk;
        result
    }

    // ===== Whole-DTD end-of-document checks =====

    fn check_entity_values_do_not_reference_unparsed_entities(&mut self) -> ParseResult<()> {
        let entries: Vec<(String, Rc<[char]>)> = self
            .general_entities
            .iter()
            .map(|(k, v)| (k.clone(), Rc::clone(v)))
            .collect();
        for (key, value) in entries {
            let chars: &[char] = &value;
            let len = chars.len();
            let mut q = 0;
            while q < len {
                if chars[q] != '&' {
                    q += 1;
                    continue;
                }
                let name_start = q + 1;
                let mut p = name_start;
                while p < len && is_name_char(chars[p]) {
                    p += 1;
                }
                if p >= len || chars[p] != ';' {
                    q += 1;
                    continue;
                }
                if match_predefined(&chars, name_start, p - name_start).is_none() {
                    let ref_name: String = chars[name_start..p].iter().collect();
                    if let Some(ids) = self.external_entity_names.get(&ref_name) {
                        if ids.ndata.is_some() {
                            let msg = format!(
                                "Well-Formedness Constraint: Parsed Entity (Section 4.1). Entity \"{key}\" references unparsed entity \"{ref_name}\" - an entity reference must not name an unparsed entity."
                            );
                            return Err(self.fatal(&msg));
                        }
                    }
                }
                q = p + 1;
            }
        }
        Ok(())
    }

    fn check_unparsed_entity_notations_declared(&mut self) -> ParseResult<()> {
        let entries: Vec<(String, Option<String>)> = self
            .external_entity_names
            .iter()
            .map(|(k, v)| (k.clone(), v.ndata.clone()))
            .collect();
        for (key, notation) in entries {
            if let Some(notation_name) = notation {
                if !self.declared_notations.contains(&notation_name) {
                    let msg = format!(
                        "Validity Constraint: Notation Declared (Section 4.2.2). Entity \"{key}\" names undeclared notation \"{notation_name}\"."
                    );
                    self.handler.error(&msg)?;
                }
            }
        }
        Ok(())
    }

    fn check_attlist_notation_names_declared(&mut self) -> ParseResult<()> {
        let snapshot = self.dtd_model.attlists_snapshot();
        for (element, attr, def) in snapshot {
            if def.attr_type != "NOTATION" {
                continue;
            }
            if let Some(enumeration) = &def.enumeration {
                for notation_name in enumeration {
                    if !self.declared_notations.contains(notation_name) {
                        let msg = format!(
                            "Validity Constraint: Notation Attributes (Section 3.3.1). Attribute \"{attr}\" of element \"{element}\" names undeclared notation \"{notation_name}\"."
                        );
                        self.handler.error(&msg)?;
                    }
                }
            }
        }
        Ok(())
    }

    // ===== Validation helpers =====

    fn push_element_validator(&mut self, q_name: &str) -> ParseResult<()> {
        if self.validator_stack.is_none() {
            self.validator_stack = Some(Vec::new());
        }
        let mut err = None;
        if let Some(stack) = self.validator_stack.as_mut() {
            if let Some(v) = stack.last_mut() {
                err = v.add_child_element(q_name);
            }
        }
        if let Some(e) = err {
            self.handler.error(&e)?;
        }
        let decl = match self.dtd_model.get_element_declaration(q_name) {
            Some(d) => d.clone(),
            None => {
                let msg = format!(
                    "Validity Constraint: Element Valid (Section 3.1). Element \"{q_name}\" is not declared in the DTD."
                );
                self.handler.error(&msg)?;
                ElementDeclaration::new(q_name.to_string(), ContentType::Any)
            }
        };
        self.validator_stack
            .as_mut()
            .unwrap()
            .push(ContentModelValidator::new(decl));
        Ok(())
    }

    fn pop_and_validate_element(&mut self) -> ParseResult<()> {
        let mut err = None;
        if let Some(stack) = self.validator_stack.as_mut() {
            if let Some(v) = stack.pop() {
                err = v.validate();
            }
        }
        if let Some(e) = err {
            self.handler.error(&e)?;
        }
        Ok(())
    }

    fn record_text_for_validation(&mut self, text: &str, ws_only: bool) -> ParseResult<()> {
        let mut err = None;
        if let Some(stack) = self.validator_stack.as_mut() {
            if let Some(v) = stack.last_mut() {
                err = v.add_text_content(text, ws_only);
            }
        }
        if let Some(e) = err {
            self.handler.error(&e)?;
        }
        Ok(())
    }

    fn record_seen_attribute_name(&mut self, name: Rc<str>) -> ParseResult<()> {
        if self.was_attribute_seen(&name) {
            return Err(self.fatal(&format!(
                "Well-formedness Constraint: Unique Att Spec. Attribute \"{name}\" already appeared on this element."
            )));
        }
        self.seen_attribute_names.push(name);
        Ok(())
    }

    fn was_attribute_seen(&self, name: &str) -> bool {
        self.seen_attribute_names.iter().any(|n| n.as_ref() == name)
    }

    /// `weight` is normally 1 (one reference counted) except at the two call
    /// sites that materialize a parameter entity's replacement text into a
    /// buffer (`scan_quoted_literal_with_char_refs`'s "Included in Literal"
    /// handling, and `expand_parameter_entity_reference`'s buffer swap):
    /// there, `weight` is the replacement's length. Parameter entities are
    /// expanded eagerly and recursively at declaration time, so a small
    /// number of *references* (cheap under a count-only check) can still
    /// materialize an exponentially large *string* — the classic "billion
    /// laughs" attack via nested parameter entities. Counting by size at
    /// those two sites closes that gap while leaving the plain
    /// reference-count check (general entities in content, which expand
    /// lazily by re-scanning rather than pre-materializing, so count alone
    /// already bounds the work) unchanged.
    fn check_entity_expansion_limit(&mut self, weight: i64) -> ParseResult<()> {
        self.entity_expansion_count += weight.max(1);
        let expansion_limit = self.settings.entity_expansion_limit as i64;
        if expansion_limit > 0 && self.entity_expansion_count > expansion_limit {
            let msg = format!("Entity expansion limit ({expansion_limit}) exceeded");
            return Err(self.fatal(&msg));
        }
        Ok(())
    }

    fn illegal_char_error(&mut self, c: char) -> ParseError {
        let msg = format!("Character U+{:04X} is not a legal XML character", c as u32);
        self.fatal(&msg)
    }

    fn is_legal_literal_char(&self, c: char) -> bool {
        if self.xml11 {
            is_legal_literal_char_xml11(c)
        } else {
            is_legal_literal_char_xml10(c)
        }
    }

    fn check_content_char(&mut self, c: char) -> ParseResult<()> {
        let allowed = self.is_legal_literal_char(c)
            || (self.allow_restricted_char_in_content
                && self.xml11
                && is_restricted_char_xml11(c));
        if !allowed {
            return Err(self.illegal_char_error(c));
        }
        if c == ']' {
            self.content_bracket_run += 1;
        } else if c == '>' && self.content_bracket_run >= 2 {
            return Err(self.fatal(
                "\"]]>\" is not allowed in content, except to mark the end of a CDATA section",
            ));
        } else {
            self.content_bracket_run = 0;
        }
        Ok(())
    }

    fn is_content_stop(&self, c: char) -> bool {
        // Printable ASCII is always a legal literal character in both XML
        // 1.0 and 1.1 (is_restricted_char_xml11's ranges never touch
        // 0x20-0x7E), and it's the overwhelming common case in real text
        // content — so for it, checking the four actual stop characters is
        // a complete, definitive answer. No need to fall through to
        // is_legal_literal_char's Unicode-range logic just to reconfirm
        // "yes, this is fine" for every ordinary character in the run.
        if (' '..='~').contains(&c) {
            return c == '<' || c == '&' || c == ']' || c == '>';
        }
        c == '<'
            || c == '&'
            || c == ']'
            || c == '>'
            || !self.is_legal_literal_char(c)
    }

    fn scan_content_run_fast(&mut self) -> ParseResult<()> {
        loop {
            let before = self.pos;
            while self.pos < self.limit && !self.is_content_stop(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos > before {
                self.content_bracket_run = 0;
            }
            if self.pos >= self.limit {
                return Ok(());
            }
            let c = self.buf[self.pos];
            if c == '<' || c == '&' {
                return Ok(());
            }
            if c == ']' {
                self.content_bracket_run += 1;
                self.pos += 1;
                continue;
            }
            if c == '>' {
                if self.content_bracket_run >= 2 {
                    return Err(self.fatal(
                        "\"]]>\" is not allowed in content, except to mark the end of a CDATA section",
                    ));
                }
                self.content_bracket_run = 0;
                self.pos += 1;
                continue;
            }
            if self.allow_restricted_char_in_content && self.xml11 && is_restricted_char_xml11(c) {
                self.content_bracket_run = 0;
                self.pos += 1;
                continue;
            }
            return Err(self.illegal_char_error(c));
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_content_run_fast`. Advances `self.pos` by whole codepoints —
    /// 1 byte for ASCII, checked with the same printable-ASCII fast path
    /// as `is_content_stop`, or the full sequence length for non-ASCII,
    /// decoded only far enough to validate legality (most real text never
    /// takes that branch at all). `NeedMore` covers both "no more buffered
    /// bytes at all" and "a trailing multi-byte sequence isn't fully
    /// buffered yet" — a distinction the char path never needs, since
    /// encoding_rs's decoder already absorbs incomplete trailing sequences
    /// before Scanner ever sees a char.
    #[allow(dead_code)]
    fn scan_content_run_bytes(&mut self) -> ContentRunBytes {
        loop {
            if self.pos >= self.limit {
                return ContentRunBytes::NeedMore;
            }
            let b = self.buf.as_bytes()[self.pos];
            if (0x20..=0x7E).contains(&b) {
                match b {
                    b'<' | b'&' => return ContentRunBytes::Stop,
                    b']' => {
                        self.content_bracket_run += 1;
                        self.pos += 1;
                    }
                    b'>' => {
                        if self.content_bracket_run >= 2 {
                            return ContentRunBytes::Illegal;
                        }
                        self.content_bracket_run = 0;
                        self.pos += 1;
                    }
                    _ => {
                        self.content_bracket_run = 0;
                        self.pos += 1;
                    }
                }
                continue;
            }
            if b < 0x80 {
                // Non-printable ASCII (controls, DEL): still one byte, no
                // decode needed, but does need the real legality check
                // (most of this range is illegal outright in content).
                let c = b as char;
                if !self.is_legal_literal_char(c) {
                    if self.allow_restricted_char_in_content
                        && self.xml11
                        && is_restricted_char_xml11(c)
                    {
                        self.content_bracket_run = 0;
                        self.pos += 1;
                        continue;
                    }
                    return ContentRunBytes::Illegal;
                }
                self.content_bracket_run = 0;
                self.pos += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return ContentRunBytes::Illegal;
            }
            if self.pos + seq_len > self.limit {
                return ContentRunBytes::NeedMore;
            }
            let slice = &self.buf.as_bytes()[self.pos..self.pos + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return ContentRunBytes::Illegal,
            };
            if !self.is_legal_literal_char(c) {
                if self.allow_restricted_char_in_content && self.xml11 && is_restricted_char_xml11(c)
                {
                    self.content_bracket_run = 0;
                    self.pos += seq_len;
                    continue;
                }
                return ContentRunBytes::Illegal;
            }
            self.content_bracket_run = 0;
            self.pos += seq_len;
        }
    }

    fn check_name_start_char(&mut self, name_start: usize) -> ParseResult<()> {
        if !is_name_start_char(self.buf[name_start]) {
            return Err(self.fatal("Names must begin with a legal NameStartChar"));
        }
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `check_name_start_char`. Decodes just the one (possibly multi-byte)
    /// character at `name_start` — safe to `unwrap`, since every caller
    /// only reaches this after its own scan loop has already walked past
    /// `name_start` without erroring, which is only possible if that byte
    /// begins a well-formed sequence.
    #[allow(dead_code)]
    fn check_name_start_char_bytes(&mut self, name_start: usize) -> ParseResult<()> {
        let b = self.buf.as_bytes()[name_start];
        let c = if b < 0x80 {
            b as char
        } else {
            let seq_len = utf8_seq_len(b);
            let slice = &self.buf.as_bytes()[name_start..name_start + seq_len];
            std::str::from_utf8(slice).unwrap().chars().next().unwrap()
        };
        if !is_name_start_char(c) {
            return Err(self.fatal("Names must begin with a legal NameStartChar"));
        }
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to the
    /// `while p < self.limit && is_name_char(self.buf[p]) { p += 1; }` loop
    /// repeated across `scan_start_tag`/`scan_attributes_and_tag_end`/
    /// `scan_end_tag`. ASCII NameChars are checked directly; the rare
    /// non-ASCII NameChar is decoded on demand, same pattern as
    /// `decode_entity_ref_bytes`'s name loop. Unlike content/attribute-value
    /// scanning, hitting invalid UTF-8 here is unconditionally a malformed
    /// document (there's no legal way for a NameChar run to contain
    /// ill-formed bytes), so callers turn `Illegal` into a fatal error with
    /// their own context-specific message.
    #[allow(dead_code)]
    fn scan_name_chars_bytes(&mut self, start: usize) -> NameScanBytes {
        let mut p = start;
        loop {
            if p >= self.limit {
                return NameScanBytes::NeedMore;
            }
            let b = self.buf.as_bytes()[p];
            if b < 0x80 {
                if !is_name_char(b as char) {
                    return NameScanBytes::End(p);
                }
                p += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return NameScanBytes::Illegal;
            }
            if p + seq_len > self.limit {
                return NameScanBytes::NeedMore;
            }
            let slice = &self.buf.as_bytes()[p..p + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return NameScanBytes::Illegal,
            };
            if !is_name_char(c) {
                return NameScanBytes::End(p);
            }
            p += seq_len;
        }
    }

    fn range_equals(&self, start: usize, len: usize, s: &str) -> bool {
        if s.chars().count() != len {
            return false;
        }
        for (i, sc) in s.chars().enumerate() {
            if self.buf[start + i] != sc {
                return false;
            }
        }
        true
    }

    // ===== Main loop =====

    fn scan(&mut self) -> ParseResult<()> {
        loop {
            if self.in_pi {
                if !self.scan_pi_data()? {
                    return Ok(());
                }
                self.in_pi = false;
                continue;
            }
            if self.in_comment {
                if !self.scan_comment_data()? {
                    return Ok(());
                }
                self.in_comment = false;
                continue;
            }
            if self.in_cdata {
                if !self.scan_cdata_content()? {
                    return Ok(());
                }
                self.in_cdata = false;
                continue;
            }
            if self.in_attribute_value {
                if !self.scan_attribute_value_streaming()? {
                    return Ok(());
                }
                self.in_attribute_value = false;
                continue;
            }
            if self.in_start_tag {
                if !self.scan_attributes_and_tag_end()? {
                    return Ok(());
                }
                self.in_start_tag = false;
                continue;
            }
            if self.in_doctype {
                if !self.scan_doctype_subset()? {
                    return Ok(());
                }
                self.in_doctype = false;
                continue;
            }
            if self.pos >= self.limit {
                return Ok(());
            }
            if self.buf[self.pos] == '<' {
                if !self.scan_markup()? {
                    return Ok(());
                }
            } else if !self.scan_content()? {
                return Ok(());
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan` — the top-level dispatch loop, tying together every
    /// byte-native scanner built across this whole exploration. Faithfully
    /// mirrors `scan`'s resumption structure, including its one quirk:
    /// `in_doctype` resumption always goes through `scan_doctype_subset_bytes`
    /// regardless of `DoctypeHandling::Skip` vs `Process`, exactly like the
    /// char path — not something this port introduces or fixes.
    #[allow(dead_code)]
    fn scan_bytes(&mut self) -> ParseResult<()> {
        loop {
            if self.in_pi {
                if !self.scan_pi_data_bytes()? {
                    return Ok(());
                }
                self.in_pi = false;
                continue;
            }
            if self.in_comment {
                if !self.scan_comment_data_bytes()? {
                    return Ok(());
                }
                self.in_comment = false;
                continue;
            }
            if self.in_cdata {
                if !self.scan_cdata_content_bytes()? {
                    return Ok(());
                }
                self.in_cdata = false;
                continue;
            }
            if self.in_attribute_value {
                let quote = self.pending_quote as u8;
                match self.scan_attribute_value_streaming_bytes(quote)? {
                    AttrValueScanBytes::NeedMore => return Ok(()),
                    AttrValueScanBytes::Done => {}
                }
                self.in_attribute_value = false;
                continue;
            }
            if self.in_start_tag {
                if !self.scan_attributes_and_tag_end_bytes()? {
                    return Ok(());
                }
                self.in_start_tag = false;
                continue;
            }
            if self.in_doctype {
                if !self.scan_doctype_subset_bytes()? {
                    return Ok(());
                }
                self.in_doctype = false;
                continue;
            }
            if self.pos >= self.limit {
                return Ok(());
            }
            if self.buf.as_bytes()[self.pos] == b'<' {
                if !self.scan_markup_bytes()? {
                    return Ok(());
                }
            } else if !self.scan_content_bytes()? {
                return Ok(());
            }
        }
    }

    // ===== Content =====

    fn is_current_element_content_element_only(&self) -> bool {
        let current = self.element_stack.last().unwrap();
        self.dtd_model.get_content_type(current) == Some(ContentType::Element)
    }

    fn is_current_element_declared_externally(&self) -> bool {
        let current = self.element_stack.last().unwrap();
        match self.dtd_model.get_element_declaration(current) {
            Some(d) => d.from_external_subset,
            None => false,
        }
    }

    fn emit_content_run(&mut self, start: usize, end_idx: usize, end: bool, is_ws: bool) -> ParseResult<()> {
        self.slice_and(start, end_idx, |this, s| this.emit_content_run_str(s, end, is_ws))
    }

    fn emit_content_run_str(&mut self, s: &str, end: bool, is_ws: bool) -> ParseResult<()> {
        if self.validation_enabled {
            self.record_text_for_validation(s, is_ws)?;
        }
        self.handler.characters(s, is_ws, end)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `emit_content_run`. Reuses `emit_content_run_str` unchanged.
    #[allow(dead_code)]
    fn emit_content_run_bytes(
        &mut self,
        start: usize,
        end_idx: usize,
        end: bool,
        is_ws: bool,
    ) -> ParseResult<()> {
        self.slice_and_bytes(start, end_idx, |this, s| this.emit_content_run_str(s, end, is_ws))
    }

    fn emit_content_empty(&mut self, end: bool, is_ws: bool) -> ParseResult<()> {
        if self.validation_enabled {
            self.record_text_for_validation("", is_ws)?;
        }
        self.handler.characters("", is_ws, end)
    }

    fn scan_content(&mut self) -> ParseResult<bool> {
        let inside_document = !self.element_stack.is_empty();
        let element_only_content = inside_document && self.is_current_element_content_element_only();
        loop {
            let run_start = self.pos;
            if element_only_content
                && self.pos < self.limit
                && self.buf[self.pos] != '<'
                && self.buf[self.pos] != '&'
            {
                let ws0 = is_ws(self.buf[self.pos]);
                while self.pos < self.limit
                    && self.buf[self.pos] != '<'
                    && self.buf[self.pos] != '&'
                    && is_ws(self.buf[self.pos]) == ws0
                {
                    let c = self.buf[self.pos];
                    self.check_content_char(c)?;
                    self.pos += 1;
                }
            } else {
                self.scan_content_run_fast()?;
            }
            let run_is_whitespace =
                element_only_content && self.pos > run_start && is_ws(self.buf[run_start]);
            if run_is_whitespace
                && self.standalone
                && self.validation_enabled
                && self.is_current_element_declared_externally()
            {
                let current = self.element_stack.last().unwrap().clone();
                let msg = format!(
                    "Validity Constraint: Standalone Document Declaration (Section 2.9). Document has standalone=\"yes\" but external DTD subset declares element \"{current}\" with element-only content, and white space occurs directly within its content."
                );
                self.handler.error(&msg)?;
            }
            if !inside_document && self.pos > run_start {
                for i in run_start..self.pos {
                    if !is_ws(self.buf[i]) {
                        let where_ = if self.root_ended {
                            "after the root element"
                        } else {
                            "before the root element"
                        };
                        let msg = format!(
                            "Only whitespace, comments, and processing instructions are allowed {where_}"
                        );
                        return Err(self.fatal(&msg));
                    }
                }
            }
            if self.pos >= self.limit {
                if inside_document && self.pos > run_start {
                    self.emit_content_run(run_start, self.pos, false, run_is_whitespace)?;
                    self.content_run_open = true;
                    self.content_run_is_whitespace = run_is_whitespace;
                }
                return Ok(false);
            }
            if self.buf[self.pos] == '<' {
                if inside_document {
                    if self.pos > run_start {
                        self.emit_content_run(run_start, self.pos, true, run_is_whitespace)?;
                        self.content_run_open = false;
                    } else if self.content_run_open {
                        let ws = self.content_run_is_whitespace;
                        self.emit_content_empty(true, ws)?;
                        self.content_run_open = false;
                    }
                }
                self.content_bracket_run = 0;
                return Ok(true);
            }
            if self.buf[self.pos] != '&' {
                if inside_document && self.pos > run_start {
                    self.emit_content_run(run_start, self.pos, true, run_is_whitespace)?;
                    self.content_run_open = false;
                }
                continue;
            }
            if !inside_document {
                return Err(self.fatal(
                    "Entity and character references are only allowed within the document element",
                ));
            }
            let amp_pos = self.pos;
            if inside_document && amp_pos > run_start {
                self.emit_content_run(run_start, amp_pos, false, run_is_whitespace)?;
                self.content_run_open = true;
                self.content_run_is_whitespace = run_is_whitespace;
            }
            match self.decode_entity_ref()? {
                RefResult::NeedMore => {
                    self.pos = amp_pos;
                    return Ok(false);
                }
                RefResult::General(name) => {
                    if inside_document && self.content_run_open {
                        let ws = self.content_run_is_whitespace;
                        self.emit_content_empty(true, ws)?;
                    }
                    self.content_run_open = false;
                    self.content_bracket_run = 0;
                    self.check_not_empty_element_content("an entity reference")?;
                    self.expand_general_entity_in_content(&name)?;
                    continue;
                }
                RefResult::Decoded(decoded) => {
                    self.content_bracket_run = 0;
                    let at_markup = self.pos < self.limit && self.buf[self.pos] == '<';
                    if inside_document {
                        if self.validation_enabled {
                            self.record_text_for_validation(&decoded, false)?;
                        }
                        self.handler.characters(&decoded, false, at_markup)?;
                        self.content_run_open = !at_markup;
                        self.content_run_is_whitespace = false;
                    }
                    if at_markup {
                        return Ok(true);
                    }
                }
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_content` — the full content orchestration built on top of
    /// `scan_content_run_bytes` (the earlier, leaf-only exploratory
    /// primitive). The element-only-content whitespace-boundary loop
    /// decodes ASCII directly and treats any non-ASCII byte as
    /// automatically non-whitespace (no XML `S` character is ever
    /// multi-byte), so it only needs to decode a full codepoint when it's
    /// already committed to including it in the current run.
    /// `scan_content_run_bytes`'s `Illegal` outcome doesn't distinguish
    /// "bad character" from "']]>' outside CDATA" (unlike the char path's
    /// two distinct error returns), so this reconstructs which one
    /// happened from `self.content_bracket_run` before producing the
    /// matching message.
    #[allow(dead_code)]
    fn scan_content_bytes(&mut self) -> ParseResult<bool> {
        let inside_document = !self.element_stack.is_empty();
        let element_only_content = inside_document && self.is_current_element_content_element_only();
        loop {
            let run_start = self.pos;
            // Set when the scan below stopped specifically because a
            // trailing multi-byte sequence isn't fully buffered yet —
            // distinct from `self.pos >= self.limit` (which only covers
            // "ran off the end with nothing left at all"). Without this,
            // that case falls through to the `self.buf[self.pos] != '&'`
            // branch below (the lead byte is neither `<` nor `&`), which
            // `continue`s the outer loop straight back into the same
            // truncated sequence forever — an infinite loop that only
            // shows up on real multi-byte content split exactly at a
            // chunk boundary, which is exactly why xmlconf's single-shot
            // `parse_all` calls never caught it.
            let mut needs_more_bytes = false;
            if element_only_content
                && self.pos < self.limit
                && self.buf.as_bytes()[self.pos] != b'<'
                && self.buf.as_bytes()[self.pos] != b'&'
            {
                let b0 = self.buf.as_bytes()[self.pos];
                let ws0 = b0 < 0x80 && is_ws(b0 as char);
                loop {
                    if self.pos >= self.limit {
                        break;
                    }
                    let b = self.buf.as_bytes()[self.pos];
                    if b == b'<' || b == b'&' {
                        break;
                    }
                    if b < 0x80 {
                        let c = b as char;
                        if is_ws(c) != ws0 {
                            break;
                        }
                        self.check_content_char(c)?;
                        self.pos += 1;
                        continue;
                    }
                    // No multi-byte codepoint is XML whitespace, so a
                    // whitespace run can never include one.
                    if ws0 {
                        break;
                    }
                    let seq_len = utf8_seq_len(b);
                    if seq_len == 0 {
                        return Err(self.fatal("Ill-formed UTF-8 sequence"));
                    }
                    if self.pos + seq_len > self.limit {
                        needs_more_bytes = true;
                        break;
                    }
                    let slice = &self.buf.as_bytes()[self.pos..self.pos + seq_len];
                    let c = match std::str::from_utf8(slice) {
                        Ok(s) => s.chars().next().unwrap(),
                        Err(_) => return Err(self.fatal("Ill-formed UTF-8 sequence")),
                    };
                    self.check_content_char(c)?;
                    self.pos += seq_len;
                }
            } else {
                match self.scan_content_run_bytes() {
                    ContentRunBytes::Stop => {}
                    ContentRunBytes::NeedMore => {
                        needs_more_bytes = true;
                    }
                    ContentRunBytes::Illegal => {
                        if self.buf.as_bytes()[self.pos] == b'>' && self.content_bracket_run >= 2 {
                            return Err(self.fatal(
                                "\"]]>\" is not allowed in content, except to mark the end of a CDATA section",
                            ));
                        }
                        let b = self.buf.as_bytes()[self.pos];
                        if b < 0x80 {
                            return Err(self.illegal_char_error(b as char));
                        }
                        // `Illegal` also covers genuinely malformed UTF-8
                        // (invalid lead byte, bad continuation bytes) --
                        // not just a validly-decoded-but-XML-disallowed
                        // character -- so decoding here can legitimately
                        // fail; that case gets its own message rather than
                        // forcing a char out of bytes that aren't one.
                        let seq_len = utf8_seq_len(b);
                        if seq_len == 0 || self.pos + seq_len > self.limit {
                            return Err(self.fatal("Ill-formed UTF-8 sequence"));
                        }
                        let slice = &self.buf.as_bytes()[self.pos..self.pos + seq_len];
                        let c = match std::str::from_utf8(slice) {
                            Ok(s) => match s.chars().next() {
                                Some(c) => c,
                                None => return Err(self.fatal("Ill-formed UTF-8 sequence")),
                            },
                            Err(_) => return Err(self.fatal("Ill-formed UTF-8 sequence")),
                        };
                        return Err(self.illegal_char_error(c));
                    }
                }
            }
            let run_is_whitespace = element_only_content && self.pos > run_start && {
                let b = self.buf.as_bytes()[run_start];
                b < 0x80 && is_ws(b as char)
            };
            if run_is_whitespace
                && self.standalone
                && self.validation_enabled
                && self.is_current_element_declared_externally()
            {
                let current = self.element_stack.last().unwrap().clone();
                let msg = format!(
                    "Validity Constraint: Standalone Document Declaration (Section 2.9). Document has standalone=\"yes\" but external DTD subset declares element \"{current}\" with element-only content, and white space occurs directly within its content."
                );
                self.handler.error(&msg)?;
            }
            if !inside_document && self.pos > run_start {
                for i in run_start..self.pos {
                    let b = self.buf.as_bytes()[i];
                    let is_ws_byte = b < 0x80 && is_ws(b as char);
                    if !is_ws_byte {
                        let where_ = if self.root_ended {
                            "after the root element"
                        } else {
                            "before the root element"
                        };
                        let msg = format!(
                            "Only whitespace, comments, and processing instructions are allowed {where_}"
                        );
                        return Err(self.fatal(&msg));
                    }
                }
            }
            if self.pos >= self.limit || needs_more_bytes {
                if inside_document && self.pos > run_start {
                    self.emit_content_run_bytes(run_start, self.pos, false, run_is_whitespace)?;
                    self.content_run_open = true;
                    self.content_run_is_whitespace = run_is_whitespace;
                }
                return Ok(false);
            }
            if self.buf.as_bytes()[self.pos] == b'<' {
                if inside_document {
                    if self.pos > run_start {
                        self.emit_content_run_bytes(run_start, self.pos, true, run_is_whitespace)?;
                        self.content_run_open = false;
                    } else if self.content_run_open {
                        let ws = self.content_run_is_whitespace;
                        self.emit_content_empty(true, ws)?;
                        self.content_run_open = false;
                    }
                }
                self.content_bracket_run = 0;
                return Ok(true);
            }
            if self.buf.as_bytes()[self.pos] != b'&' {
                if inside_document && self.pos > run_start {
                    self.emit_content_run_bytes(run_start, self.pos, true, run_is_whitespace)?;
                    self.content_run_open = false;
                }
                continue;
            }
            if !inside_document {
                return Err(self.fatal(
                    "Entity and character references are only allowed within the document element",
                ));
            }
            let amp_pos = self.pos;
            if inside_document && amp_pos > run_start {
                self.emit_content_run_bytes(run_start, amp_pos, false, run_is_whitespace)?;
                self.content_run_open = true;
                self.content_run_is_whitespace = run_is_whitespace;
            }
            match self.decode_entity_ref_bytes()? {
                RefResult::NeedMore => {
                    self.pos = amp_pos;
                    return Ok(false);
                }
                RefResult::General(name) => {
                    if inside_document && self.content_run_open {
                        let ws = self.content_run_is_whitespace;
                        self.emit_content_empty(true, ws)?;
                    }
                    self.content_run_open = false;
                    self.content_bracket_run = 0;
                    self.check_not_empty_element_content("an entity reference")?;
                    self.expand_general_entity_in_content_bytes(&name)?;
                    continue;
                }
                RefResult::Decoded(decoded) => {
                    self.content_bracket_run = 0;
                    let at_markup =
                        self.pos < self.limit && self.buf.as_bytes()[self.pos] == b'<';
                    if inside_document {
                        if self.validation_enabled {
                            self.record_text_for_validation(&decoded, false)?;
                        }
                        self.handler.characters(&decoded, false, at_markup)?;
                        self.content_run_open = !at_markup;
                        self.content_run_is_whitespace = false;
                    }
                    if at_markup {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // ===== Entity reference decoding =====

    fn decode_entity_ref(&mut self) -> ParseResult<RefResult> {
        let mut p = self.pos + 1;
        if p >= self.limit {
            return Ok(RefResult::NeedMore);
        }
        if self.buf[p] == '#' {
            p += 1;
            let mut hex = false;
            if p < self.limit && self.buf[p] == 'x' {
                hex = true;
                p += 1;
            }
            let digits_start = p;
            while p < self.limit && self.buf[p] != ';' {
                let d = self.buf[p];
                let ok = if hex {
                    d.is_ascii_hexdigit()
                } else {
                    d.is_ascii_digit()
                };
                if !ok {
                    return Err(self.fatal("Malformed character reference"));
                }
                p += 1;
            }
            if p >= self.limit {
                return Ok(RefResult::NeedMore);
            }
            if p == digits_start {
                return Err(self.fatal("Empty character reference"));
            }
            let digits: String = self.buf[digits_start..p].iter().collect();
            let code_point = match u32::from_str_radix(&digits, if hex { 16 } else { 10 }) {
                Ok(v) => v,
                Err(_) => return Err(self.fatal("Malformed character reference")),
            };
            if !is_legal_char_ref_code_point(code_point, self.xml11) {
                let msg = format!("Character reference out of range: {code_point}");
                return Err(self.fatal(&msg));
            }
            self.pos = p + 1;
            let ch = char::from_u32(code_point)
                .ok_or_else(|| ParseError::new("Character reference out of range"))?;
            return Ok(RefResult::Decoded(ch.to_string()));
        }

        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            return Ok(RefResult::NeedMore);
        }
        if p == name_start || self.buf[p] != ';' {
            return Err(self.fatal("Malformed entity reference"));
        }
        self.check_name_start_char(name_start)?;
        let len = p - name_start;
        if let Some(predef) = match_predefined(self.buf.as_chars(), name_start, len) {
            self.pos = p + 1;
            return Ok(RefResult::Decoded(predef.to_string()));
        }
        let name: String = self.buf[name_start..p].iter().collect();
        self.pos = p + 1;
        Ok(RefResult::General(name))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `decode_entity_ref`. Reuses the same `RefResult` the char path
    /// returns -- it's just an owned `String`/name, built fresh regardless
    /// of which path produced it, so nothing downstream needs to change.
    /// Numeric character references never involve multi-byte decoding
    /// (digits, 'x', and ';' are all ASCII by definition); named references
    /// can, so that scan reuses the same NeedMore-on-split-sequence handling
    /// as the other byte-native scanners.
    #[allow(dead_code)]
    fn decode_entity_ref_bytes(&mut self) -> ParseResult<RefResult> {
        let mut p = self.pos + 1;
        if p >= self.limit {
            return Ok(RefResult::NeedMore);
        }
        if self.buf.as_bytes()[p] == b'#' {
            p += 1;
            let mut hex = false;
            if p < self.limit && self.buf.as_bytes()[p] == b'x' {
                hex = true;
                p += 1;
            }
            let digits_start = p;
            while p < self.limit && self.buf.as_bytes()[p] != b';' {
                let d = self.buf.as_bytes()[p];
                let ok = if hex {
                    d.is_ascii_hexdigit()
                } else {
                    d.is_ascii_digit()
                };
                if !ok {
                    return Err(self.fatal("Malformed character reference"));
                }
                p += 1;
            }
            if p >= self.limit {
                return Ok(RefResult::NeedMore);
            }
            if p == digits_start {
                return Err(self.fatal("Empty character reference"));
            }
            // SAFETY: every byte in [digits_start, p) was just checked to be
            // an ASCII hex/decimal digit.
            let digits =
                unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[digits_start..p]) };
            let code_point = match u32::from_str_radix(digits, if hex { 16 } else { 10 }) {
                Ok(v) => v,
                Err(_) => return Err(self.fatal("Malformed character reference")),
            };
            if !is_legal_char_ref_code_point(code_point, self.xml11) {
                let msg = format!("Character reference out of range: {code_point}");
                return Err(self.fatal(&msg));
            }
            self.pos = p + 1;
            let ch = char::from_u32(code_point)
                .ok_or_else(|| ParseError::new("Character reference out of range"))?;
            return Ok(RefResult::Decoded(ch.to_string()));
        }

        let name_start = p;
        loop {
            if p >= self.limit {
                return Ok(RefResult::NeedMore);
            }
            let b = self.buf.as_bytes()[p];
            if b == b';' {
                break;
            }
            if b < 0x80 {
                if !is_name_char(b as char) {
                    break;
                }
                p += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return Err(self.fatal("Malformed entity reference"));
            }
            if p + seq_len > self.limit {
                return Ok(RefResult::NeedMore);
            }
            let slice = &self.buf.as_bytes()[p..p + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return Err(self.fatal("Malformed entity reference")),
            };
            if !is_name_char(c) {
                break;
            }
            p += seq_len;
        }
        if p >= self.limit {
            return Ok(RefResult::NeedMore);
        }
        if p == name_start || self.buf.as_bytes()[p] != b';' {
            return Err(self.fatal("Malformed entity reference"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name_bytes = &self.buf.as_bytes()[name_start..p];
        if let Some(predef) = match_predefined_bytes(name_bytes) {
            self.pos = p + 1;
            return Ok(RefResult::Decoded(predef.to_string()));
        }
        // SAFETY: every byte in this range was validated as part of a legal
        // XML Name above (ASCII checked directly; non-ASCII decoded and
        // checked via is_name_char).
        let name = unsafe { std::str::from_utf8_unchecked(name_bytes) }.to_string();
        self.pos = p + 1;
        Ok(RefResult::General(name))
    }

    // ===== Markup dispatch =====

    fn scan_markup(&mut self) -> ParseResult<bool> {
        let tag_start = self.pos;
        let p = tag_start + 1;
        if p >= self.limit {
            return Ok(false);
        }
        let c = self.buf[p];
        if c == '/' {
            self.scan_end_tag(tag_start)
        } else if c == '!' {
            if p + 1 >= self.limit {
                return Ok(false);
            }
            if self.buf[p + 1] == '-' {
                self.check_not_empty_element_content("a comment")?;
            }
            self.scan_bang_markup(tag_start)
        } else if c == '?' {
            self.check_not_empty_element_content("a processing instruction")?;
            self.scan_pi(tag_start)
        } else {
            self.scan_start_tag(tag_start)
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_markup`.
    #[allow(dead_code)]
    fn scan_markup_bytes(&mut self) -> ParseResult<bool> {
        let tag_start = self.pos;
        let p = tag_start + 1;
        if p >= self.limit {
            return Ok(false);
        }
        let c = self.buf.as_bytes()[p];
        if c == b'/' {
            self.scan_end_tag_bytes(tag_start)
        } else if c == b'!' {
            if p + 1 >= self.limit {
                return Ok(false);
            }
            if self.buf.as_bytes()[p + 1] == b'-' {
                self.check_not_empty_element_content("a comment")?;
            }
            self.scan_bang_markup_bytes(tag_start)
        } else if c == b'?' {
            self.check_not_empty_element_content("a processing instruction")?;
            self.scan_pi_bytes(tag_start)
        } else {
            self.scan_start_tag_bytes(tag_start)
        }
    }

    fn check_not_empty_element_content(&mut self, what: &str) -> ParseResult<()> {
        if self.validation_enabled && !self.element_stack.is_empty() {
            let current = self.element_stack.last().unwrap().clone();
            if self.dtd_model.get_content_type(&current) == Some(ContentType::Empty) {
                let msg = format!(
                    "Validity Constraint: Element Valid (Section 3.1). Element \"{current}\" is declared EMPTY but contains {what}."
                );
                self.handler.error(&msg)?;
            }
        }
        Ok(())
    }

    // ===== Start tag =====

    fn scan_start_tag(&mut self, tag_start: usize) -> ParseResult<bool> {
        let mut p = tag_start + 1;
        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == name_start {
            return Err(self.fatal("Malformed start tag"));
        }
        self.check_name_start_char(name_start)?;
        if self.root_ended {
            return Err(self.fatal("A document may contain only one root element"));
        }
        let q_name = self.name_pool.intern_range(self.buf.as_chars(), name_start, p - name_start);
        if !self.root_started {
            self.root_started = true;
            if self.validation_enabled {
                if let Some(dname) = self.doctype_name.clone() {
                    if dname != *q_name {
                        let msg = format!(
                            "Validity Constraint: Root Element Type (Section 3.2). Document root element \"{q_name}\" does not match DOCTYPE name \"{dname}\"."
                        );
                        self.handler.error(&msg)?;
                    }
                }
            }
        }
        if self.validation_enabled {
            self.push_element_validator(&q_name)?;
        }
        self.pos = p;
        self.element_stack.push(q_name.clone());
        self.seen_attribute_names.clear();
        self.handler.start_element(&q_name)?;
        self.in_start_tag = true;
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_start_tag`. Interning uses `name_pool.intern_str` directly on
    /// a decoded `&str` view of the name range rather than a byte-native
    /// `intern_range` — `intern_str` already exists and takes exactly that,
    /// so no port was needed there either (same shape of discovery as
    /// `emit_attribute_value_content` and `expand_general_entity_in_attribute_value`).
    #[allow(dead_code)]
    fn scan_start_tag_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        let name_start = tag_start + 1;
        let p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            NameScanBytes::Illegal => return Err(self.fatal("Malformed start tag")),
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed start tag"));
        }
        self.check_name_start_char_bytes(name_start)?;
        if self.root_ended {
            return Err(self.fatal("A document may contain only one root element"));
        }
        // SAFETY: [name_start, p) was validated as a legal XML Name by
        // scan_name_chars_bytes above (ASCII checked directly; non-ASCII
        // decoded and checked via is_name_char).
        let name_str =
            unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[name_start..p]) };
        let q_name = self.name_pool.intern_str(name_str);
        if !self.root_started {
            self.root_started = true;
            if self.validation_enabled {
                if let Some(dname) = self.doctype_name.clone() {
                    if dname != *q_name {
                        let msg = format!(
                            "Validity Constraint: Root Element Type (Section 3.2). Document root element \"{q_name}\" does not match DOCTYPE name \"{dname}\"."
                        );
                        self.handler.error(&msg)?;
                    }
                }
            }
        }
        if self.validation_enabled {
            self.push_element_validator(&q_name)?;
        }
        self.pos = p;
        self.element_stack.push(q_name.clone());
        self.seen_attribute_names.clear();
        self.handler.start_element(&q_name)?;
        self.in_start_tag = true;
        Ok(true)
    }

    fn scan_attributes_and_tag_end(&mut self) -> ParseResult<bool> {
        let current_element_name = self.element_stack.last().unwrap().clone();
        let declared_attrs: Option<Vec<(String, crate::dtd::AttDef)>> = self
            .dtd_model
            .get_attributes(&current_element_name)
            .cloned();
        loop {
            let attr_start = self.pos;
            while self.pos < self.limit && is_ws(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            let c = self.buf[self.pos];
            if self.pos == attr_start && is_name_char(c) {
                return Err(self.fatal("White space is required between attributes"));
            }
            if c == '>' {
                self.pos += 1;
                self.apply_attribute_defaults(&current_element_name)?;
                self.handler.end_attributes()?;
                return Ok(true);
            }
            if c == '/' {
                if self.pos + 1 >= self.limit {
                    self.pos = attr_start;
                    return Ok(false);
                }
                if self.buf[self.pos + 1] != '>' {
                    return Err(self.fatal("Malformed start tag"));
                }
                self.pos += 2;
                self.apply_attribute_defaults(&current_element_name)?;
                if self.validation_enabled {
                    self.pop_and_validate_element()?;
                }
                self.element_stack.pop();
                self.root_ended = self.element_stack.is_empty();
                self.handler.end_attributes()?;
                self.handler.end_element()?;
                return Ok(true);
            }

            let name_start = self.pos;
            while self.pos < self.limit && is_name_char(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            if self.pos == name_start {
                return Err(self.fatal("Malformed start tag"));
            }
            self.check_name_start_char(name_start)?;
            let attr_name = self
                .name_pool
                .intern_range(self.buf.as_chars(), name_start, self.pos - name_start);

            while self.pos < self.limit && is_ws(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            if self.buf[self.pos] != '=' {
                return Err(self.fatal("Expected '=' after attribute name"));
            }
            self.pos += 1;

            while self.pos < self.limit && is_ws(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            let quote = self.buf[self.pos];
            if quote != '"' && quote != '\'' {
                return Err(self.fatal("Expected quoted attribute value"));
            }
            self.pos += 1;

            // Check for duplicate after all backtrack points have passed.
            self.record_seen_attribute_name(attr_name.clone())?;

            let attr_def = declared_attrs
                .as_ref()
                .and_then(|attrs| attrs.iter().find(|(n, _)| n.as_str() == attr_name.as_ref()).map(|(_, d)| d));
            let attr_type = attr_def.map(|d| d.attr_type.clone()).unwrap_or_else(|| "CDATA".to_string());
            if self.validation_enabled && attr_def.is_none() {
                let msg = format!(
                    "Validity Constraint: Attribute Value Type (Section 3.3.1). Attribute \"{attr_name}\" is not declared for element \"{current_element_name}\"."
                );
                self.handler.error(&msg)?;
            }
            let declared = attr_def.is_some();
            let declared_externally = attr_def.map(|d| d.declared_externally).unwrap_or(false);
            self.handler
                .start_attribute(&attr_name, &attr_type, declared, true)?;
            self.pending_quote = quote;
            self.attr_value_run_open = false;
            self.collapse_current_attr_value = attr_type != "CDATA";
            let check_xml_space = attr_name.as_ref() == "xml:space";
            self.normalizing_current_attribute =
                self.collapse_current_attr_value || self.validation_enabled || check_xml_space;
            if self.normalizing_current_attribute {
                self.normalize_builder.clear();
                if self.validation_enabled || check_xml_space {
                    self.current_attr_element_name = current_element_name.to_string();
                    self.current_attr_name = attr_name.to_string();
                    self.current_attr_type = attr_type.clone();
                }
                if self.validation_enabled
                    && self.standalone
                    && self.collapse_current_attr_value
                    && declared
                    && declared_externally
                {
                    let msg = format!(
                        "Validity Constraint: Standalone Document Declaration (Section 2.9). Document has standalone=\"yes\" but external markup declares attribute \"{attr_name}\" of element \"{current_element_name}\" with type \"{attr_type}\", which normalizes this specified value differently."
                    );
                    self.handler.error(&msg)?;
                }
            }
            if !self.scan_attribute_value_streaming()? {
                self.in_attribute_value = true;
                return Ok(false);
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_attributes_and_tag_end`. Whitespace/`>`/`/`/`=`/quote checks
    /// compare raw bytes directly (all of `is_ws`'s and the structural
    /// characters here are ASCII, so no byte in a multi-byte sequence's
    /// lead/continuation range can ever match them — no decode needed).
    /// Attribute-name interning again goes through `intern_str` on a
    /// decoded `&str`, same as `scan_start_tag_bytes`.
    #[allow(dead_code)]
    fn scan_attributes_and_tag_end_bytes(&mut self) -> ParseResult<bool> {
        let current_element_name = self.element_stack.last().unwrap().clone();
        let declared_attrs: Option<Vec<(String, crate::dtd::AttDef)>> = self
            .dtd_model
            .get_attributes(&current_element_name)
            .cloned();
        loop {
            let attr_start = self.pos;
            while self.pos < self.limit && is_ws(self.buf.as_bytes()[self.pos] as char) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            let b = self.buf.as_bytes()[self.pos];
            if self.pos == attr_start && b < 0x80 && is_name_char(b as char) {
                return Err(self.fatal("White space is required between attributes"));
            }
            if b == b'>' {
                self.pos += 1;
                self.apply_attribute_defaults(&current_element_name)?;
                self.handler.end_attributes()?;
                return Ok(true);
            }
            if b == b'/' {
                if self.pos + 1 >= self.limit {
                    self.pos = attr_start;
                    return Ok(false);
                }
                if self.buf.as_bytes()[self.pos + 1] != b'>' {
                    return Err(self.fatal("Malformed start tag"));
                }
                self.pos += 2;
                self.apply_attribute_defaults(&current_element_name)?;
                if self.validation_enabled {
                    self.pop_and_validate_element()?;
                }
                self.element_stack.pop();
                self.root_ended = self.element_stack.is_empty();
                self.handler.end_attributes()?;
                self.handler.end_element()?;
                return Ok(true);
            }

            let name_start = self.pos;
            let name_end = match self.scan_name_chars_bytes(name_start) {
                NameScanBytes::NeedMore => {
                    self.pos = attr_start;
                    return Ok(false);
                }
                NameScanBytes::Illegal => return Err(self.fatal("Malformed start tag")),
                NameScanBytes::End(p) => p,
            };
            if name_end == name_start {
                return Err(self.fatal("Malformed start tag"));
            }
            self.check_name_start_char_bytes(name_start)?;
            // SAFETY: [name_start, name_end) was validated as a legal XML
            // Name by scan_name_chars_bytes above.
            let attr_name_str = unsafe {
                std::str::from_utf8_unchecked(&self.buf.as_bytes()[name_start..name_end])
            };
            let attr_name = self.name_pool.intern_str(attr_name_str);
            self.pos = name_end;

            while self.pos < self.limit && is_ws(self.buf.as_bytes()[self.pos] as char) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            if self.buf.as_bytes()[self.pos] != b'=' {
                return Err(self.fatal("Expected '=' after attribute name"));
            }
            self.pos += 1;

            while self.pos < self.limit && is_ws(self.buf.as_bytes()[self.pos] as char) {
                self.pos += 1;
            }
            if self.pos >= self.limit {
                self.pos = attr_start;
                return Ok(false);
            }
            let quote = self.buf.as_bytes()[self.pos];
            if quote != b'"' && quote != b'\'' {
                return Err(self.fatal("Expected quoted attribute value"));
            }
            self.pos += 1;

            // Check for duplicate after all backtrack points have passed.
            self.record_seen_attribute_name(attr_name.clone())?;

            let attr_def = declared_attrs
                .as_ref()
                .and_then(|attrs| attrs.iter().find(|(n, _)| n.as_str() == attr_name.as_ref()).map(|(_, d)| d));
            let attr_type = attr_def.map(|d| d.attr_type.clone()).unwrap_or_else(|| "CDATA".to_string());
            if self.validation_enabled && attr_def.is_none() {
                let msg = format!(
                    "Validity Constraint: Attribute Value Type (Section 3.3.1). Attribute \"{attr_name}\" is not declared for element \"{current_element_name}\"."
                );
                self.handler.error(&msg)?;
            }
            let declared = attr_def.is_some();
            let declared_externally = attr_def.map(|d| d.declared_externally).unwrap_or(false);
            self.handler
                .start_attribute(&attr_name, &attr_type, declared, true)?;
            self.pending_quote = quote as char;
            self.attr_value_run_open = false;
            self.collapse_current_attr_value = attr_type != "CDATA";
            let check_xml_space = attr_name.as_ref() == "xml:space";
            self.normalizing_current_attribute =
                self.collapse_current_attr_value || self.validation_enabled || check_xml_space;
            if self.normalizing_current_attribute {
                self.normalize_builder.clear();
                if self.validation_enabled || check_xml_space {
                    self.current_attr_element_name = current_element_name.to_string();
                    self.current_attr_name = attr_name.to_string();
                    self.current_attr_type = attr_type.clone();
                }
                if self.validation_enabled
                    && self.standalone
                    && self.collapse_current_attr_value
                    && declared
                    && declared_externally
                {
                    let msg = format!(
                        "Validity Constraint: Standalone Document Declaration (Section 2.9). Document has standalone=\"yes\" but external markup declares attribute \"{attr_name}\" of element \"{current_element_name}\" with type \"{attr_type}\", which normalizes this specified value differently."
                    );
                    self.handler.error(&msg)?;
                }
            }
            if self.scan_attribute_value_streaming_bytes(quote)? == AttrValueScanBytes::NeedMore {
                self.in_attribute_value = true;
                return Ok(false);
            }
        }
    }

    fn is_attr_stop(&self, c: char, quote: char) -> bool {
        // See is_content_stop: printable ASCII is always legal, so the
        // three real stop characters are a complete answer without
        // touching is_legal_literal_char at all.
        if (' '..='~').contains(&c) {
            return c == quote || c == '&' || c == '<';
        }
        c == quote
            || c == '&'
            || c == '<'
            || c == '\t'
            || c == '\n'
            || c == '\r'
            || !self.is_legal_literal_char(c)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `is_attr_stop`'s scanning loop inside `scan_attribute_value_streaming`
    /// — the position-finding and in-place tab/newline/CR-to-space
    /// normalization only, not yet the handler emission or entity-reference
    /// decoding wired around it in the real function (that needs
    /// `emit_attribute_value_content`/`decode_entity_ref` to grow their own
    /// byte-native forms first, a separate later step). Same NeedMore
    /// distinction as `scan_content_run_bytes`, for the same reason: a
    /// chunk boundary can split a multi-byte sequence here too.
    #[allow(dead_code)]
    fn scan_attr_value_run_bytes(&mut self, quote: u8) -> AttrValueRunBytes {
        loop {
            if self.pos >= self.limit {
                return AttrValueRunBytes::NeedMore;
            }
            let b = self.buf.as_bytes()[self.pos];
            if (0x20..=0x7E).contains(&b) {
                if b == quote {
                    return AttrValueRunBytes::Quote;
                }
                if b == b'&' {
                    return AttrValueRunBytes::Amp;
                }
                if b == b'<' {
                    return AttrValueRunBytes::Illegal;
                }
                self.pos += 1;
                continue;
            }
            if b == b'\t' || b == b'\n' || b == b'\r' {
                self.buf.as_bytes_mut()[self.pos] = b' ';
                self.pos += 1;
                continue;
            }
            if b < 0x80 {
                let c = b as char;
                if !self.is_legal_literal_char(c) {
                    return AttrValueRunBytes::Illegal;
                }
                self.pos += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return AttrValueRunBytes::Illegal;
            }
            if self.pos + seq_len > self.limit {
                return AttrValueRunBytes::NeedMore;
            }
            let slice = &self.buf.as_bytes()[self.pos..self.pos + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return AttrValueRunBytes::Illegal,
            };
            if !self.is_legal_literal_char(c) {
                return AttrValueRunBytes::Illegal;
            }
            self.pos += seq_len;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_attribute_value_streaming`, now handling entity/character
    /// references inline (mirroring the char path's loop) rather than
    /// stopping at `&`. Calls the real, representation-agnostic
    /// `emit_attribute_value_content` (via `slice_and_bytes` for ordinary
    /// runs, directly for decoded reference text) and
    /// `expand_general_entity_in_attribute_value` — both already operate
    /// purely on `&str`/entity tables and never touch `self.buf`, so
    /// neither needed a byte-native port at all.
    #[allow(dead_code)]
    fn scan_attribute_value_streaming_bytes(
        &mut self,
        quote: u8,
    ) -> ParseResult<AttrValueScanBytes> {
        loop {
            let run_start = self.pos;
            match self.scan_attr_value_run_bytes(quote) {
                AttrValueRunBytes::NeedMore => {
                    if self.pos > run_start {
                        self.slice_and_bytes(run_start, self.pos, |this, s| {
                            this.emit_attribute_value_content(s, false)
                        })?;
                    }
                    return Ok(AttrValueScanBytes::NeedMore);
                }
                AttrValueRunBytes::Illegal => {
                    return Err(self.fatal("Illegal character or '<' in attribute value"));
                }
                AttrValueRunBytes::Quote => {
                    if self.pos > run_start {
                        self.slice_and_bytes(run_start, self.pos, |this, s| {
                            this.emit_attribute_value_content(s, true)
                        })?;
                    } else {
                        self.emit_attribute_value_content("", true)?;
                    }
                    self.pos += 1;
                    return Ok(AttrValueScanBytes::Done);
                }
                AttrValueRunBytes::Amp => {
                    let amp_pos = self.pos;
                    if amp_pos > run_start {
                        self.slice_and_bytes(run_start, amp_pos, |this, s| {
                            this.emit_attribute_value_content(s, false)
                        })?;
                    }
                    let decoded = match self.decode_entity_ref_bytes()? {
                        RefResult::NeedMore => {
                            self.pos = amp_pos;
                            return Ok(AttrValueScanBytes::NeedMore);
                        }
                        RefResult::General(name) => {
                            self.expand_general_entity_in_attribute_value(&name)?
                        }
                        RefResult::Decoded(s) => s,
                    };
                    let at_quote =
                        self.pos < self.limit && self.buf.as_bytes()[self.pos] == quote;
                    self.emit_attribute_value_content(&decoded, at_quote)?;
                    if at_quote {
                        self.pos += 1;
                        return Ok(AttrValueScanBytes::Done);
                    }
                }
            }
        }
    }

    fn scan_attribute_value_streaming(&mut self) -> ParseResult<bool> {
        let quote = self.pending_quote;
        loop {
            let run_start = self.pos;
            loop {
                while self.pos < self.limit && !self.is_attr_stop(self.buf[self.pos], quote) {
                    self.pos += 1;
                }
                if self.pos >= self.limit {
                    break;
                }
                let c = self.buf[self.pos];
                if c == '\t' || c == '\n' || c == '\r' {
                    self.buf[self.pos] = ' ';
                    self.pos += 1;
                    continue;
                }
                break;
            }
            if self.pos >= self.limit {
                if self.pos > run_start {
                    self.slice_and(run_start, self.pos, |this, s| {
                        this.emit_attribute_value_content(s, false)
                    })?;
                    self.attr_value_run_open = true;
                }
                return Ok(false);
            }
            if self.buf[self.pos] == '<' {
                return Err(self.fatal("'<' is not allowed in an attribute value"));
            }
            if self.buf[self.pos] != quote && self.buf[self.pos] != '&' {
                let c = self.buf[self.pos];
                return Err(self.illegal_char_error(c));
            }
            if self.buf[self.pos] == quote {
                if self.pos > run_start {
                    self.slice_and(run_start, self.pos, |this, s| {
                        this.emit_attribute_value_content(s, true)
                    })?;
                } else {
                    self.emit_attribute_value_content("", true)?;
                }
                self.attr_value_run_open = false;
                self.pos += 1;
                return Ok(true);
            }
            // '&'
            let amp_pos = self.pos;
            if amp_pos > run_start {
                self.slice_and(run_start, amp_pos, |this, s| {
                    this.emit_attribute_value_content(s, false)
                })?;
                self.attr_value_run_open = true;
            }
            let decoded = match self.decode_entity_ref()? {
                RefResult::NeedMore => {
                    self.pos = amp_pos;
                    return Ok(false);
                }
                RefResult::General(name) => self.expand_general_entity_in_attribute_value(&name)?,
                RefResult::Decoded(s) => s,
            };
            let at_quote = self.pos < self.limit && self.buf[self.pos] == quote;
            self.emit_attribute_value_content(&decoded, at_quote)?;
            if at_quote {
                self.attr_value_run_open = false;
                self.pos += 1;
                return Ok(true);
            }
            self.attr_value_run_open = true;
        }
    }

    fn emit_attribute_value_content(&mut self, chunk: &str, end: bool) -> ParseResult<()> {
        if !self.normalizing_current_attribute {
            return self.handler.attribute_value_content(chunk, end);
        }
        self.normalize_builder.push_str(chunk);
        if end {
            let value = if self.collapse_current_attr_value {
                collapse_whitespace(&self.normalize_builder)
            } else {
                self.normalize_builder.clone()
            };
            self.normalizing_current_attribute = false;
            if self.validation_enabled {
                let element = self.current_attr_element_name.clone();
                let name = self.current_attr_name.clone();
                let ty = self.current_attr_type.clone();
                self.check_attribute_value_vcs(&element, &name, &ty, &value)?;
            }
            if self.current_attr_name == "xml:space" && value != "default" && value != "preserve" {
                let msg = format!(
                    "The \"xml:space\" attribute's value must be \"default\" or \"preserve\", not \"{value}\"."
                );
                self.handler.error(&msg)?;
            }
            self.handler.attribute_value_content(&value, true)?;
        }
        Ok(())
    }

    // ===== End tag =====

    fn scan_end_tag(&mut self, tag_start: usize) -> ParseResult<bool> {
        let mut p = tag_start + 2;
        let name_start = p;
        let stack_size = self.element_stack.len();
        if stack_size > 0 {
            let expected = self.element_stack[stack_size - 1].clone();
            let expected_len = expected.chars().count();
            let after_name = name_start + expected_len;
            if after_name < self.limit
                && self.buf[after_name] == '>'
                && self.range_equals(name_start, expected_len, &expected)
                && (self.entity_stack_floors.is_empty()
                    || stack_size > *self.entity_stack_floors.last().unwrap())
            {
                self.element_stack.pop();
                if self.validation_enabled {
                    self.pop_and_validate_element()?;
                }
                self.root_ended = self.element_stack.is_empty();
                self.pos = after_name + 1;
                self.handler.end_element()?;
                return Ok(true);
            }
        }
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == name_start {
            return Err(self.fatal("Malformed end tag"));
        }
        self.check_name_start_char(name_start)?;
        let name_end = p;
        while p < self.limit && is_ws(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.buf[p] != '>' {
            return Err(self.fatal("Malformed end tag"));
        }
        p += 1;

        let name_len = name_end - name_start;
        if self.element_stack.is_empty() {
            let found = self.slice(name_start, name_start + name_len);
            let msg = format!("End tag without matching start tag: {found}");
            return Err(self.fatal(&msg));
        }
        if !self.entity_stack_floors.is_empty()
            && self.element_stack.len() <= *self.entity_stack_floors.last().unwrap()
        {
            let found = self.slice(name_start, name_start + name_len);
            let msg = format!(
                "End tag </{found}> in an entity's replacement text must not close an element that was opened outside that entity (element boundaries must nest within entity boundaries)"
            );
            return Err(self.fatal(&msg));
        }
        let expected = self.element_stack.pop().unwrap();
        if !self.range_equals(name_start, name_len, &expected) {
            let found = self.slice(name_start, name_start + name_len);
            let msg = format!("Mismatched end tag: expected </{expected}> but found </{found}>");
            return Err(self.fatal(&msg));
        }
        if self.validation_enabled {
            self.pop_and_validate_element()?;
        }
        self.root_ended = self.element_stack.is_empty();
        self.pos = p;
        self.handler.end_element()?;
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_end_tag`. The fast-path re-check compares raw byte slices
    /// directly rather than going through a `range_equals`-style helper —
    /// slice `!=` already accounts for a length mismatch (unlike the char
    /// path, which has to compare `expected.chars().count()` against a
    /// char-position span before it can compare content), so no
    /// byte-native `range_equals` port was needed either.
    #[allow(dead_code)]
    fn scan_end_tag_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        let name_start = tag_start + 2;
        let stack_size = self.element_stack.len();
        if stack_size > 0 {
            let expected = self.element_stack[stack_size - 1].clone();
            let expected_bytes = expected.as_bytes();
            let after_name = name_start + expected_bytes.len();
            if after_name < self.limit
                && self.buf.as_bytes()[after_name] == b'>'
                && &self.buf.as_bytes()[name_start..after_name] == expected_bytes
                && (self.entity_stack_floors.is_empty()
                    || stack_size > *self.entity_stack_floors.last().unwrap())
            {
                self.element_stack.pop();
                if self.validation_enabled {
                    self.pop_and_validate_element()?;
                }
                self.root_ended = self.element_stack.is_empty();
                self.pos = after_name + 1;
                self.handler.end_element()?;
                return Ok(true);
            }
        }
        let name_end = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            NameScanBytes::Illegal => return Err(self.fatal("Malformed end tag")),
            NameScanBytes::End(p) => p,
        };
        if name_end == name_start {
            return Err(self.fatal("Malformed end tag"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let mut p = name_end;
        while p < self.limit && is_ws(self.buf.as_bytes()[p] as char) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.buf.as_bytes()[p] != b'>' {
            return Err(self.fatal("Malformed end tag"));
        }
        p += 1;

        if self.element_stack.is_empty() {
            // SAFETY: [name_start, name_end) was validated as a legal XML
            // Name above.
            let found = unsafe {
                std::str::from_utf8_unchecked(&self.buf.as_bytes()[name_start..name_end])
            }
            .to_string();
            let msg = format!("End tag without matching start tag: {found}");
            return Err(self.fatal(&msg));
        }
        if !self.entity_stack_floors.is_empty()
            && self.element_stack.len() <= *self.entity_stack_floors.last().unwrap()
        {
            let found = unsafe {
                std::str::from_utf8_unchecked(&self.buf.as_bytes()[name_start..name_end])
            }
            .to_string();
            let msg = format!(
                "End tag </{found}> in an entity's replacement text must not close an element that was opened outside that entity (element boundaries must nest within entity boundaries)"
            );
            return Err(self.fatal(&msg));
        }
        let expected = self.element_stack.pop().unwrap();
        if &self.buf.as_bytes()[name_start..name_end] != expected.as_bytes() {
            let found = unsafe {
                std::str::from_utf8_unchecked(&self.buf.as_bytes()[name_start..name_end])
            }
            .to_string();
            let msg = format!("Mismatched end tag: expected </{expected}> but found </{found}>");
            return Err(self.fatal(&msg));
        }
        if self.validation_enabled {
            self.pop_and_validate_element()?;
        }
        self.root_ended = self.element_stack.is_empty();
        self.pos = p;
        self.handler.end_element()?;
        Ok(true)
    }

    // ===== Comment / CDATA / PI =====

    fn scan_bang_markup(&mut self, tag_start: usize) -> ParseResult<bool> {
        let p = tag_start + 2;
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        match self.buf[p] {
            '-' => self.scan_comment(tag_start),
            '[' => self.scan_cdata(tag_start),
            'D' => self.scan_doctype(tag_start),
            _ => Err(self.fatal("Malformed markup declaration")),
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_bang_markup`.
    #[allow(dead_code)]
    fn scan_bang_markup_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        let p = tag_start + 2;
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        match self.buf.as_bytes()[p] {
            b'-' => self.scan_comment_bytes(tag_start),
            b'[' => self.scan_cdata_bytes(tag_start),
            b'D' => self.scan_doctype_bytes(tag_start),
            _ => Err(self.fatal("Malformed markup declaration")),
        }
    }

    fn scan_comment(&mut self, tag_start: usize) -> ParseResult<bool> {
        if tag_start + 4 > self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.buf[tag_start + 3] != '-' {
            return Err(self.fatal("Malformed markup declaration"));
        }
        self.handler.start_comment()?;
        self.pos = tag_start + 4;
        if !self.scan_comment_data()? {
            self.in_comment = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn scan_comment_data(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            while p < self.limit && self.buf[p] != '-' {
                if !self.is_legal_literal_char(self.buf[p]) {
                    let c = self.buf[p];
                    return Err(self.illegal_char_error(c));
                }
                p += 1;
            }
            if p >= self.limit || p + 2 >= self.limit {
                if p > self.pos {
                    self.slice_and(self.pos, p, |this, s| this.handler.comment_data(s, false))?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf[p + 1] == '-' {
                if self.buf[p + 2] == '>' {
                    self.slice_and(self.pos, p, |this, s| this.handler.comment_data(s, true))?;
                    self.pos = p + 3;
                    return Ok(true);
                }
                return Err(self.fatal("'--' is not allowed inside a comment"));
            }
            p += 1;
        }
    }

    fn scan_cdata(&mut self, tag_start: usize) -> ParseResult<bool> {
        let marker: Vec<char> = CDATA_MARKER.chars().collect();
        let match_len = marker.len().min(self.limit - tag_start);
        for (i, &mc) in marker.iter().enumerate().take(match_len).skip(2) {
            if self.buf[tag_start + i] != mc {
                return Err(self.fatal("Malformed markup declaration"));
            }
        }
        if tag_start + marker.len() > self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.element_stack.is_empty() {
            return Err(self.fatal("CDATA sections are only allowed within the document element"));
        }
        self.handler.start_cdata()?;
        self.pos = tag_start + marker.len();
        self.cdata_run_open = false;
        if !self.scan_cdata_content()? {
            self.in_cdata = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn scan_cdata_content(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            while p < self.limit && self.buf[p] != ']' {
                if !self.is_legal_literal_char(self.buf[p]) {
                    let c = self.buf[p];
                    return Err(self.illegal_char_error(c));
                }
                p += 1;
            }
            if p >= self.limit || p + 2 >= self.limit {
                if p > self.pos {
                    let start = self.pos;
                    self.emit_cdata_chunk(start, p, false)?;
                    self.cdata_run_open = true;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf[p + 1] == ']' && self.buf[p + 2] == '>' {
                if p > self.pos || self.cdata_run_open {
                    let start = self.pos;
                    self.emit_cdata_chunk(start, p, true)?;
                }
                self.cdata_run_open = false;
                self.pos = p + 3;
                self.handler.end_cdata()?;
                return Ok(true);
            }
            p += 1;
        }
    }

    fn emit_cdata_chunk(&mut self, start: usize, end: usize, is_end: bool) -> ParseResult<()> {
        let non_empty = end > start;
        self.slice_and(start, end, |this, s| {
            this.emit_cdata_chunk_str(s, non_empty, is_end)
        })
    }

    fn emit_cdata_chunk_str(&mut self, s: &str, non_empty: bool, is_end: bool) -> ParseResult<()> {
        // CDATA never matches the nonterminal S (Sun xmlconf empty / not-sa14):
        // even whitespace-only CDATA is character data for Element Valid, not
        // ignorable separator whitespace between children.
        if non_empty && self.validation_enabled {
            self.record_text_for_validation(s, false)?;
        }
        self.handler.characters(s, false, is_end)
    }

    fn scan_pi(&mut self, tag_start: usize) -> ParseResult<bool> {
        let mut p = tag_start + 2;
        let target_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == target_start {
            return Err(self.fatal("Malformed processing instruction"));
        }
        self.check_name_start_char(target_start)?;
        let target = self.name_pool.intern_range(self.buf.as_chars(), target_start, p - target_start);
        let tchars: Vec<char> = target.chars().collect();
        if tchars.len() == 3
            && (tchars[0] == 'x' || tchars[0] == 'X')
            && (tchars[1] == 'm' || tchars[1] == 'M')
            && (tchars[2] == 'l' || tchars[2] == 'L')
        {
            return Err(self.fatal("Processing instruction target matching [Xx][Mm][Ll] is reserved"));
        }
        if self.namespace_aware && target.contains(':') {
            let msg = format!(
                "Processing instruction target \"{target}\" must not contain a colon (Namespaces in XML, Section 6)"
            );
            return Err(self.fatal(&msg));
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if is_ws(self.buf[p]) {
            p += 1;
        } else if self.buf[p] != '?' {
            return Err(self.fatal(
                "White space is required between a processing instruction's target and its data",
            ));
        }
        self.handler.pi_target(&target)?;
        self.pos = p;
        if !self.scan_pi_data()? {
            self.in_pi = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn scan_pi_data(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            while p < self.limit && self.buf[p] != '?' {
                if !self.is_legal_literal_char(self.buf[p]) {
                    let c = self.buf[p];
                    return Err(self.illegal_char_error(c));
                }
                p += 1;
            }
            if p >= self.limit || p + 1 >= self.limit {
                if p > self.pos {
                    self.slice_and(self.pos, p, |this, s| this.handler.pi_data(s, false))?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf[p + 1] == '>' {
                self.slice_and(self.pos, p, |this, s| this.handler.pi_data(s, true))?;
                self.pos = p + 2;
                return Ok(true);
            }
            p += 1;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to the
    /// `while p < self.limit && self.buf[p] != stop { check legality; p += 1 }`
    /// loop shared, in the char path, by `scan_comment_data`,
    /// `scan_cdata_content`, and `scan_pi_data` (looking for `-`, `]`, and
    /// `?` respectively — always ASCII, so no byte in a multi-byte
    /// sequence can ever equal one). ASCII chars are legality-checked
    /// directly; the rare non-ASCII char is decoded on demand, same
    /// pattern as every other byte-native scanner here. Returns the
    /// position reached either way, since callers need it to emit a
    /// partial run before reporting `NeedMore`.
    #[allow(dead_code)]
    fn scan_until_byte_bytes(
        &mut self,
        start: usize,
        stop_byte: u8,
    ) -> ParseResult<LiteralUntilBytes> {
        let mut p = start;
        loop {
            if p >= self.limit {
                return Ok(LiteralUntilBytes::NeedMore(p));
            }
            let b = self.buf.as_bytes()[p];
            if b == stop_byte {
                return Ok(LiteralUntilBytes::Stop(p));
            }
            if b < 0x80 {
                if !self.is_legal_literal_char(b as char) {
                    return Err(self.illegal_char_error(b as char));
                }
                p += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return Err(self.fatal("Ill-formed UTF-8 sequence"));
            }
            if p + seq_len > self.limit {
                return Ok(LiteralUntilBytes::NeedMore(p));
            }
            let slice = &self.buf.as_bytes()[p..p + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return Err(self.fatal("Ill-formed UTF-8 sequence")),
            };
            if !self.is_legal_literal_char(c) {
                return Err(self.illegal_char_error(c));
            }
            p += seq_len;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_comment`.
    #[allow(dead_code)]
    fn scan_comment_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        if tag_start + 4 > self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.buf.as_bytes()[tag_start + 3] != b'-' {
            return Err(self.fatal("Malformed markup declaration"));
        }
        self.handler.start_comment()?;
        self.pos = tag_start + 4;
        if !self.scan_comment_data_bytes()? {
            self.in_comment = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_comment_data`, built on `scan_until_byte_bytes`.
    #[allow(dead_code)]
    fn scan_comment_data_bytes(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            p = match self.scan_until_byte_bytes(p, b'-')? {
                LiteralUntilBytes::NeedMore(p) => {
                    if p > self.pos {
                        self.slice_and_bytes(self.pos, p, |this, s| {
                            this.handler.comment_data(s, false)
                        })?;
                        self.pos = p;
                    }
                    return Ok(false);
                }
                LiteralUntilBytes::Stop(p) => p,
            };
            if p + 2 >= self.limit {
                if p > self.pos {
                    self.slice_and_bytes(self.pos, p, |this, s| {
                        this.handler.comment_data(s, false)
                    })?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf.as_bytes()[p + 1] == b'-' {
                if self.buf.as_bytes()[p + 2] == b'>' {
                    self.slice_and_bytes(self.pos, p, |this, s| {
                        this.handler.comment_data(s, true)
                    })?;
                    self.pos = p + 3;
                    return Ok(true);
                }
                return Err(self.fatal("'--' is not allowed inside a comment"));
            }
            p += 1;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_cdata`. `CDATA_MARKER` is pure ASCII, so its bytes are
    /// compared directly against `CDATA_MARKER.as_bytes()` instead of
    /// going through a `Vec<char>` intermediate.
    #[allow(dead_code)]
    fn scan_cdata_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        let marker = CDATA_MARKER.as_bytes();
        let match_len = marker.len().min(self.limit - tag_start);
        for (i, &mb) in marker.iter().enumerate().take(match_len).skip(2) {
            if self.buf.as_bytes()[tag_start + i] != mb {
                return Err(self.fatal("Malformed markup declaration"));
            }
        }
        if tag_start + marker.len() > self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if self.element_stack.is_empty() {
            return Err(self.fatal("CDATA sections are only allowed within the document element"));
        }
        self.handler.start_cdata()?;
        self.pos = tag_start + marker.len();
        self.cdata_run_open = false;
        if !self.scan_cdata_content_bytes()? {
            self.in_cdata = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_cdata_content`, built on `scan_until_byte_bytes`.
    #[allow(dead_code)]
    fn scan_cdata_content_bytes(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            p = match self.scan_until_byte_bytes(p, b']')? {
                LiteralUntilBytes::NeedMore(p) => {
                    if p > self.pos {
                        let start = self.pos;
                        self.emit_cdata_chunk_bytes(start, p, false)?;
                        self.cdata_run_open = true;
                        self.pos = p;
                    }
                    return Ok(false);
                }
                LiteralUntilBytes::Stop(p) => p,
            };
            if p + 2 >= self.limit {
                if p > self.pos {
                    let start = self.pos;
                    self.emit_cdata_chunk_bytes(start, p, false)?;
                    self.cdata_run_open = true;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf.as_bytes()[p + 1] == b']' && self.buf.as_bytes()[p + 2] == b'>' {
                if p > self.pos || self.cdata_run_open {
                    let start = self.pos;
                    self.emit_cdata_chunk_bytes(start, p, true)?;
                }
                self.cdata_run_open = false;
                self.pos = p + 3;
                self.handler.end_cdata()?;
                return Ok(true);
            }
            p += 1;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `emit_cdata_chunk`. Reuses the existing, representation-agnostic
    /// `emit_cdata_chunk_str` unchanged — it only ever touches the `&str`
    /// it's handed, never `self.buf`.
    #[allow(dead_code)]
    fn emit_cdata_chunk_bytes(&mut self, start: usize, end: usize, is_end: bool) -> ParseResult<()> {
        let non_empty = end > start;
        self.slice_and_bytes(start, end, |this, s| {
            this.emit_cdata_chunk_str(s, non_empty, is_end)
        })
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_pi`. The reserved-`[Xx][Mm][Ll]`-target check and the
    /// namespace-colon check both operate on the already-interned
    /// `target: Rc<str>` via `.chars()`/`.contains(':')` — pure `&str`
    /// operations that never touch `self.buf` — so they're reused
    /// unchanged, same discovery as the entity/attribute-value handler
    /// calls.
    #[allow(dead_code)]
    fn scan_pi_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        let target_start = tag_start + 2;
        let p = match self.scan_name_chars_bytes(target_start) {
            NameScanBytes::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            NameScanBytes::Illegal => return Err(self.fatal("Malformed processing instruction")),
            NameScanBytes::End(p) => p,
        };
        if p == target_start {
            return Err(self.fatal("Malformed processing instruction"));
        }
        self.check_name_start_char_bytes(target_start)?;
        // SAFETY: [target_start, p) was validated as a legal XML Name by
        // scan_name_chars_bytes above.
        let target_str =
            unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[target_start..p]) };
        let target = self.name_pool.intern_str(target_str);
        let tchars: Vec<char> = target.chars().collect();
        if tchars.len() == 3
            && (tchars[0] == 'x' || tchars[0] == 'X')
            && (tchars[1] == 'm' || tchars[1] == 'M')
            && (tchars[2] == 'l' || tchars[2] == 'L')
        {
            return Err(self.fatal("Processing instruction target matching [Xx][Mm][Ll] is reserved"));
        }
        if self.namespace_aware && target.contains(':') {
            let msg = format!(
                "Processing instruction target \"{target}\" must not contain a colon (Namespaces in XML, Section 6)"
            );
            return Err(self.fatal(&msg));
        }
        let mut p = p;
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if is_ws(self.buf.as_bytes()[p] as char) {
            p += 1;
        } else if self.buf.as_bytes()[p] != b'?' {
            return Err(self.fatal(
                "White space is required between a processing instruction's target and its data",
            ));
        }
        self.handler.pi_target(&target)?;
        self.pos = p;
        if !self.scan_pi_data_bytes()? {
            self.in_pi = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_pi_data`, built on `scan_until_byte_bytes`.
    #[allow(dead_code)]
    fn scan_pi_data_bytes(&mut self) -> ParseResult<bool> {
        let mut p = self.pos;
        loop {
            p = match self.scan_until_byte_bytes(p, b'?')? {
                LiteralUntilBytes::NeedMore(p) => {
                    if p > self.pos {
                        self.slice_and_bytes(self.pos, p, |this, s| this.handler.pi_data(s, false))?;
                        self.pos = p;
                    }
                    return Ok(false);
                }
                LiteralUntilBytes::Stop(p) => p,
            };
            if p + 1 >= self.limit {
                if p > self.pos {
                    self.slice_and_bytes(self.pos, p, |this, s| this.handler.pi_data(s, false))?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf.as_bytes()[p + 1] == b'>' {
                self.slice_and_bytes(self.pos, p, |this, s| this.handler.pi_data(s, true))?;
                self.pos = p + 2;
                return Ok(true);
            }
            p += 1;
        }
    }

    // ===== DOCTYPE / DTD =====

    fn match_keyword(&self, p: usize, marker: &str) -> KwResult {
        let mlen = marker.len();
        let match_len = mlen.min(self.limit - p);
        for (i, mc) in marker.chars().enumerate() {
            if i >= match_len {
                break;
            }
            if self.buf[p + i] != mc {
                return KwResult::NoMatch;
            }
        }
        if p + mlen > self.limit {
            return KwResult::NeedMore;
        }
        KwResult::Match
    }

    fn skip_optional_whitespace(&self, mut p: usize) -> usize {
        while p < self.limit && is_ws(self.buf[p]) {
            p += 1;
        }
        p
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `match_keyword`. Every DTD keyword marker (`SYSTEM`, `PUBLIC`,
    /// `<!ENTITY`, ...) is pure ASCII, so bytes are compared directly
    /// against `marker.as_bytes()`.
    #[allow(dead_code)]
    fn match_keyword_bytes(&self, p: usize, marker: &str) -> KwResult {
        let marker = marker.as_bytes();
        let mlen = marker.len();
        let match_len = mlen.min(self.limit - p);
        for (i, &mb) in marker.iter().enumerate() {
            if i >= match_len {
                break;
            }
            if self.buf.as_bytes()[p + i] != mb {
                return KwResult::NoMatch;
            }
        }
        if p + mlen > self.limit {
            return KwResult::NeedMore;
        }
        KwResult::Match
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_optional_whitespace`. `is_ws` is ASCII-only, so `b as char`
    /// is safe for every byte value without a multi-byte decode.
    #[allow(dead_code)]
    fn skip_optional_whitespace_bytes(&self, mut p: usize) -> usize {
        while p < self.limit && is_ws(self.buf.as_bytes()[p] as char) {
            p += 1;
        }
        p
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `slice`. Not a hot-path helper (DTD-declaration-time calls only,
    /// same scope carve-out as `slice` itself), so a plain owned `String`
    /// is fine.
    #[allow(dead_code)]
    fn slice_bytes(&self, start: usize, end: usize) -> String {
        // SAFETY: every caller passes a range bounded by ASCII delimiters
        // and/or a previously-validated Name/literal scan, so [start, end)
        // always lands on a UTF-8 boundary.
        unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[start..end]) }.to_string()
    }

    fn find_quoted_literal_end(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        if p >= self.limit {
            return Ok(None);
        }
        let q = self.buf[p];
        if q != '"' && q != '\'' {
            return Err(self.fatal("Expected quoted literal"));
        }
        p += 1;
        loop {
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf[p] == q {
                return Ok(Some(p + 1));
            }
            p += 1;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `find_quoted_literal_end`. Quote bytes are ASCII, so no byte of a
    /// multi-byte sequence can ever match one — a raw byte scan is safe
    /// without any UTF-8 decoding.
    #[allow(dead_code)]
    fn find_quoted_literal_end_bytes(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        if p >= self.limit {
            return Ok(None);
        }
        let q = self.buf.as_bytes()[p];
        if q != b'"' && q != b'\'' {
            return Err(self.fatal("Expected quoted literal"));
        }
        p += 1;
        loop {
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[p] == q {
                return Ok(Some(p + 1));
            }
            p += 1;
        }
    }

    fn check_pubid_literal(&mut self, public_id: &str) -> ParseResult<()> {
        for c in public_id.chars() {
            if !is_pubid_char(c) {
                let msg = format!(
                    "Character U+{:04X} is not allowed in a public identifier",
                    c as u32
                );
                return Err(self.fatal(&msg));
            }
        }
        Ok(())
    }

    fn check_system_literal_no_fragment(&mut self, system_id: &str) -> ParseResult<()> {
        if system_id.contains('#') {
            let msg = format!("A system identifier may not contain a URI fragment: \"{system_id}\"");
            self.handler.error(&msg)?;
        }
        Ok(())
    }

    fn skip_external_id(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        let is_public;
        match self.match_keyword(p, SYSTEM_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                is_public = false;
                p += SYSTEM_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword(p, PUBLIC_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    is_public = true;
                    p += PUBLIC_MARKER.len();
                }
                KwResult::NoMatch => return Err(self.fatal("Malformed external ID")),
            },
        }
        let ws = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed external ID"));
        }

        self.last_external_id_public_id = None;
        self.last_external_id_system_id = None;

        if is_public {
            let lit_start = p + 1;
            let r = match self.find_quoted_literal_end(p)? {
                None => return Ok(None),
                Some(r) => r,
            };
            let pubid = self.slice(lit_start, r - 1);
            self.check_pubid_literal(&pubid)?;
            self.last_external_id_public_id = Some(pubid);
            p = r;
            let ws2 = p;
            p = self.skip_optional_whitespace(p);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws2 {
                return Err(self.fatal("Malformed external ID"));
            }
        }
        let sys_lit_start = p + 1;
        let sys_end = match self.find_quoted_literal_end(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let sysid = self.slice(sys_lit_start, sys_end - 1);
        self.check_system_literal_no_fragment(&sysid)?;
        self.last_external_id_system_id = Some(sysid);
        Ok(Some(sys_end))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_external_id`. A 1:1 structural port onto the byte-native
    /// primitives above; `check_pubid_literal`/`check_system_literal_no_fragment`
    /// operate on the decoded `&str` values, never `self.buf`, so they're
    /// reused unchanged.
    #[allow(dead_code)]
    fn skip_external_id_bytes(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        let is_public;
        match self.match_keyword_bytes(p, SYSTEM_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                is_public = false;
                p += SYSTEM_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword_bytes(p, PUBLIC_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    is_public = true;
                    p += PUBLIC_MARKER.len();
                }
                KwResult::NoMatch => return Err(self.fatal("Malformed external ID")),
            },
        }
        let ws = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed external ID"));
        }

        self.last_external_id_public_id = None;
        self.last_external_id_system_id = None;

        if is_public {
            let lit_start = p + 1;
            let r = match self.find_quoted_literal_end_bytes(p)? {
                None => return Ok(None),
                Some(r) => r,
            };
            let pubid = self.slice_bytes(lit_start, r - 1);
            self.check_pubid_literal(&pubid)?;
            self.last_external_id_public_id = Some(pubid);
            p = r;
            let ws2 = p;
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws2 {
                return Err(self.fatal("Malformed external ID"));
            }
        }
        let sys_lit_start = p + 1;
        let sys_end = match self.find_quoted_literal_end_bytes(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let sysid = self.slice_bytes(sys_lit_start, sys_end - 1);
        self.check_system_literal_no_fragment(&sysid)?;
        self.last_external_id_system_id = Some(sysid);
        Ok(Some(sys_end))
    }

    fn scan_notation_declaration(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        let ws = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed notation declaration"));
        }
        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == name_start {
            return Err(self.fatal("Malformed notation declaration"));
        }
        self.check_name_start_char(name_start)?;
        let name = self.slice(name_start, p);
        self.check_no_colon_in_namespace_mode(&name, "Notation")?;

        let ws2 = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed notation declaration"));
        }

        let is_public;
        match self.match_keyword(p, SYSTEM_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                is_public = false;
                p += SYSTEM_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword(p, PUBLIC_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    is_public = true;
                    p += PUBLIC_MARKER.len();
                }
                KwResult::NoMatch => return Err(self.fatal("Malformed notation declaration")),
            },
        }
        let ws3 = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws3 {
            return Err(self.fatal("Malformed notation declaration"));
        }
        let r = match self.find_quoted_literal_end(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let mut public_id: Option<String> = None;
        let mut system_id: Option<String> = None;
        if is_public {
            let pid = self.slice(p + 1, r - 1);
            self.check_pubid_literal(&pid)?;
            public_id = Some(pid);
        } else {
            system_id = Some(self.slice(p + 1, r - 1));
        }
        p = r;

        if is_public {
            let after_ws = self.skip_optional_whitespace(p);
            if after_ws >= self.limit {
                return Ok(None);
            }
            if self.buf[after_ws] == '"' || self.buf[after_ws] == '\'' {
                let r2 = match self.find_quoted_literal_end(after_ws)? {
                    None => return Ok(None),
                    Some(r) => r,
                };
                system_id = Some(self.slice(after_ws + 1, r2 - 1));
                p = r2;
            }
        }

        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if self.buf[p] != '>' {
            return Err(self.fatal("Malformed notation declaration"));
        }
        p += 1;

        if let Some(sid) = &system_id {
            self.check_system_literal_no_fragment(sid)?;
        }
        if self.declared_notations.insert(name.clone()) {
            self.notation_external_ids.insert(
                name.clone(),
                ExternalId {
                    public_id: public_id.clone(),
                    system_id: system_id.clone(),
                },
            );
            self.handler
                .notation_decl(&name, public_id.as_deref(), system_id.as_deref())?;
        }
        Ok(Some(p))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_notation_declaration`. Name scanning goes through
    /// `scan_name_chars_bytes`/`check_name_start_char_bytes`; everything
    /// else is a 1:1 port onto the byte-native primitives above.
    #[allow(dead_code)]
    fn scan_notation_declaration_bytes(&mut self, mut p: usize) -> ParseResult<Option<usize>> {
        let ws = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed notation declaration"));
        }
        let name_start = p;
        p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => return Err(self.fatal("Malformed notation declaration")),
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed notation declaration"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name = self.slice_bytes(name_start, p);
        self.check_no_colon_in_namespace_mode(&name, "Notation")?;

        let ws2 = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed notation declaration"));
        }

        let is_public;
        match self.match_keyword_bytes(p, SYSTEM_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                is_public = false;
                p += SYSTEM_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword_bytes(p, PUBLIC_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    is_public = true;
                    p += PUBLIC_MARKER.len();
                }
                KwResult::NoMatch => return Err(self.fatal("Malformed notation declaration")),
            },
        }
        let ws3 = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws3 {
            return Err(self.fatal("Malformed notation declaration"));
        }
        let r = match self.find_quoted_literal_end_bytes(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let mut public_id: Option<String> = None;
        let mut system_id: Option<String> = None;
        if is_public {
            let pid = self.slice_bytes(p + 1, r - 1);
            self.check_pubid_literal(&pid)?;
            public_id = Some(pid);
        } else {
            system_id = Some(self.slice_bytes(p + 1, r - 1));
        }
        p = r;

        if is_public {
            let after_ws = self.skip_optional_whitespace_bytes(p);
            if after_ws >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[after_ws] == b'"' || self.buf.as_bytes()[after_ws] == b'\'' {
                let r2 = match self.find_quoted_literal_end_bytes(after_ws)? {
                    None => return Ok(None),
                    Some(r) => r,
                };
                system_id = Some(self.slice_bytes(after_ws + 1, r2 - 1));
                p = r2;
            }
        }

        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if self.buf.as_bytes()[p] != b'>' {
            return Err(self.fatal("Malformed notation declaration"));
        }
        p += 1;

        if let Some(sid) = &system_id {
            self.check_system_literal_no_fragment(sid)?;
        }
        if self.declared_notations.insert(name.clone()) {
            self.notation_external_ids.insert(
                name.clone(),
                ExternalId {
                    public_id: public_id.clone(),
                    system_id: system_id.clone(),
                },
            );
            self.handler
                .notation_decl(&name, public_id.as_deref(), system_id.as_deref())?;
        }
        Ok(Some(p))
    }

    fn decode_char_ref_into(&mut self, sb: &mut String, q: usize) -> ParseResult<Option<usize>> {
        let mut p = q + 2;
        let mut hex = false;
        if p < self.limit && self.buf[p] == 'x' {
            hex = true;
            p += 1;
        }
        let digits_start = p;
        while p < self.limit && self.buf[p] != ';' {
            let d = self.buf[p];
            let ok = if hex {
                d.is_ascii_hexdigit()
            } else {
                d.is_ascii_digit()
            };
            if !ok {
                return Err(self.fatal("Malformed character reference"));
            }
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == digits_start {
            return Err(self.fatal("Empty character reference"));
        }
        let digits: String = self.buf[digits_start..p].iter().collect();
        let code_point = match u32::from_str_radix(&digits, if hex { 16 } else { 10 }) {
            Ok(v) => v,
            Err(_) => return Err(self.fatal("Malformed character reference")),
        };
        if !is_legal_char_ref_code_point(code_point, self.xml11) {
            let msg = format!("Character reference out of range: {code_point}");
            return Err(self.fatal(&msg));
        }
        self.last_char_ref_code_point = code_point;
        let ch = char::from_u32(code_point)
            .ok_or_else(|| ParseError::new("Character reference out of range"))?;
        sb.push(ch);
        Ok(Some(p + 1))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `decode_char_ref_into`. Digits, `x`, and `;` are all ASCII, so no
    /// multi-byte decoding is ever needed here (same reasoning as
    /// `decode_entity_ref_bytes`'s numeric-reference branch).
    #[allow(dead_code)]
    fn decode_char_ref_into_bytes(&mut self, sb: &mut String, q: usize) -> ParseResult<Option<usize>> {
        let mut p = q + 2;
        let mut hex = false;
        if p < self.limit && self.buf.as_bytes()[p] == b'x' {
            hex = true;
            p += 1;
        }
        let digits_start = p;
        while p < self.limit && self.buf.as_bytes()[p] != b';' {
            let d = self.buf.as_bytes()[p];
            let ok = if hex {
                d.is_ascii_hexdigit()
            } else {
                d.is_ascii_digit()
            };
            if !ok {
                return Err(self.fatal("Malformed character reference"));
            }
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == digits_start {
            return Err(self.fatal("Empty character reference"));
        }
        // SAFETY: every byte in [digits_start, p) was just checked to be an
        // ASCII hex/decimal digit.
        let digits =
            unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[digits_start..p]) };
        let code_point = match u32::from_str_radix(digits, if hex { 16 } else { 10 }) {
            Ok(v) => v,
            Err(_) => return Err(self.fatal("Malformed character reference")),
        };
        if !is_legal_char_ref_code_point(code_point, self.xml11) {
            let msg = format!("Character reference out of range: {code_point}");
            return Err(self.fatal(&msg));
        }
        self.last_char_ref_code_point = code_point;
        let ch = char::from_u32(code_point)
            .ok_or_else(|| ParseError::new("Character reference out of range"))?;
        sb.push(ch);
        Ok(Some(p + 1))
    }

    fn scan_quoted_literal_with_char_refs(
        &mut self,
        p: usize,
        sb: &mut String,
        is_entity_value: bool,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        let quote = self.buf[p];
        let mut q = p + 1;
        self.last_literal_contained_restricted_char = false;
        loop {
            if q >= self.limit {
                return Ok(None);
            }
            let c = self.buf[q];
            if c == quote {
                return Ok(Some(q + 1));
            }
            if c == '&' && q + 1 < self.limit && self.buf[q + 1] == '#' {
                match self.decode_char_ref_into(sb, q)? {
                    None => return Ok(None),
                    Some(r) => {
                        if is_entity_value
                            && self.xml11
                            && self.last_char_ref_code_point <= 0xFFFF
                            && is_restricted_char_xml11(
                                char::from_u32(self.last_char_ref_code_point).unwrap_or('\u{0}'),
                            )
                        {
                            self.last_literal_contained_restricted_char = true;
                        }
                        q = r;
                        continue;
                    }
                }
            }
            if c == '&' && q + 1 >= self.limit {
                return Ok(None);
            }
            if c == '&' {
                match self.scan_reference_name_literal(q, sb, '&')? {
                    None => return Ok(None),
                    Some(r) => {
                        q = r;
                        continue;
                    }
                }
            }
            if is_entity_value && c == '%' {
                if q + 1 >= self.limit {
                    return Ok(None);
                }
                match self.resolve_parameter_entity_reference_at(q, pending)? {
                    None => return Ok(None),
                    Some(replacement) => {
                        for rc in replacement.iter() {
                            sb.push(*rc);
                        }
                        q = self.last_pe_reference_end;
                        continue;
                    }
                }
            }
            if !self.is_legal_literal_char(c) {
                return Err(self.illegal_char_error(c));
            }
            sb.push(c);
            q += 1;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_quoted_literal_with_char_refs`. Every structural byte checked
    /// here (quote, `&`, `#`, `%`) is ASCII; the rare non-ASCII literal
    /// character is decoded on demand, same pattern as every other
    /// byte-native scanner. `resolve_parameter_entity_replacement`'s
    /// `Rc<[char]>` result is pushed into `sb` char-by-char exactly like
    /// the char path — that step was never representation-dependent.
    #[allow(dead_code)]
    fn scan_quoted_literal_with_char_refs_bytes(
        &mut self,
        p: usize,
        sb: &mut String,
        is_entity_value: bool,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        let quote = self.buf.as_bytes()[p];
        let mut q = p + 1;
        self.last_literal_contained_restricted_char = false;
        loop {
            if q >= self.limit {
                return Ok(None);
            }
            let b = self.buf.as_bytes()[q];
            if b == quote {
                return Ok(Some(q + 1));
            }
            if b == b'&' && q + 1 < self.limit && self.buf.as_bytes()[q + 1] == b'#' {
                match self.decode_char_ref_into_bytes(sb, q)? {
                    None => return Ok(None),
                    Some(r) => {
                        if is_entity_value
                            && self.xml11
                            && self.last_char_ref_code_point <= 0xFFFF
                            && is_restricted_char_xml11(
                                char::from_u32(self.last_char_ref_code_point).unwrap_or('\u{0}'),
                            )
                        {
                            self.last_literal_contained_restricted_char = true;
                        }
                        q = r;
                        continue;
                    }
                }
            }
            if b == b'&' && q + 1 >= self.limit {
                return Ok(None);
            }
            if b == b'&' {
                match self.scan_reference_name_literal_bytes(q, sb, '&')? {
                    None => return Ok(None),
                    Some(r) => {
                        q = r;
                        continue;
                    }
                }
            }
            if is_entity_value && b == b'%' {
                if q + 1 >= self.limit {
                    return Ok(None);
                }
                match self.resolve_parameter_entity_reference_at_bytes(q, pending)? {
                    None => return Ok(None),
                    Some(replacement) => {
                        for rc in replacement.iter() {
                            sb.push(*rc);
                        }
                        q = self.last_pe_reference_end;
                        continue;
                    }
                }
            }
            if b < 0x80 {
                if !self.is_legal_literal_char(b as char) {
                    return Err(self.illegal_char_error(b as char));
                }
                sb.push(b as char);
                q += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 {
                return Err(self.fatal("Ill-formed UTF-8 sequence"));
            }
            if q + seq_len > self.limit {
                return Ok(None);
            }
            let slice = &self.buf.as_bytes()[q..q + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return Err(self.fatal("Ill-formed UTF-8 sequence")),
            };
            if !self.is_legal_literal_char(c) {
                return Err(self.illegal_char_error(c));
            }
            sb.push(c);
            q += seq_len;
        }
    }

    fn scan_reference_name_literal(
        &mut self,
        q: usize,
        sb: &mut String,
        marker: char,
    ) -> ParseResult<Option<usize>> {
        let name_start = q + 1;
        let mut r = name_start;
        while r < self.limit && is_name_char(self.buf[r]) {
            r += 1;
        }
        if r >= self.limit {
            return Ok(None);
        }
        if r == name_start || self.buf[r] != ';' {
            let kind = if marker == '%' {
                "parameter entity"
            } else {
                "entity"
            };
            let msg = format!("A literal '{marker}' must begin a {kind} reference ({marker}Name;)");
            return Err(self.fatal(&msg));
        }
        self.check_name_start_char(name_start)?;
        for i in q..=r {
            sb.push(self.buf[i]);
        }
        Ok(Some(r + 1))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_reference_name_literal`. `[q, r+1)` spans the ASCII marker
    /// byte (`&`/`%`), a validated Name (`scan_name_chars_bytes` already
    /// confirms `End(r)` only ever lands at a byte boundary, since it
    /// advances a whole UTF-8 sequence at a time), and the ASCII `;` — so
    /// the whole range decodes as one `push_str`, no char-by-char loop
    /// needed.
    #[allow(dead_code)]
    fn scan_reference_name_literal_bytes(
        &mut self,
        q: usize,
        sb: &mut String,
        marker: char,
    ) -> ParseResult<Option<usize>> {
        let name_start = q + 1;
        let r = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => return Err(self.fatal("Malformed reference")),
            NameScanBytes::End(r) => r,
        };
        if r == name_start || self.buf.as_bytes()[r] != b';' {
            let kind = if marker == '%' {
                "parameter entity"
            } else {
                "entity"
            };
            let msg = format!("A literal '{marker}' must begin a {kind} reference ({marker}Name;)");
            return Err(self.fatal(&msg));
        }
        self.check_name_start_char_bytes(name_start)?;
        // SAFETY: see doc comment above.
        let literal = unsafe { std::str::from_utf8_unchecked(&self.buf.as_bytes()[q..=r]) };
        sb.push_str(literal);
        Ok(Some(r + 1))
    }

    fn report_unparsed_entities(&mut self, external_names: &HashMap<String, ExtEntity>) -> ParseResult<()> {
        let entries: Vec<(String, ExtEntity)> = external_names
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (name, ids) in entries {
            if let Some(notation) = &ids.ndata {
                self.handler.unparsed_entity_decl(
                    &name,
                    ids.public_id.as_deref(),
                    ids.system_id.as_deref(),
                    notation,
                )?;
            }
        }
        Ok(())
    }

    fn scan_entity_declaration(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed entity declaration"));
        }

        let mut is_param = false;
        if self.buf[p] == '%' {
            is_param = true;
            let ws3 = p + 1;
            p = self.skip_optional_whitespace(p + 1);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws3 {
                return Err(self.fatal("Malformed parameter entity declaration"));
            }
        }

        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == name_start {
            return Err(self.fatal("Malformed entity declaration"));
        }
        self.check_name_start_char(name_start)?;
        let name = self.slice(name_start, p);
        self.check_no_colon_in_namespace_mode(&name, "Entity")?;

        let ws2 = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed entity declaration"));
        }

        if self.buf[p] == '"' || self.buf[p] == '\'' {
            let mut sb = String::new();
            let q = match self.scan_quoted_literal_with_char_refs(p, &mut sb, true, pending)? {
                None => return Ok(None),
                Some(q) => q,
            };
            p = q;
            p = self.skip_optional_whitespace(p);
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf[p] != '>' {
                return Err(self.fatal("Malformed entity declaration"));
            }
            self.check_not_from_pe_splice(p, "an <!ENTITY> declaration")?;
            p += 1;

            if is_param {
                if !pending.param_entities.contains_key(&name)
                    && !pending.param_external_names.contains_key(&name)
                    && !self.parameter_entities.contains_key(&name)
                    && !self.parameter_entity_external_ids.contains_key(&name)
                {
                    let decoded: Rc<[char]> = sb.chars().collect::<Vec<char>>().into();
                    pending.param_entities.insert(name.clone(), decoded);
                    self.handler.internal_entity_decl(&format!("%{name}"), &sb)?;
                }
            } else if !pending.entities.contains_key(&name)
                && !pending.external_names.contains_key(&name)
                && !self.general_entities.contains_key(&name)
                && !self.external_entity_names.contains_key(&name)
            {
                let decoded: Rc<[char]> = sb.chars().collect::<Vec<char>>().into();
                pending.entities.insert(name.clone(), decoded);
                self.handler.internal_entity_decl(&name, &sb)?;
                if self.last_literal_contained_restricted_char {
                    self.restricted_char_entities.insert(name.clone());
                }
                if self.parsing_external_content {
                    self.externally_declared_general_entities.insert(name.clone());
                }
            }
            return Ok(Some(p));
        }

        let r = match self.skip_external_id(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let ext_public_id = self.last_external_id_public_id.clone();
        let ext_system_id = self.last_external_id_system_id.clone();
        p = r;

        let ws_before_ndata = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            return Ok(None);
        }
        let mut ndata_name: Option<String> = None;
        if self.buf[p] != '>' {
            match self.match_keyword(p, NDATA_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {}
                KwResult::NoMatch => return Err(self.fatal("Malformed entity declaration")),
            }
            if p == ws_before_ndata {
                return Err(self.fatal("White space is required before \"NDATA\""));
            }
            if is_param {
                return Err(self.fatal("Parameter entities may not have an NDATA annotation"));
            }
            p += NDATA_MARKER.len();
            let ws_n = p;
            p = self.skip_optional_whitespace(p);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws_n {
                return Err(self.fatal("Malformed entity declaration"));
            }
            let ndata_name_start = p;
            while p < self.limit && is_name_char(self.buf[p]) {
                p += 1;
            }
            if p >= self.limit {
                return Ok(None);
            }
            if p == ndata_name_start {
                return Err(self.fatal("Malformed entity declaration"));
            }
            self.check_name_start_char(ndata_name_start)?;
            ndata_name = Some(self.slice(ndata_name_start, p));
            p = self.skip_optional_whitespace(p);
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf[p] != '>' {
                return Err(self.fatal("Malformed entity declaration"));
            }
        }
        self.check_not_from_pe_splice(p, "an <!ENTITY> declaration")?;
        p += 1;

        if is_param {
            if !pending.param_entities.contains_key(&name)
                && !pending.param_external_names.contains_key(&name)
                && !self.parameter_entities.contains_key(&name)
                && !self.parameter_entity_external_ids.contains_key(&name)
            {
                pending.param_external_names.insert(
                    name.clone(),
                    ExtPe {
                        public_id: ext_public_id.clone(),
                        system_id: ext_system_id.clone(),
                        decl_base: self.base_system_id.clone(),
                    },
                );
                self.handler.external_entity_decl(
                    &format!("%{name}"),
                    ext_public_id.as_deref(),
                    ext_system_id.as_deref().unwrap_or(""),
                )?;
            }
        } else if !pending.entities.contains_key(&name)
            && !pending.external_names.contains_key(&name)
            && !self.general_entities.contains_key(&name)
            && !self.external_entity_names.contains_key(&name)
        {
            pending.external_names.insert(
                name.clone(),
                ExtEntity {
                    public_id: ext_public_id.clone(),
                    system_id: ext_system_id.clone(),
                    ndata: ndata_name.clone(),
                },
            );
            if ndata_name.is_none() {
                self.handler.external_entity_decl(
                    &name,
                    ext_public_id.as_deref(),
                    ext_system_id.as_deref().unwrap_or(""),
                )?;
            }
            if self.parsing_external_content {
                self.externally_declared_general_entities.insert(name.clone());
            }
        }
        Ok(Some(p))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_entity_declaration`. A 1:1 structural port onto the
    /// byte-native primitives above; `check_no_colon_in_namespace_mode`/
    /// `check_not_from_pe_splice` and the `pending`/`self.*_entities`
    /// bookkeeping are unchanged since none of it touches `self.buf`.
    #[allow(dead_code)]
    fn scan_entity_declaration_bytes(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed entity declaration"));
        }

        let mut is_param = false;
        if self.buf.as_bytes()[p] == b'%' {
            is_param = true;
            let ws3 = p + 1;
            p = self.skip_optional_whitespace_bytes(p + 1);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws3 {
                return Err(self.fatal("Malformed parameter entity declaration"));
            }
        }

        let name_start = p;
        p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => return Err(self.fatal("Malformed entity declaration")),
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed entity declaration"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name = self.slice_bytes(name_start, p);
        self.check_no_colon_in_namespace_mode(&name, "Entity")?;

        let ws2 = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed entity declaration"));
        }

        if self.buf.as_bytes()[p] == b'"' || self.buf.as_bytes()[p] == b'\'' {
            let mut sb = String::new();
            let q = match self.scan_quoted_literal_with_char_refs_bytes(p, &mut sb, true, pending)?
            {
                None => return Ok(None),
                Some(q) => q,
            };
            p = q;
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[p] != b'>' {
                return Err(self.fatal("Malformed entity declaration"));
            }
            self.check_not_from_pe_splice(p, "an <!ENTITY> declaration")?;
            p += 1;

            if is_param {
                if !pending.param_entities.contains_key(&name)
                    && !pending.param_external_names.contains_key(&name)
                    && !self.parameter_entities.contains_key(&name)
                    && !self.parameter_entity_external_ids.contains_key(&name)
                {
                    let decoded: Rc<[char]> = sb.chars().collect::<Vec<char>>().into();
                    pending.param_entities.insert(name.clone(), decoded);
                    self.handler.internal_entity_decl(&format!("%{name}"), &sb)?;
                }
            } else if !pending.entities.contains_key(&name)
                && !pending.external_names.contains_key(&name)
                && !self.general_entities.contains_key(&name)
                && !self.external_entity_names.contains_key(&name)
            {
                let decoded: Rc<[char]> = sb.chars().collect::<Vec<char>>().into();
                pending.entities.insert(name.clone(), decoded);
                self.handler.internal_entity_decl(&name, &sb)?;
                if self.last_literal_contained_restricted_char {
                    self.restricted_char_entities.insert(name.clone());
                }
                if self.parsing_external_content {
                    self.externally_declared_general_entities.insert(name.clone());
                }
            }
            return Ok(Some(p));
        }

        let r = match self.skip_external_id_bytes(p)? {
            None => return Ok(None),
            Some(r) => r,
        };
        let ext_public_id = self.last_external_id_public_id.clone();
        let ext_system_id = self.last_external_id_system_id.clone();
        p = r;

        let ws_before_ndata = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            return Ok(None);
        }
        let mut ndata_name: Option<String> = None;
        if self.buf.as_bytes()[p] != b'>' {
            match self.match_keyword_bytes(p, NDATA_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {}
                KwResult::NoMatch => return Err(self.fatal("Malformed entity declaration")),
            }
            if p == ws_before_ndata {
                return Err(self.fatal("White space is required before \"NDATA\""));
            }
            if is_param {
                return Err(self.fatal("Parameter entities may not have an NDATA annotation"));
            }
            p += NDATA_MARKER.len();
            let ws_n = p;
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws_n {
                return Err(self.fatal("Malformed entity declaration"));
            }
            let ndata_name_start = p;
            p = match self.scan_name_chars_bytes(ndata_name_start) {
                NameScanBytes::NeedMore => return Ok(None),
                NameScanBytes::Illegal => {
                    return Err(self.fatal("Malformed entity declaration"));
                }
                NameScanBytes::End(p) => p,
            };
            if p == ndata_name_start {
                return Err(self.fatal("Malformed entity declaration"));
            }
            self.check_name_start_char_bytes(ndata_name_start)?;
            ndata_name = Some(self.slice_bytes(ndata_name_start, p));
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[p] != b'>' {
                return Err(self.fatal("Malformed entity declaration"));
            }
        }
        self.check_not_from_pe_splice(p, "an <!ENTITY> declaration")?;
        p += 1;

        if is_param {
            if !pending.param_entities.contains_key(&name)
                && !pending.param_external_names.contains_key(&name)
                && !self.parameter_entities.contains_key(&name)
                && !self.parameter_entity_external_ids.contains_key(&name)
            {
                pending.param_external_names.insert(
                    name.clone(),
                    ExtPe {
                        public_id: ext_public_id.clone(),
                        system_id: ext_system_id.clone(),
                        decl_base: self.base_system_id.clone(),
                    },
                );
                self.handler.external_entity_decl(
                    &format!("%{name}"),
                    ext_public_id.as_deref(),
                    ext_system_id.as_deref().unwrap_or(""),
                )?;
            }
        } else if !pending.entities.contains_key(&name)
            && !pending.external_names.contains_key(&name)
            && !self.general_entities.contains_key(&name)
            && !self.external_entity_names.contains_key(&name)
        {
            pending.external_names.insert(
                name.clone(),
                ExtEntity {
                    public_id: ext_public_id.clone(),
                    system_id: ext_system_id.clone(),
                    ndata: ndata_name.clone(),
                },
            );
            if ndata_name.is_none() {
                self.handler.external_entity_decl(
                    &name,
                    ext_public_id.as_deref(),
                    ext_system_id.as_deref().unwrap_or(""),
                )?;
            }
            if self.parsing_external_content {
                self.externally_declared_general_entities.insert(name.clone());
            }
        }
        Ok(Some(p))
    }

    fn scan_enumeration_list(
        &mut self,
        p: usize,
        require_name_start_char: bool,
    ) -> ParseResult<Option<usize>> {
        let mut values: Vec<String> = Vec::new();
        let mut q = p + 1;
        loop {
            q = self.skip_optional_whitespace(q);
            if q >= self.limit {
                return Ok(None);
            }
            let token_start = q;
            while q < self.limit && is_name_char(self.buf[q]) {
                q += 1;
            }
            if q >= self.limit {
                return Ok(None);
            }
            if q == token_start {
                return Err(self.fatal("Malformed enumeration"));
            }
            if require_name_start_char {
                self.check_name_start_char(token_start)?;
            }
            let token = self.slice(token_start, q);
            if self.validation_enabled && values.contains(&token) {
                let msg = format!(
                    "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{token}\" appears more than once in this attribute's enumerated type."
                );
                self.handler.error(&msg)?;
            }
            values.push(token);
            q = self.skip_optional_whitespace(q);
            if q >= self.limit {
                return Ok(None);
            }
            if self.buf[q] == '|' {
                q += 1;
                continue;
            }
            if self.buf[q] == ')' {
                q += 1;
                break;
            }
            return Err(self.fatal("Malformed enumeration"));
        }
        self.last_enumeration_values = Some(values);
        Ok(Some(q))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_enumeration_list`. A 1:1 structural port onto the byte-native
    /// primitives above.
    #[allow(dead_code)]
    fn scan_enumeration_list_bytes(
        &mut self,
        p: usize,
        require_name_start_char: bool,
    ) -> ParseResult<Option<usize>> {
        let mut values: Vec<String> = Vec::new();
        let mut q = p + 1;
        loop {
            q = self.skip_optional_whitespace_bytes(q);
            if q >= self.limit {
                return Ok(None);
            }
            let token_start = q;
            q = match self.scan_name_chars_bytes(token_start) {
                NameScanBytes::NeedMore => return Ok(None),
                NameScanBytes::Illegal => return Err(self.fatal("Malformed enumeration")),
                NameScanBytes::End(q) => q,
            };
            if q == token_start {
                return Err(self.fatal("Malformed enumeration"));
            }
            if require_name_start_char {
                self.check_name_start_char_bytes(token_start)?;
            }
            let token = self.slice_bytes(token_start, q);
            if self.validation_enabled && values.contains(&token) {
                let msg = format!(
                    "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{token}\" appears more than once in this attribute's enumerated type."
                );
                self.handler.error(&msg)?;
            }
            values.push(token);
            q = self.skip_optional_whitespace_bytes(q);
            if q >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[q] == b'|' {
                q += 1;
                continue;
            }
            if self.buf.as_bytes()[q] == b')' {
                q += 1;
                break;
            }
            return Err(self.fatal("Malformed enumeration"));
        }
        self.last_enumeration_values = Some(values);
        Ok(Some(q))
    }

    fn scan_element_declaration(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_whitespace_in_declaration(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed element declaration"));
        }

        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == name_start {
            return Err(self.fatal("Malformed element declaration"));
        }
        self.check_name_start_char(name_start)?;
        let name = self.slice(name_start, p);

        let ws2 = p;
        let validation = self.validation_enabled;
        p = self.skip_whitespace_in_declaration(p, pending, validation)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed element declaration"));
        }

        let content_type;
        let mut model: Option<ContentModel> = None;
        match self.match_keyword(p, EMPTY_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                content_type = ContentType::Empty;
                p += EMPTY_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword(p, ANY_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    content_type = ContentType::Any;
                    p += ANY_MARKER.len();
                }
                KwResult::NoMatch => {
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if self.buf[p] != '(' {
                        return Err(self.fatal("Malformed element declaration"));
                    }
                    let model_start = p;
                    let after_paren = self.skip_optional_whitespace(p + 1);
                    if after_paren >= self.limit {
                        return Ok(None);
                    }
                    match self.match_keyword(after_paren, PCDATA_MARKER) {
                        KwResult::NeedMore => return Ok(None),
                        KwResult::Match => content_type = ContentType::Mixed,
                        KwResult::NoMatch => content_type = ContentType::Element,
                    }
                    let mut depth = 0i32;
                    loop {
                        if p >= self.limit {
                            return Ok(None);
                        }
                        let c = self.buf[p];
                        if c == '%' {
                            p = self.splice_pe_reference_at(p, pending, validation)?;
                            if p >= self.limit {
                                return Ok(None);
                            }
                            continue;
                        }
                        p += 1;
                        if c == '(' {
                            depth += 1;
                        } else if c == ')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if self.buf[p] == '?' || self.buf[p] == '*' || self.buf[p] == '+' {
                        p += 1;
                    }
                    self.cm_pos = model_start;
                    self.cm_end = p;
                    model = Some(self.parse_content_model_group(true)?);
                }
            },
        }

        p = self.skip_whitespace_in_declaration(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if self.buf[p] != '>' {
            return Err(self.fatal("Malformed element declaration"));
        }
        self.check_not_from_pe_splice(p, "an <!ELEMENT> declaration")?;
        p += 1;

        if self.validation_enabled && self.dtd_model.get_element_declaration(&name).is_some() {
            let msg = format!(
                "Validity Constraint: Unique Element Type Declaration (Section 3.2). Element \"{name}\" is already declared."
            );
            self.handler.error(&msg)?;
        }
        let mut decl = ElementDeclaration::new(name.clone(), content_type);
        decl.content_model = model.clone();
        decl.from_external_subset = self.parsing_external_content;
        let model_str = match &model {
            Some(m) => m.to_string(),
            None => content_type.name().to_string(),
        };
        if self.dtd_model.declare_element(&name, decl) {
            self.handler.element_decl(&name, &model_str)?;
        }
        Ok(Some(p))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_element_declaration`. A 1:1 structural port onto the
    /// byte-native primitives above, including `splice_pe_reference_at_bytes`
    /// for PE references used as declaration separators or inside the
    /// content model text itself (both real, if uncommon, cases in
    /// external-subset DTDs). Once the matching close-paren is located,
    /// `self.cm_pos`/`self.cm_end` mark a byte range for
    /// `parse_content_model_group_bytes` to walk -- content model text is
    /// always fully buffered by this point.
    #[allow(dead_code)]
    fn scan_element_declaration_bytes(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed element declaration"));
        }

        let name_start = p;
        p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => return Err(self.fatal("Malformed element declaration")),
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed element declaration"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name = self.slice_bytes(name_start, p);

        let ws2 = p;
        let validation = self.validation_enabled;
        p = self.skip_whitespace_in_declaration_bytes(p, pending, validation)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws2 {
            return Err(self.fatal("Malformed element declaration"));
        }

        let content_type;
        let mut model: Option<ContentModel> = None;
        match self.match_keyword_bytes(p, EMPTY_MARKER) {
            KwResult::NeedMore => return Ok(None),
            KwResult::Match => {
                content_type = ContentType::Empty;
                p += EMPTY_MARKER.len();
            }
            KwResult::NoMatch => match self.match_keyword_bytes(p, ANY_MARKER) {
                KwResult::NeedMore => return Ok(None),
                KwResult::Match => {
                    content_type = ContentType::Any;
                    p += ANY_MARKER.len();
                }
                KwResult::NoMatch => {
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if self.buf.as_bytes()[p] != b'(' {
                        return Err(self.fatal("Malformed element declaration"));
                    }
                    let model_start = p;
                    let after_paren = self.skip_optional_whitespace_bytes(p + 1);
                    if after_paren >= self.limit {
                        return Ok(None);
                    }
                    match self.match_keyword_bytes(after_paren, PCDATA_MARKER) {
                        KwResult::NeedMore => return Ok(None),
                        KwResult::Match => content_type = ContentType::Mixed,
                        KwResult::NoMatch => content_type = ContentType::Element,
                    }
                    let mut depth = 0i32;
                    loop {
                        if p >= self.limit {
                            return Ok(None);
                        }
                        let c = self.buf.as_bytes()[p];
                        if c == b'%' {
                            p = self.splice_pe_reference_at_bytes(p, pending, validation)?;
                            if p >= self.limit {
                                return Ok(None);
                            }
                            continue;
                        }
                        p += 1;
                        if c == b'(' {
                            depth += 1;
                        } else if c == b')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if self.buf.as_bytes()[p] == b'?'
                        || self.buf.as_bytes()[p] == b'*'
                        || self.buf.as_bytes()[p] == b'+'
                    {
                        p += 1;
                    }
                    self.cm_pos = model_start;
                    self.cm_end = p;
                    model = Some(self.parse_content_model_group_bytes(true)?);
                }
            },
        }

        p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if self.buf.as_bytes()[p] != b'>' {
            return Err(self.fatal("Malformed element declaration"));
        }
        self.check_not_from_pe_splice(p, "an <!ELEMENT> declaration")?;
        p += 1;

        if self.validation_enabled && self.dtd_model.get_element_declaration(&name).is_some() {
            let msg = format!(
                "Validity Constraint: Unique Element Type Declaration (Section 3.2). Element \"{name}\" is already declared."
            );
            self.handler.error(&msg)?;
        }
        let mut decl = ElementDeclaration::new(name.clone(), content_type);
        decl.content_model = model.clone();
        decl.from_external_subset = self.parsing_external_content;
        let model_str = match &model {
            Some(m) => m.to_string(),
            None => content_type.name().to_string(),
        };
        if self.dtd_model.declare_element(&name, decl) {
            self.handler.element_decl(&name, &model_str)?;
        }
        Ok(Some(p))
    }

    // ===== Content model tree parsing =====

    fn skip_cm_whitespace(&self, mut p: usize) -> usize {
        while p < self.cm_end && is_ws(self.buf[p]) {
            p += 1;
        }
        p
    }

    fn read_cm_occurrence(&mut self) -> Occurrence {
        if self.cm_pos < self.cm_end {
            let c = self.buf[self.cm_pos];
            if c == '?' {
                self.cm_pos += 1;
                return Occurrence::Optional;
            }
            if c == '*' {
                self.cm_pos += 1;
                return Occurrence::ZeroOrMore;
            }
            if c == '+' {
                self.cm_pos += 1;
                return Occurrence::OneOrMore;
            }
        }
        Occurrence::Once
    }

    fn parse_content_model_particle(&mut self) -> ParseResult<ContentModel> {
        self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
        if self.cm_pos < self.cm_end && self.buf[self.cm_pos] == '(' {
            return self.parse_content_model_group(false);
        }
        let name_start = self.cm_pos;
        while self.cm_pos < self.cm_end && is_name_char(self.buf[self.cm_pos]) {
            self.cm_pos += 1;
        }
        if self.cm_pos == name_start {
            return Err(self.fatal("Malformed content model"));
        }
        self.check_name_start_char(name_start)?;
        let element_name = self.slice(name_start, self.cm_pos);
        let occ = self.read_cm_occurrence();
        Ok(ContentModel::leaf(NodeType::Element, Some(element_name), occ))
    }

    fn parse_content_model_group(&mut self, allow_mixed: bool) -> ParseResult<ContentModel> {
        self.cm_pos += 1; // consume '('
        self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
        let pm = self.match_keyword_cm(self.cm_pos, PCDATA_MARKER);
        if pm && !allow_mixed {
            return Err(self.fatal(
                "\"#PCDATA\" is only legal in an element declaration's own outermost content model group, not nested inside another group",
            ));
        }
        if pm {
            self.cm_pos += PCDATA_MARKER.len();
            let mut children: Vec<ContentModel> = Vec::new();
            children.push(ContentModel::leaf(NodeType::Pcdata, None, Occurrence::Once));
            self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
            while self.cm_pos < self.cm_end && self.buf[self.cm_pos] == '|' {
                self.cm_pos += 1;
                self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
                let name_start = self.cm_pos;
                while self.cm_pos < self.cm_end && is_name_char(self.buf[self.cm_pos]) {
                    self.cm_pos += 1;
                }
                if self.cm_pos == name_start {
                    return Err(self.fatal("Malformed content model"));
                }
                self.check_name_start_char(name_start)?;
                let mixed_name = self.slice(name_start, self.cm_pos);
                if self.validation_enabled {
                    let dup = children.iter().skip(1).any(|c| {
                        c.element_name.as_deref() == Some(mixed_name.as_str())
                    });
                    if dup {
                        let msg = format!(
                            "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{mixed_name}\" appears more than once in this mixed-content declaration."
                        );
                        self.handler.error(&msg)?;
                    }
                }
                children.push(ContentModel::leaf(
                    NodeType::Element,
                    Some(mixed_name),
                    Occurrence::Once,
                ));
                self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
            }
            if self.cm_pos >= self.cm_end || self.buf[self.cm_pos] != ')' {
                return Err(self.fatal("Malformed content model"));
            }
            self.cm_pos += 1;
            let has_element_names = children.len() > 1;
            let occ;
            if has_element_names {
                if self.cm_pos >= self.cm_end || self.buf[self.cm_pos] != '*' {
                    return Err(self.fatal(
                        "A mixed-content declaration with element names must end with \")*\"",
                    ));
                }
                self.cm_pos += 1;
                occ = Occurrence::ZeroOrMore;
            } else if self.cm_pos < self.cm_end
                && (self.buf[self.cm_pos] == '?' || self.buf[self.cm_pos] == '+')
            {
                let ch = self.buf[self.cm_pos];
                let msg = format!(
                    "\"(#PCDATA)\" may not be followed by a \"{ch}\" occurrence indicator"
                );
                return Err(self.fatal(&msg));
            } else if self.cm_pos < self.cm_end && self.buf[self.cm_pos] == '*' {
                self.cm_pos += 1;
                occ = Occurrence::ZeroOrMore;
            } else {
                occ = Occurrence::Once;
            }
            return Ok(ContentModel::group(NodeType::Choice, children, occ));
        }

        let mut children: Vec<ContentModel> = Vec::new();
        children.push(self.parse_content_model_particle()?);
        self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
        let mut separator = '\u{0}';
        while self.cm_pos < self.cm_end
            && (self.buf[self.cm_pos] == ',' || self.buf[self.cm_pos] == '|')
        {
            let sep = self.buf[self.cm_pos];
            if separator == '\u{0}' {
                separator = sep;
            } else if separator != sep {
                return Err(self.fatal("Cannot mix ',' and '|' within the same content model group"));
            }
            self.cm_pos += 1;
            self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
            children.push(self.parse_content_model_particle()?);
            self.cm_pos = self.skip_cm_whitespace(self.cm_pos);
        }
        if self.cm_pos >= self.cm_end || self.buf[self.cm_pos] != ')' {
            return Err(self.fatal("Malformed content model"));
        }
        self.cm_pos += 1;
        let group_occ = self.read_cm_occurrence();
        let group_type = if separator == '|' {
            NodeType::Choice
        } else {
            NodeType::Sequence
        };
        if group_type == NodeType::Choice {
            for i in 0..children.len() {
                if children[i].node_type != NodeType::Element {
                    continue;
                }
                for j in 0..i {
                    if children[j].node_type == NodeType::Element
                        && children[i].element_name == children[j].element_name
                    {
                        let dup = children[i].element_name.clone().unwrap_or_default();
                        let msg = format!(
                            "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{dup}\" appears more than once in this choice group."
                        );
                        self.handler.error(&msg)?;
                        break;
                    }
                }
            }
        }
        Ok(ContentModel::group(group_type, children, group_occ))
    }

    fn match_keyword_cm(&self, p: usize, marker: &str) -> bool {
        let mlen = marker.len();
        if p + mlen > self.cm_end {
            return false;
        }
        for (i, mc) in marker.chars().enumerate() {
            if self.buf[p + i] != mc {
                return false;
            }
        }
        true
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_cm_whitespace`.
    #[allow(dead_code)]
    fn skip_cm_whitespace_bytes(&self, mut p: usize) -> usize {
        while p < self.cm_end && is_ws(self.buf.as_bytes()[p] as char) {
            p += 1;
        }
        p
    }

    /// Exploratory (explore/utf8-byte-path): advances `self.cm_pos` past a
    /// run of NameChars, bounded by `self.cm_end` rather than `self.limit`
    /// -- unlike every other name-scanning helper in this file, content
    /// model text is always fully buffered by the time this runs (the
    /// caller only invokes `parse_content_model_group_bytes` after
    /// locating the matching close-paren via a full depth-tracking scan),
    /// so there's no `NeedMore` outcome to report here at all.
    #[allow(dead_code)]
    fn advance_cm_name_bytes(&mut self) -> ParseResult<()> {
        loop {
            if self.cm_pos >= self.cm_end {
                return Ok(());
            }
            let b = self.buf.as_bytes()[self.cm_pos];
            if b < 0x80 {
                if !is_name_char(b as char) {
                    return Ok(());
                }
                self.cm_pos += 1;
                continue;
            }
            let seq_len = utf8_seq_len(b);
            if seq_len == 0 || self.cm_pos + seq_len > self.cm_end {
                return Err(self.fatal("Ill-formed UTF-8 sequence"));
            }
            let slice = &self.buf.as_bytes()[self.cm_pos..self.cm_pos + seq_len];
            let c = match std::str::from_utf8(slice) {
                Ok(s) => s.chars().next().unwrap(),
                Err(_) => return Err(self.fatal("Ill-formed UTF-8 sequence")),
            };
            if !is_name_char(c) {
                return Ok(());
            }
            self.cm_pos += seq_len;
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `read_cm_occurrence`. `?`/`*`/`+` are ASCII.
    #[allow(dead_code)]
    fn read_cm_occurrence_bytes(&mut self) -> Occurrence {
        if self.cm_pos < self.cm_end {
            let b = self.buf.as_bytes()[self.cm_pos];
            if b == b'?' {
                self.cm_pos += 1;
                return Occurrence::Optional;
            }
            if b == b'*' {
                self.cm_pos += 1;
                return Occurrence::ZeroOrMore;
            }
            if b == b'+' {
                self.cm_pos += 1;
                return Occurrence::OneOrMore;
            }
        }
        Occurrence::Once
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `parse_content_model_particle`.
    #[allow(dead_code)]
    fn parse_content_model_particle_bytes(&mut self) -> ParseResult<ContentModel> {
        self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
        if self.cm_pos < self.cm_end && self.buf.as_bytes()[self.cm_pos] == b'(' {
            return self.parse_content_model_group_bytes(false);
        }
        let name_start = self.cm_pos;
        self.advance_cm_name_bytes()?;
        if self.cm_pos == name_start {
            return Err(self.fatal("Malformed content model"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let element_name = self.slice_bytes(name_start, self.cm_pos);
        let occ = self.read_cm_occurrence_bytes();
        Ok(ContentModel::leaf(NodeType::Element, Some(element_name), occ))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `parse_content_model_group`. A 1:1 structural port -- every
    /// structural byte checked here (`(`, `)`, `|`, `,`, `?`, `*`, `+`,
    /// whitespace, `#PCDATA`) is ASCII; only element-name scanning can be
    /// multi-byte, handled via `advance_cm_name_bytes`.
    #[allow(dead_code)]
    fn parse_content_model_group_bytes(&mut self, allow_mixed: bool) -> ParseResult<ContentModel> {
        self.cm_pos += 1; // consume '('
        self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
        let pm = self.match_keyword_cm_bytes(self.cm_pos, PCDATA_MARKER);
        if pm && !allow_mixed {
            return Err(self.fatal(
                "\"#PCDATA\" is only legal in an element declaration's own outermost content model group, not nested inside another group",
            ));
        }
        if pm {
            self.cm_pos += PCDATA_MARKER.len();
            let mut children: Vec<ContentModel> = Vec::new();
            children.push(ContentModel::leaf(NodeType::Pcdata, None, Occurrence::Once));
            self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
            while self.cm_pos < self.cm_end && self.buf.as_bytes()[self.cm_pos] == b'|' {
                self.cm_pos += 1;
                self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
                let name_start = self.cm_pos;
                self.advance_cm_name_bytes()?;
                if self.cm_pos == name_start {
                    return Err(self.fatal("Malformed content model"));
                }
                self.check_name_start_char_bytes(name_start)?;
                let mixed_name = self.slice_bytes(name_start, self.cm_pos);
                if self.validation_enabled {
                    let dup = children.iter().skip(1).any(|c| {
                        c.element_name.as_deref() == Some(mixed_name.as_str())
                    });
                    if dup {
                        let msg = format!(
                            "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{mixed_name}\" appears more than once in this mixed-content declaration."
                        );
                        self.handler.error(&msg)?;
                    }
                }
                children.push(ContentModel::leaf(
                    NodeType::Element,
                    Some(mixed_name),
                    Occurrence::Once,
                ));
                self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
            }
            if self.cm_pos >= self.cm_end || self.buf.as_bytes()[self.cm_pos] != b')' {
                return Err(self.fatal("Malformed content model"));
            }
            self.cm_pos += 1;
            let has_element_names = children.len() > 1;
            let occ;
            if has_element_names {
                if self.cm_pos >= self.cm_end || self.buf.as_bytes()[self.cm_pos] != b'*' {
                    return Err(self.fatal(
                        "A mixed-content declaration with element names must end with \")*\"",
                    ));
                }
                self.cm_pos += 1;
                occ = Occurrence::ZeroOrMore;
            } else if self.cm_pos < self.cm_end
                && (self.buf.as_bytes()[self.cm_pos] == b'?'
                    || self.buf.as_bytes()[self.cm_pos] == b'+')
            {
                let ch = self.buf.as_bytes()[self.cm_pos] as char;
                let msg = format!(
                    "\"(#PCDATA)\" may not be followed by a \"{ch}\" occurrence indicator"
                );
                return Err(self.fatal(&msg));
            } else if self.cm_pos < self.cm_end && self.buf.as_bytes()[self.cm_pos] == b'*' {
                self.cm_pos += 1;
                occ = Occurrence::ZeroOrMore;
            } else {
                occ = Occurrence::Once;
            }
            return Ok(ContentModel::group(NodeType::Choice, children, occ));
        }

        let mut children: Vec<ContentModel> = Vec::new();
        children.push(self.parse_content_model_particle_bytes()?);
        self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
        let mut separator = '\u{0}';
        while self.cm_pos < self.cm_end
            && (self.buf.as_bytes()[self.cm_pos] == b',' || self.buf.as_bytes()[self.cm_pos] == b'|')
        {
            let sep = self.buf.as_bytes()[self.cm_pos] as char;
            if separator == '\u{0}' {
                separator = sep;
            } else if separator != sep {
                return Err(self.fatal("Cannot mix ',' and '|' within the same content model group"));
            }
            self.cm_pos += 1;
            self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
            children.push(self.parse_content_model_particle_bytes()?);
            self.cm_pos = self.skip_cm_whitespace_bytes(self.cm_pos);
        }
        if self.cm_pos >= self.cm_end || self.buf.as_bytes()[self.cm_pos] != b')' {
            return Err(self.fatal("Malformed content model"));
        }
        self.cm_pos += 1;
        let group_occ = self.read_cm_occurrence_bytes();
        let group_type = if separator == '|' {
            NodeType::Choice
        } else {
            NodeType::Sequence
        };
        if group_type == NodeType::Choice {
            for i in 0..children.len() {
                if children[i].node_type != NodeType::Element {
                    continue;
                }
                for j in 0..i {
                    if children[j].node_type == NodeType::Element
                        && children[i].element_name == children[j].element_name
                    {
                        let dup = children[i].element_name.clone().unwrap_or_default();
                        let msg = format!(
                            "Validity Constraint: No Duplicate Types (Section 3.3.1). \"{dup}\" appears more than once in this choice group."
                        );
                        self.handler.error(&msg)?;
                        break;
                    }
                }
            }
        }
        Ok(ContentModel::group(group_type, children, group_occ))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `match_keyword_cm`. `PCDATA_MARKER` is pure ASCII.
    #[allow(dead_code)]
    fn match_keyword_cm_bytes(&self, p: usize, marker: &str) -> bool {
        let marker = marker.as_bytes();
        let mlen = marker.len();
        if p + mlen > self.cm_end {
            return false;
        }
        for (i, &mb) in marker.iter().enumerate() {
            if self.buf.as_bytes()[p + i] != mb {
                return false;
            }
        }
        true
    }

    // ===== ATTLIST =====

    fn check_attlist_declaration_vcs(
        &mut self,
        element_name: &str,
        attr_name: &str,
        ty: &str,
        mode: Mode,
    ) -> ParseResult<()> {
        if ty == "ID" {
            if mode != Mode::Required && mode != Mode::Implied {
                let msg = format!(
                    "Validity Constraint: ID Attribute Default (Section 3.3.1). ID attribute \"{attr_name}\" on element \"{element_name}\" must be declared #IMPLIED or #REQUIRED."
                );
                self.handler.error(&msg)?;
            }
            if self.dtd_model.has_attribute_of_type(element_name, "ID", attr_name) {
                let msg = format!(
                    "Validity Constraint: One ID per Element Type (Section 3.3.1). Element \"{element_name}\" already has an ID attribute declared."
                );
                self.handler.error(&msg)?;
            }
        } else if ty == "NOTATION"
            && self
                .dtd_model
                .has_attribute_of_type(element_name, "NOTATION", attr_name)
        {
            let msg = format!(
                "Validity Constraint: One Notation Per Element Type (Section 3.3.1). Element \"{element_name}\" already has a NOTATION attribute declared."
            );
            self.handler.error(&msg)?;
        }
        Ok(())
    }

    fn scan_attlist_declaration(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_whitespace_in_declaration(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed attribute-list declaration"));
        }
        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            return Ok(None);
        }
        if p == name_start {
            return Err(self.fatal("Malformed attribute-list declaration"));
        }
        self.check_name_start_char(name_start)?;
        let element_name = self.slice(name_start, p);

        loop {
            let ws2 = p;
            p = self.skip_whitespace_in_declaration(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf[p] == '>' {
                self.check_not_from_pe_splice(p, "an <!ATTLIST> declaration")?;
                p += 1;
                return Ok(Some(p));
            }
            if p == ws2 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let attr_name_start = p;
            while p < self.limit && is_name_char(self.buf[p]) {
                p += 1;
            }
            if p >= self.limit {
                return Ok(None);
            }
            if p == attr_name_start {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }
            self.check_name_start_char(attr_name_start)?;
            let attr_name = self
                .name_pool
                .intern_range(self.buf.as_chars(), attr_name_start, p - attr_name_start);

            let ws3 = p;
            p = self.skip_whitespace_in_declaration(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws3 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let ty;
            let mut enumeration: Option<Vec<String>> = None;
            if self.buf[p] == '(' {
                ty = "ENUMERATION".to_string();
                let r = match self.scan_enumeration_list(p, false)? {
                    None => return Ok(None),
                    Some(r) => r,
                };
                p = r;
                enumeration = self.last_enumeration_values.clone();
            } else {
                let type_start = p;
                while p < self.limit && is_name_char(self.buf[p]) {
                    p += 1;
                }
                if p >= self.limit {
                    return Ok(None);
                }
                if p == type_start {
                    return Err(self.fatal("Malformed attribute-list declaration"));
                }
                ty = self.slice(type_start, p);
                if !matches!(
                    ty.as_str(),
                    "CDATA"
                        | "ID"
                        | "IDREF"
                        | "IDREFS"
                        | "ENTITY"
                        | "ENTITIES"
                        | "NMTOKEN"
                        | "NMTOKENS"
                        | "NOTATION"
                ) {
                    let msg = format!("Unrecognised attribute type \"{ty}\"");
                    return Err(self.fatal(&msg));
                }
                if ty == "NOTATION" {
                    let ws3b = p;
                    p = self.skip_whitespace_in_declaration(p, pending, false)?;
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if p == ws3b {
                        return Err(self.fatal("Malformed attribute-list declaration"));
                    }
                    if self.buf[p] != '(' {
                        return Err(self.fatal("Malformed attribute-list declaration"));
                    }
                    let r = match self.scan_enumeration_list(p, true)? {
                        None => return Ok(None),
                        Some(r) => r,
                    };
                    p = r;
                    enumeration = self.last_enumeration_values.clone();
                }
            }

            let ws4 = p;
            p = self.skip_whitespace_in_declaration(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws4 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let raw_default: Option<String>;
            let mode;
            if self.buf[p] == '#' {
                match self.match_keyword(p, REQUIRED_MARKER) {
                    KwResult::NeedMore => return Ok(None),
                    KwResult::Match => {
                        p += REQUIRED_MARKER.len();
                        raw_default = None;
                        mode = Mode::Required;
                    }
                    KwResult::NoMatch => match self.match_keyword(p, IMPLIED_MARKER) {
                        KwResult::NeedMore => return Ok(None),
                        KwResult::Match => {
                            p += IMPLIED_MARKER.len();
                            raw_default = None;
                            mode = Mode::Implied;
                        }
                        KwResult::NoMatch => match self.match_keyword(p, FIXED_MARKER) {
                            KwResult::NeedMore => return Ok(None),
                            KwResult::NoMatch => {
                                return Err(self.fatal("Malformed attribute-list declaration"))
                            }
                            KwResult::Match => {
                                p += FIXED_MARKER.len();
                                let ws5 = p;
                                p = self.skip_whitespace_in_declaration(p, pending, false)?;
                                if p >= self.limit {
                                    return Ok(None);
                                }
                                if p == ws5 {
                                    return Err(self.fatal("Malformed attribute-list declaration"));
                                }
                                if self.buf[p] != '"' && self.buf[p] != '\'' {
                                    return Err(self.fatal("Malformed attribute-list declaration"));
                                }
                                let mut sb = String::new();
                                let r = match self
                                    .scan_quoted_literal_with_char_refs(p, &mut sb, false, pending)?
                                {
                                    None => return Ok(None),
                                    Some(r) => r,
                                };
                                p = r;
                                raw_default = Some(sb);
                                mode = Mode::Fixed;
                            }
                        },
                    },
                }
            } else if self.buf[p] == '"' || self.buf[p] == '\'' {
                let mut sb = String::new();
                let r = match self.scan_quoted_literal_with_char_refs(p, &mut sb, false, pending)? {
                    None => return Ok(None),
                    Some(r) => r,
                };
                p = r;
                raw_default = Some(sb);
                mode = Mode::None;
            } else {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            if let Some(raw) = &raw_default {
                let raw = raw.clone();
                self.check_attlist_default_entities_declared(&raw, pending)?;
            }
            if self.validation_enabled {
                self.check_attlist_declaration_vcs(&element_name, &attr_name, &ty, mode)?;
            }
            let declared = self.dtd_model.declare_attribute(
                &element_name,
                &attr_name,
                &ty,
                mode,
                raw_default.clone(),
                enumeration.clone(),
                self.parsing_external_content,
            );
            if declared {
                let type_str = format_attribute_decl_type(&ty, enumeration.as_ref());
                let mode_str = format_attribute_decl_mode(mode);
                self.handler.attribute_decl(
                    &element_name,
                    &attr_name,
                    &type_str,
                    mode_str.unwrap_or(""),
                    raw_default.as_deref(),
                )?;
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_attlist_declaration`. A 1:1 structural port onto the
    /// byte-native primitives above; `check_attlist_declaration_vcs`/
    /// `check_attlist_default_entities_declared` and the `dtd_model`
    /// bookkeeping are unchanged since neither touches `self.buf`.
    #[allow(dead_code)]
    fn scan_attlist_declaration_bytes(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<usize>> {
        self.saw_splice_since_declaration_start = false;
        let ws = p;
        p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
        if p >= self.limit {
            return Ok(None);
        }
        if p == ws {
            return Err(self.fatal("Malformed attribute-list declaration"));
        }
        let name_start = p;
        p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed attribute-list declaration"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let element_name = self.slice_bytes(name_start, p);

        loop {
            let ws2 = p;
            p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if self.buf.as_bytes()[p] == b'>' {
                self.check_not_from_pe_splice(p, "an <!ATTLIST> declaration")?;
                p += 1;
                return Ok(Some(p));
            }
            if p == ws2 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let attr_name_start = p;
            p = match self.scan_name_chars_bytes(attr_name_start) {
                NameScanBytes::NeedMore => return Ok(None),
                NameScanBytes::Illegal => {
                    return Err(self.fatal("Malformed attribute-list declaration"));
                }
                NameScanBytes::End(p) => p,
            };
            if p == attr_name_start {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }
            self.check_name_start_char_bytes(attr_name_start)?;
            // SAFETY: [attr_name_start, p) was validated as a legal XML
            // Name by scan_name_chars_bytes above.
            let attr_name_str = unsafe {
                std::str::from_utf8_unchecked(&self.buf.as_bytes()[attr_name_start..p])
            };
            let attr_name = self.name_pool.intern_str(attr_name_str);

            let ws3 = p;
            p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws3 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let ty;
            let mut enumeration: Option<Vec<String>> = None;
            if self.buf.as_bytes()[p] == b'(' {
                ty = "ENUMERATION".to_string();
                let r = match self.scan_enumeration_list_bytes(p, false)? {
                    None => return Ok(None),
                    Some(r) => r,
                };
                p = r;
                enumeration = self.last_enumeration_values.clone();
            } else {
                let type_start = p;
                p = match self.scan_name_chars_bytes(type_start) {
                    NameScanBytes::NeedMore => return Ok(None),
                    NameScanBytes::Illegal => {
                        return Err(self.fatal("Malformed attribute-list declaration"));
                    }
                    NameScanBytes::End(p) => p,
                };
                if p == type_start {
                    return Err(self.fatal("Malformed attribute-list declaration"));
                }
                ty = self.slice_bytes(type_start, p);
                if !matches!(
                    ty.as_str(),
                    "CDATA"
                        | "ID"
                        | "IDREF"
                        | "IDREFS"
                        | "ENTITY"
                        | "ENTITIES"
                        | "NMTOKEN"
                        | "NMTOKENS"
                        | "NOTATION"
                ) {
                    let msg = format!("Unrecognised attribute type \"{ty}\"");
                    return Err(self.fatal(&msg));
                }
                if ty == "NOTATION" {
                    let ws3b = p;
                    p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
                    if p >= self.limit {
                        return Ok(None);
                    }
                    if p == ws3b {
                        return Err(self.fatal("Malformed attribute-list declaration"));
                    }
                    if self.buf.as_bytes()[p] != b'(' {
                        return Err(self.fatal("Malformed attribute-list declaration"));
                    }
                    let r = match self.scan_enumeration_list_bytes(p, true)? {
                        None => return Ok(None),
                        Some(r) => r,
                    };
                    p = r;
                    enumeration = self.last_enumeration_values.clone();
                }
            }

            let ws4 = p;
            p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
            if p >= self.limit {
                return Ok(None);
            }
            if p == ws4 {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            let raw_default: Option<String>;
            let mode;
            if self.buf.as_bytes()[p] == b'#' {
                match self.match_keyword_bytes(p, REQUIRED_MARKER) {
                    KwResult::NeedMore => return Ok(None),
                    KwResult::Match => {
                        p += REQUIRED_MARKER.len();
                        raw_default = None;
                        mode = Mode::Required;
                    }
                    KwResult::NoMatch => match self.match_keyword_bytes(p, IMPLIED_MARKER) {
                        KwResult::NeedMore => return Ok(None),
                        KwResult::Match => {
                            p += IMPLIED_MARKER.len();
                            raw_default = None;
                            mode = Mode::Implied;
                        }
                        KwResult::NoMatch => match self.match_keyword_bytes(p, FIXED_MARKER) {
                            KwResult::NeedMore => return Ok(None),
                            KwResult::NoMatch => {
                                return Err(self.fatal("Malformed attribute-list declaration"))
                            }
                            KwResult::Match => {
                                p += FIXED_MARKER.len();
                                let ws5 = p;
                                p = self.skip_whitespace_in_declaration_bytes(p, pending, false)?;
                                if p >= self.limit {
                                    return Ok(None);
                                }
                                if p == ws5 {
                                    return Err(self.fatal("Malformed attribute-list declaration"));
                                }
                                if self.buf.as_bytes()[p] != b'"' && self.buf.as_bytes()[p] != b'\''
                                {
                                    return Err(self.fatal("Malformed attribute-list declaration"));
                                }
                                let mut sb = String::new();
                                let r = match self.scan_quoted_literal_with_char_refs_bytes(
                                    p, &mut sb, false, pending,
                                )? {
                                    None => return Ok(None),
                                    Some(r) => r,
                                };
                                p = r;
                                raw_default = Some(sb);
                                mode = Mode::Fixed;
                            }
                        },
                    },
                }
            } else if self.buf.as_bytes()[p] == b'"' || self.buf.as_bytes()[p] == b'\'' {
                let mut sb = String::new();
                let r = match self
                    .scan_quoted_literal_with_char_refs_bytes(p, &mut sb, false, pending)?
                {
                    None => return Ok(None),
                    Some(r) => r,
                };
                p = r;
                raw_default = Some(sb);
                mode = Mode::None;
            } else {
                return Err(self.fatal("Malformed attribute-list declaration"));
            }

            if let Some(raw) = &raw_default {
                let raw = raw.clone();
                self.check_attlist_default_entities_declared(&raw, pending)?;
            }
            if self.validation_enabled {
                self.check_attlist_declaration_vcs(&element_name, &attr_name, &ty, mode)?;
            }
            let declared = self.dtd_model.declare_attribute(
                &element_name,
                &attr_name,
                &ty,
                mode,
                raw_default.clone(),
                enumeration.clone(),
                self.parsing_external_content,
            );
            if declared {
                let type_str = format_attribute_decl_type(&ty, enumeration.as_ref());
                let mode_str = format_attribute_decl_mode(mode);
                self.handler.attribute_decl(
                    &element_name,
                    &attr_name,
                    &type_str,
                    mode_str.unwrap_or(""),
                    raw_default.as_deref(),
                )?;
            }
        }
    }

    // ===== DOCTYPE =====

    fn scan_doctype(&mut self, tag_start: usize) -> ParseResult<bool> {
        match self.match_keyword(tag_start, DOCTYPE_MARKER) {
            KwResult::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            KwResult::NoMatch => return Err(self.fatal("Malformed markup declaration")),
            KwResult::Match => {}
        }
        if self.root_started {
            return Err(self.fatal("DOCTYPE declaration must precede the root element"));
        }
        if self.doctype_seen {
            return Err(self.fatal("Only one DOCTYPE declaration is allowed"));
        }
        if matches!(self.settings.doctype_handling, DoctypeHandling::Disallow) {
            return Err(self.fatal(
                "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" is set to true",
            ));
        }

        let mut p = tag_start + DOCTYPE_MARKER.len();
        let ws = p;
        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == ws {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        let name_start = p;
        while p < self.limit && is_name_char(self.buf[p]) {
            p += 1;
        }
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == name_start {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.check_name_start_char(name_start)?;
        let name = self.slice(name_start, p);

        p = self.skip_optional_whitespace(p);
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }

        if self.buf[p] == 'S' || self.buf[p] == 'P' {
            let r = match self.skip_external_id(p)? {
                None => {
                    self.pos = tag_start;
                    return Ok(false);
                }
                Some(r) => r,
            };
            self.doctype_external_public_id = self.last_external_id_public_id.clone();
            self.doctype_external_system_id = self.last_external_id_system_id.clone();
            self.doctype_public_id = self.last_external_id_public_id.clone();
            self.doctype_system_id = self.last_external_id_system_id.clone();
            p = r;
            p = self.skip_optional_whitespace(p);
            if p >= self.limit {
                self.pos = tag_start;
                return Ok(false);
            }
        }

        if self.buf[p] == '[' {
            let pub_id = self.doctype_external_public_id.clone();
            let sys_id = self.doctype_external_system_id.clone();
            self.handler.start_dtd(&name, pub_id.as_deref(), sys_id.as_deref())?;
            self.doctype_name_pending = Some(name);
            self.pos = p + 1;
            self.in_doctype = true;
            let finished = if matches!(self.settings.doctype_handling, DoctypeHandling::Skip) {
                self.skip_doctype_subset_inner()?
            } else {
                self.doctype_pending = Some(PendingDecls::default());
                self.scan_doctype_subset()?
            };
            if !finished {
                return Ok(false);
            }
            self.in_doctype = false;
            return Ok(true);
        }

        if self.buf[p] != '>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        p += 1;
        self.pos = p;
        let pub_id = self.doctype_external_public_id.clone();
        let sys_id = self.doctype_external_system_id.clone();
        self.handler.start_dtd(&name, pub_id.as_deref(), sys_id.as_deref())?;
        self.finish_doctype_external_subset(&name)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = Some(name);
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_doctype` — the top of the DOCTYPE dispatch tree, tying
    /// together every byte-native DTD primitive built so far. Reuses
    /// `finish_doctype_external_subset` unchanged: it (via
    /// `parse_external_subset`) always parses fetched external-subset
    /// content through its own temporary `Vec<char>` swap, regardless of
    /// what representation the live scanner is in, so it never touches
    /// `self.buf`'s outer state either way.
    #[allow(dead_code)]
    fn scan_doctype_bytes(&mut self, tag_start: usize) -> ParseResult<bool> {
        match self.match_keyword_bytes(tag_start, DOCTYPE_MARKER) {
            KwResult::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            KwResult::NoMatch => return Err(self.fatal("Malformed markup declaration")),
            KwResult::Match => {}
        }
        if self.root_started {
            return Err(self.fatal("DOCTYPE declaration must precede the root element"));
        }
        if self.doctype_seen {
            return Err(self.fatal("Only one DOCTYPE declaration is allowed"));
        }
        if matches!(self.settings.doctype_handling, DoctypeHandling::Disallow) {
            return Err(self.fatal(
                "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" is set to true",
            ));
        }

        let mut p = tag_start + DOCTYPE_MARKER.len();
        let ws = p;
        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }
        if p == ws {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        let name_start = p;
        p = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => {
                self.pos = tag_start;
                return Ok(false);
            }
            NameScanBytes::Illegal => return Err(self.fatal("Malformed DOCTYPE declaration")),
            NameScanBytes::End(p) => p,
        };
        if p == name_start {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name = self.slice_bytes(name_start, p);

        p = self.skip_optional_whitespace_bytes(p);
        if p >= self.limit {
            self.pos = tag_start;
            return Ok(false);
        }

        if self.buf.as_bytes()[p] == b'S' || self.buf.as_bytes()[p] == b'P' {
            let r = match self.skip_external_id_bytes(p)? {
                None => {
                    self.pos = tag_start;
                    return Ok(false);
                }
                Some(r) => r,
            };
            self.doctype_external_public_id = self.last_external_id_public_id.clone();
            self.doctype_external_system_id = self.last_external_id_system_id.clone();
            self.doctype_public_id = self.last_external_id_public_id.clone();
            self.doctype_system_id = self.last_external_id_system_id.clone();
            p = r;
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit {
                self.pos = tag_start;
                return Ok(false);
            }
        }

        if self.buf.as_bytes()[p] == b'[' {
            let pub_id = self.doctype_external_public_id.clone();
            let sys_id = self.doctype_external_system_id.clone();
            self.handler.start_dtd(&name, pub_id.as_deref(), sys_id.as_deref())?;
            self.doctype_name_pending = Some(name);
            self.pos = p + 1;
            self.in_doctype = true;
            let finished = if matches!(self.settings.doctype_handling, DoctypeHandling::Skip) {
                self.skip_doctype_subset_inner_bytes()?
            } else {
                self.doctype_pending = Some(PendingDecls::default());
                self.scan_doctype_subset_bytes()?
            };
            if !finished {
                return Ok(false);
            }
            self.in_doctype = false;
            return Ok(true);
        }

        if self.buf.as_bytes()[p] != b'>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        p += 1;
        self.pos = p;
        let pub_id = self.doctype_external_public_id.clone();
        let sys_id = self.doctype_external_system_id.clone();
        self.handler.start_dtd(&name, pub_id.as_deref(), sys_id.as_deref())?;
        self.finish_doctype_external_subset_bytes(&name)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = Some(name);
        Ok(true)
    }

    fn finish_doctype_external_subset(&mut self, root_name: &str) -> ParseResult<()> {
        if matches!(self.settings.doctype_handling, DoctypeHandling::Skip) {
            // Never fetch or parse an external subset in Skip mode,
            // regardless of external_parameter_entities — that flag only
            // controls whether Process mode reads external content.
            self.doctype_external_public_id = None;
            self.doctype_external_system_id = None;
            return Ok(());
        }
        if self.doctype_external_system_id.is_some() {
            self.handler.start_entity("[dtd]")?;
            if self.settings.external_parameter_entities {
                let what = format!("the external DTD subset for \"{root_name}\"");
                let public_id = self.doctype_external_public_id.clone();
                let system_id = self.doctype_external_system_id.clone();
                let chars =
                    self.fetch_external_resource("[dtd]", &what, public_id.as_deref(), system_id.as_deref())?;
                let saved_base = self.base_system_id.clone();
                self.base_system_id = self.last_resolved_system_id.clone();
                let result = self.parse_external_subset(&chars);
                self.base_system_id = saved_base;
                result?;
            }
            self.handler.end_entity("[dtd]")?;
        }
        self.doctype_external_public_id = None;
        self.doctype_external_system_id = None;
        self.resolve_attlist_defaults_against_entities()?;
        if self.validation_enabled {
            self.check_attlist_defaults_legal()?;
        }
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `finish_doctype_external_subset`. `fetch_external_resource`,
    /// `resolve_attlist_defaults_against_entities`, and
    /// `check_attlist_defaults_legal` are reused unchanged (none touch
    /// `self.buf`); only the `parse_external_subset` call needed a
    /// byte-native counterpart, for the reason documented on
    /// `parse_external_subset_bytes`.
    #[allow(dead_code)]
    fn finish_doctype_external_subset_bytes(&mut self, root_name: &str) -> ParseResult<()> {
        if matches!(self.settings.doctype_handling, DoctypeHandling::Skip) {
            self.doctype_external_public_id = None;
            self.doctype_external_system_id = None;
            return Ok(());
        }
        if self.doctype_external_system_id.is_some() {
            self.handler.start_entity("[dtd]")?;
            if self.settings.external_parameter_entities {
                let what = format!("the external DTD subset for \"{root_name}\"");
                let public_id = self.doctype_external_public_id.clone();
                let system_id = self.doctype_external_system_id.clone();
                let chars = self.fetch_external_resource(
                    "[dtd]",
                    &what,
                    public_id.as_deref(),
                    system_id.as_deref(),
                )?;
                let saved_base = self.base_system_id.clone();
                self.base_system_id = self.last_resolved_system_id.clone();
                let result = self.parse_external_subset_bytes(&chars);
                self.base_system_id = saved_base;
                result?;
            }
            self.handler.end_entity("[dtd]")?;
        }
        self.doctype_external_public_id = None;
        self.doctype_external_system_id = None;
        self.resolve_attlist_defaults_against_entities()?;
        if self.validation_enabled {
            self.check_attlist_defaults_legal()?;
        }
        Ok(())
    }

    fn scan_doctype_subset(&mut self) -> ParseResult<bool> {
        let mut pending = self.doctype_pending.take().unwrap_or_default();
        let result = self.scan_doctype_subset_inner(&mut pending);
        self.doctype_pending = Some(pending);
        result
    }

    fn scan_doctype_subset_inner(&mut self, pending: &mut PendingDecls) -> ParseResult<bool> {
        if !self.doctype_subset_closed {
            loop {
                if self.in_pi {
                    if !self.scan_pi_data()? {
                        return Ok(false);
                    }
                    self.in_pi = false;
                    continue;
                }
                if self.in_comment {
                    if !self.scan_comment_data()? {
                        return Ok(false);
                    }
                    self.in_comment = false;
                    continue;
                }
                self.pos = self.skip_optional_whitespace(self.pos);
                if self.pos >= self.limit {
                    return Ok(false);
                }
                let c = self.buf[self.pos];
                if c == ']' {
                    self.pos += 1;
                    self.doctype_subset_closed = true;
                    break;
                }
                if c == '%' {
                    let mut q = self.pos + 1;
                    while q < self.limit && is_name_char(self.buf[q]) {
                        q += 1;
                    }
                    if q >= self.limit {
                        return Ok(false);
                    }
                    if self.buf[q] != ';' {
                        return Err(self.fatal("Malformed parameter entity reference"));
                    }
                    self.expand_parameter_entity_reference(pending)?;
                    continue;
                }
                if c != '<' {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
                if self.pos + 1 >= self.limit {
                    return Ok(false);
                }
                let c2 = self.buf[self.pos + 1];
                if c2 == '?' {
                    if !self.scan_pi(self.pos)? {
                        return Ok(false);
                    }
                } else if c2 == '!' {
                    if self.pos + 2 >= self.limit {
                        return Ok(false);
                    }
                    if self.buf[self.pos + 2] == '-' {
                        if !self.scan_comment(self.pos)? {
                            return Ok(false);
                        }
                    } else {
                        match self.match_keyword(self.pos, ENTITY_MARKER) {
                            KwResult::NeedMore => return Ok(false),
                            KwResult::Match => {
                                let start = self.pos + ENTITY_MARKER.len();
                                match self.scan_entity_declaration(start, pending)? {
                                    None => return Ok(false),
                                    Some(r) => self.pos = r,
                                }
                            }
                            KwResult::NoMatch => match self.match_keyword(self.pos, ATTLIST_MARKER) {
                                KwResult::NeedMore => return Ok(false),
                                KwResult::Match => {
                                    let start = self.pos + ATTLIST_MARKER.len();
                                    match self.scan_attlist_declaration(start, pending)? {
                                        None => return Ok(false),
                                        Some(r) => self.pos = r,
                                    }
                                }
                                KwResult::NoMatch => {
                                    match self.match_keyword(self.pos, ELEMENT_MARKER) {
                                        KwResult::NeedMore => return Ok(false),
                                        KwResult::Match => {
                                            let start = self.pos + ELEMENT_MARKER.len();
                                            match self.scan_element_declaration(start, pending)? {
                                                None => return Ok(false),
                                                Some(r) => self.pos = r,
                                            }
                                        }
                                        KwResult::NoMatch => {
                                            match self.match_keyword(self.pos, NOTATION_MARKER) {
                                                KwResult::NeedMore => return Ok(false),
                                                KwResult::NoMatch => {
                                                    return Err(self.fatal("Expected an element, attribute-list, entity, or notation declaration"))
                                                }
                                                KwResult::Match => {
                                                    let start =
                                                        self.pos + NOTATION_MARKER.len();
                                                    match self.scan_notation_declaration(start)? {
                                                        None => return Ok(false),
                                                        Some(r) => self.pos = r,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                        }
                    }
                } else {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
            }
        }

        self.pos = self.skip_optional_whitespace(self.pos);
        if self.pos >= self.limit {
            return Ok(false);
        }
        if self.buf[self.pos] != '>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.pos += 1;

        // Merge pending into scanner-wide maps.
        for (k, v) in pending.entities.drain() {
            self.general_entities.entry(k).or_insert(v);
        }
        let external_snapshot: HashMap<String, ExtEntity> = pending.external_names.clone();
        for (k, v) in pending.external_names.drain() {
            self.external_entity_names.entry(k).or_insert(v);
        }
        self.report_unparsed_entities(&external_snapshot)?;
        for (k, v) in pending.param_entities.drain() {
            self.parameter_entities.entry(k).or_insert(v);
        }
        for (k, v) in pending.param_external_names.drain() {
            self.parameter_entity_external_ids.entry(k).or_insert(v);
        }
        let name_pending = self.doctype_name_pending.clone().unwrap_or_default();
        self.finish_doctype_external_subset(&name_pending)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = self.doctype_name_pending.take();
        self.doctype_name_pending = None;
        self.doctype_subset_closed = false;
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_doctype_subset`.
    #[allow(dead_code)]
    fn scan_doctype_subset_bytes(&mut self) -> ParseResult<bool> {
        let mut pending = self.doctype_pending.take().unwrap_or_default();
        let result = self.scan_doctype_subset_inner_bytes(&mut pending);
        self.doctype_pending = Some(pending);
        result
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `scan_doctype_subset_inner` — the internal-subset streaming
    /// dispatch loop, resumable across `receive()` calls (unlike
    /// `parse_markup_decl_seq_bytes`, which assumes its input is already
    /// fully buffered). A 1:1 structural port dispatching to every
    /// byte-native declaration/comment/PI scanner built so far, plus
    /// `expand_parameter_entity_reference_bytes` for `%` references used
    /// as declaration separators.
    #[allow(dead_code)]
    fn scan_doctype_subset_inner_bytes(&mut self, pending: &mut PendingDecls) -> ParseResult<bool> {
        if !self.doctype_subset_closed {
            loop {
                if self.in_pi {
                    if !self.scan_pi_data_bytes()? {
                        return Ok(false);
                    }
                    self.in_pi = false;
                    continue;
                }
                if self.in_comment {
                    if !self.scan_comment_data_bytes()? {
                        return Ok(false);
                    }
                    self.in_comment = false;
                    continue;
                }
                self.pos = self.skip_optional_whitespace_bytes(self.pos);
                if self.pos >= self.limit {
                    return Ok(false);
                }
                let c = self.buf.as_bytes()[self.pos];
                if c == b']' {
                    self.pos += 1;
                    self.doctype_subset_closed = true;
                    break;
                }
                if c == b'%' {
                    let q = match self.scan_name_chars_bytes(self.pos + 1) {
                        NameScanBytes::NeedMore => return Ok(false),
                        NameScanBytes::Illegal => {
                            return Err(self.fatal("Malformed parameter entity reference"));
                        }
                        NameScanBytes::End(q) => q,
                    };
                    if q >= self.limit {
                        return Ok(false);
                    }
                    if self.buf.as_bytes()[q] != b';' {
                        return Err(self.fatal("Malformed parameter entity reference"));
                    }
                    self.expand_parameter_entity_reference_bytes(pending)?;
                    continue;
                }
                if c != b'<' {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
                if self.pos + 1 >= self.limit {
                    return Ok(false);
                }
                let c2 = self.buf.as_bytes()[self.pos + 1];
                if c2 == b'?' {
                    if !self.scan_pi_bytes(self.pos)? {
                        return Ok(false);
                    }
                } else if c2 == b'!' {
                    if self.pos + 2 >= self.limit {
                        return Ok(false);
                    }
                    if self.buf.as_bytes()[self.pos + 2] == b'-' {
                        if !self.scan_comment_bytes(self.pos)? {
                            return Ok(false);
                        }
                    } else {
                        match self.match_keyword_bytes(self.pos, ENTITY_MARKER) {
                            KwResult::NeedMore => return Ok(false),
                            KwResult::Match => {
                                let start = self.pos + ENTITY_MARKER.len();
                                match self.scan_entity_declaration_bytes(start, pending)? {
                                    None => return Ok(false),
                                    Some(r) => self.pos = r,
                                }
                            }
                            KwResult::NoMatch => {
                                match self.match_keyword_bytes(self.pos, ATTLIST_MARKER) {
                                    KwResult::NeedMore => return Ok(false),
                                    KwResult::Match => {
                                        let start = self.pos + ATTLIST_MARKER.len();
                                        match self.scan_attlist_declaration_bytes(start, pending)?
                                        {
                                            None => return Ok(false),
                                            Some(r) => self.pos = r,
                                        }
                                    }
                                    KwResult::NoMatch => {
                                        match self.match_keyword_bytes(self.pos, ELEMENT_MARKER) {
                                            KwResult::NeedMore => return Ok(false),
                                            KwResult::Match => {
                                                let start = self.pos + ELEMENT_MARKER.len();
                                                match self
                                                    .scan_element_declaration_bytes(start, pending)?
                                                {
                                                    None => return Ok(false),
                                                    Some(r) => self.pos = r,
                                                }
                                            }
                                            KwResult::NoMatch => {
                                                match self
                                                    .match_keyword_bytes(self.pos, NOTATION_MARKER)
                                                {
                                                    KwResult::NeedMore => return Ok(false),
                                                    KwResult::NoMatch => {
                                                        return Err(self.fatal("Expected an element, attribute-list, entity, or notation declaration"))
                                                    }
                                                    KwResult::Match => {
                                                        let start =
                                                            self.pos + NOTATION_MARKER.len();
                                                        match self
                                                            .scan_notation_declaration_bytes(start)?
                                                        {
                                                            None => return Ok(false),
                                                            Some(r) => self.pos = r,
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
            }
        }

        self.pos = self.skip_optional_whitespace_bytes(self.pos);
        if self.pos >= self.limit {
            return Ok(false);
        }
        if self.buf.as_bytes()[self.pos] != b'>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.pos += 1;

        // Merge pending into scanner-wide maps.
        for (k, v) in pending.entities.drain() {
            self.general_entities.entry(k).or_insert(v);
        }
        let external_snapshot: HashMap<String, ExtEntity> = pending.external_names.clone();
        for (k, v) in pending.external_names.drain() {
            self.external_entity_names.entry(k).or_insert(v);
        }
        self.report_unparsed_entities(&external_snapshot)?;
        for (k, v) in pending.param_entities.drain() {
            self.parameter_entities.entry(k).or_insert(v);
        }
        for (k, v) in pending.param_external_names.drain() {
            self.parameter_entity_external_ids.entry(k).or_insert(v);
        }
        let name_pending = self.doctype_name_pending.clone().unwrap_or_default();
        self.finish_doctype_external_subset_bytes(&name_pending)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = self.doctype_name_pending.take();
        self.doctype_name_pending = None;
        self.doctype_subset_closed = false;
        Ok(true)
    }

    /// `DoctypeHandling::Skip`'s counterpart to `scan_doctype_subset_inner`:
    /// recognizes the internal subset well enough to find where it ends
    /// (bracket/quote/comment/PI-aware) without parsing any declaration's
    /// contents — no entity table, no attribute defaults are built. Reuses
    /// the same comment/PI sub-scanners as the full parse, since those are
    /// generic and don't care why the caller is scanning.
    fn skip_doctype_subset_inner(&mut self) -> ParseResult<bool> {
        if !self.doctype_subset_closed {
            loop {
                if self.in_pi {
                    if !self.scan_pi_data()? {
                        return Ok(false);
                    }
                    self.in_pi = false;
                    continue;
                }
                if self.in_comment {
                    if !self.scan_comment_data()? {
                        return Ok(false);
                    }
                    self.in_comment = false;
                    continue;
                }
                if self.in_skipped_declaration {
                    if !self.skip_declaration_body()? {
                        return Ok(false);
                    }
                    self.in_skipped_declaration = false;
                    continue;
                }
                self.pos = self.skip_optional_whitespace(self.pos);
                if self.pos >= self.limit {
                    return Ok(false);
                }
                let c = self.buf[self.pos];
                if c == ']' {
                    self.pos += 1;
                    self.doctype_subset_closed = true;
                    break;
                }
                if c == '%' {
                    // A parameter entity reference used as a declaration
                    // separator — skip the token itself, don't resolve it.
                    let mut q = self.pos + 1;
                    while q < self.limit && is_name_char(self.buf[q]) {
                        q += 1;
                    }
                    if q >= self.limit {
                        return Ok(false);
                    }
                    if self.buf[q] != ';' {
                        return Err(self.fatal("Malformed parameter entity reference"));
                    }
                    self.pos = q + 1;
                    continue;
                }
                if c != '<' {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
                if self.pos + 1 >= self.limit {
                    return Ok(false);
                }
                let c2 = self.buf[self.pos + 1];
                if c2 == '?' {
                    if !self.scan_pi(self.pos)? {
                        return Ok(false);
                    }
                } else if c2 == '!' {
                    if self.pos + 2 >= self.limit {
                        return Ok(false);
                    }
                    if self.buf[self.pos + 2] == '-' {
                        if !self.scan_comment(self.pos)? {
                            return Ok(false);
                        }
                    } else {
                        // <!ELEMENT / <!ATTLIST / <!ENTITY / <!NOTATION —
                        // skip to the first unquoted '>'. Uniform across
                        // all four (not distinguishing which one matched)
                        // is strictly safe and simpler.
                        self.pos += 2;
                        self.in_skipped_declaration = true;
                        self.skip_decl_quote = None;
                    }
                } else {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
            }
        }

        self.pos = self.skip_optional_whitespace(self.pos);
        if self.pos >= self.limit {
            return Ok(false);
        }
        if self.buf[self.pos] != '>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.pos += 1;

        let name_pending = self.doctype_name_pending.clone().unwrap_or_default();
        self.finish_doctype_external_subset(&name_pending)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = self.doctype_name_pending.take();
        self.doctype_name_pending = None;
        self.doctype_subset_closed = false;
        Ok(true)
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_doctype_subset_inner`. `DoctypeHandling::Skip`'s dispatch loop
    /// -- recognizes the internal subset well enough to find where it ends
    /// without parsing any declaration's contents, so it never needs the
    /// declaration scanners, only the byte-native comment/PI scanners plus
    /// `skip_declaration_body_bytes`.
    #[allow(dead_code)]
    fn skip_doctype_subset_inner_bytes(&mut self) -> ParseResult<bool> {
        if !self.doctype_subset_closed {
            loop {
                if self.in_pi {
                    if !self.scan_pi_data_bytes()? {
                        return Ok(false);
                    }
                    self.in_pi = false;
                    continue;
                }
                if self.in_comment {
                    if !self.scan_comment_data_bytes()? {
                        return Ok(false);
                    }
                    self.in_comment = false;
                    continue;
                }
                if self.in_skipped_declaration {
                    if !self.skip_declaration_body_bytes()? {
                        return Ok(false);
                    }
                    self.in_skipped_declaration = false;
                    continue;
                }
                self.pos = self.skip_optional_whitespace_bytes(self.pos);
                if self.pos >= self.limit {
                    return Ok(false);
                }
                let c = self.buf.as_bytes()[self.pos];
                if c == b']' {
                    self.pos += 1;
                    self.doctype_subset_closed = true;
                    break;
                }
                if c == b'%' {
                    // A parameter entity reference used as a declaration
                    // separator — skip the token itself, don't resolve it.
                    let q = match self.scan_name_chars_bytes(self.pos + 1) {
                        NameScanBytes::NeedMore => return Ok(false),
                        NameScanBytes::Illegal => {
                            return Err(self.fatal("Malformed parameter entity reference"));
                        }
                        NameScanBytes::End(q) => q,
                    };
                    if q >= self.limit {
                        return Ok(false);
                    }
                    if self.buf.as_bytes()[q] != b';' {
                        return Err(self.fatal("Malformed parameter entity reference"));
                    }
                    self.pos = q + 1;
                    continue;
                }
                if c != b'<' {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
                if self.pos + 1 >= self.limit {
                    return Ok(false);
                }
                let c2 = self.buf.as_bytes()[self.pos + 1];
                if c2 == b'?' {
                    if !self.scan_pi_bytes(self.pos)? {
                        return Ok(false);
                    }
                } else if c2 == b'!' {
                    if self.pos + 2 >= self.limit {
                        return Ok(false);
                    }
                    if self.buf.as_bytes()[self.pos + 2] == b'-' {
                        if !self.scan_comment_bytes(self.pos)? {
                            return Ok(false);
                        }
                    } else {
                        // <!ELEMENT / <!ATTLIST / <!ENTITY / <!NOTATION —
                        // skip to the first unquoted '>'. Uniform across
                        // all four (not distinguishing which one matched)
                        // is strictly safe and simpler.
                        self.pos += 2;
                        self.in_skipped_declaration = true;
                        self.skip_decl_quote = None;
                    }
                } else {
                    return Err(self.fatal("Malformed internal DTD subset"));
                }
            }
        }

        self.pos = self.skip_optional_whitespace_bytes(self.pos);
        if self.pos >= self.limit {
            return Ok(false);
        }
        if self.buf.as_bytes()[self.pos] != b'>' {
            return Err(self.fatal("Malformed DOCTYPE declaration"));
        }
        self.pos += 1;

        let name_pending = self.doctype_name_pending.clone().unwrap_or_default();
        self.finish_doctype_external_subset_bytes(&name_pending)?;
        self.handler.end_dtd()?;
        self.doctype_seen = true;
        self.doctype_name = self.doctype_name_pending.take();
        self.doctype_name_pending = None;
        self.doctype_subset_closed = false;
        Ok(true)
    }

    /// Advances past a skipped `<!...>` declaration's body to its first
    /// unquoted `>`, tracking `self.skip_decl_quote` so a `>` or `]` inside
    /// a quoted default/literal value doesn't end the declaration early.
    /// Resumable across `receive()` calls, same idiom as `in_pi`/`in_comment`.
    fn skip_declaration_body(&mut self) -> ParseResult<bool> {
        loop {
            if self.pos >= self.limit {
                return Ok(false);
            }
            let c = self.buf[self.pos];
            if let Some(q) = self.skip_decl_quote {
                self.pos += 1;
                if c == q {
                    self.skip_decl_quote = None;
                }
                continue;
            }
            match c {
                '\'' | '"' => {
                    self.skip_decl_quote = Some(c);
                    self.pos += 1;
                }
                '>' => {
                    self.pos += 1;
                    return Ok(true);
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_declaration_body`. Never interprets a skipped byte as a
    /// character (only compares against the ASCII quote/`>` bytes), so
    /// walking one raw byte at a time through a multi-byte sequence's
    /// non-marker bytes is exactly equivalent, same reasoning as
    /// `skip_ignored_section_bytes`.
    #[allow(dead_code)]
    fn skip_declaration_body_bytes(&mut self) -> ParseResult<bool> {
        loop {
            if self.pos >= self.limit {
                return Ok(false);
            }
            let c = self.buf.as_bytes()[self.pos];
            if let Some(q) = self.skip_decl_quote {
                self.pos += 1;
                if c == q as u8 {
                    self.skip_decl_quote = None;
                }
                continue;
            }
            match c {
                b'\'' | b'"' => {
                    self.skip_decl_quote = Some(c as char);
                    self.pos += 1;
                }
                b'>' => {
                    self.pos += 1;
                    return Ok(true);
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    fn resolve_attlist_defaults_against_entities(&mut self) -> ParseResult<()> {
        let raws = self.dtd_model.collect_default_raws();
        for (element, attr, raw) in raws {
            let resolved = self.resolve_attlist_default_value(&raw)?;
            self.dtd_model.set_default_value(&element, &attr, resolved);
        }
        Ok(())
    }

    fn check_entity_referenceable(&mut self, name: &str, allow_external: bool) -> ParseResult<bool> {
        let is_general = self.general_entities.contains_key(name);
        let is_external = self.external_entity_names.contains_key(name);
        if !is_general && !is_external {
            if matches!(self.settings.doctype_handling, DoctypeHandling::Skip) {
                // The DTD's contents were never read, so we genuinely can't
                // tell whether this entity is declared — report it via the
                // standard "unresolvable, don't expand, don't error" path
                // rather than treating it as a well-formedness violation.
                self.handler.skipped_entity(name)?;
                return Ok(false);
            }
            if self.saw_internal_subset_parameter_entity_reference {
                let msg = format!(
                    "Validity Constraint: Entity Declared (Section 4.1). Entity \"{name}\" was not declared (a parameter entity reference elsewhere in the internal DTD subset downgrades this from a well-formedness error to a validity error)."
                );
                self.handler.error(&msg)?;
                return Ok(false);
            }
            let msg = format!("Entity \"{name}\" was not declared");
            return Err(self.fatal(&msg));
        }
        if is_external && !allow_external {
            let msg = format!("External entity \"{name}\" may not be referenced in an attribute value");
            return Err(self.fatal(&msg));
        }
        if is_external {
            if let Some(ids) = self.external_entity_names.get(name) {
                if ids.ndata.is_some() {
                    let msg = format!(
                        "Well-Formedness Constraint: Parsed Entity (Section 4.1). Entity reference \"&{name};\" names an unparsed entity."
                    );
                    return Err(self.fatal(&msg));
                }
            }
        }
        if self.standalone && self.externally_declared_general_entities.contains(name) {
            let msg = format!(
                "Well-Formedness Constraint: Entity Declared (Section 4.1). Document has standalone=\"yes\" but entity \"{name}\" is declared in external markup, and is referenced."
            );
            return Err(self.fatal(&msg));
        }
        if self.entity_expansion_stack.iter().any(|n| n == name) {
            let msg = format!("Recursive entity reference: &{name};");
            return Err(self.fatal(&msg));
        }
        self.check_entity_expansion_limit(1)?;
        Ok(true)
    }

    /// Cache-only lookup/build for `name`'s flattened content-context
    /// text. Assumes the caller has *already* confirmed `name` itself is
    /// referenceable (the top-level call site in
    /// `expand_general_entity_in_content`(`_bytes`) already does this
    /// before reaching here) — nested names discovered while walking the
    /// text go through `flatten_content_entity_nested` instead, which
    /// does check, so every nested reference still gets exactly one
    /// real WFC/VC check and one `check_entity_expansion_limit` count,
    /// just no longer once *per occurrence* of the outer entity.
    fn flatten_content_entity_cached(&mut self, name: &str) -> ParseResult<Option<Rc<[char]>>> {
        if self.xml11 {
            // allow_restricted_char_in_content is tracked and applied per
            // entity, specifically while scanning THAT entity's own
            // declared text; a single flattened blob loses that per-entity
            // context. XML 1.1 is rare enough in practice that skipping
            // flattening entirely for it, rather than reasoning through
            // the interaction, is the safer trade.
            return Ok(None);
        }
        if let Some(cached) = self.content_entity_cache.get(name) {
            return Ok(cached.clone());
        }
        // Cycle guard, independent of (but reusing) the real scan-time
        // recursion stack: this walk recurses eagerly, ahead of any
        // actual scanning, so it needs its own protection against
        // self-referential or mutually-recursive entities. A genuine
        // cycle just falls back to the real recursive scan, which
        // reports it properly via this same stack at scan time.
        if self.entity_expansion_stack.iter().any(|n| n == name) {
            return Ok(None);
        }
        let declared = match self.general_entities.get(name) {
            Some(v) => v.clone(),
            None => {
                self.content_entity_cache.insert(name.to_string(), None);
                return Ok(None);
            }
        };
        self.entity_expansion_stack.push(name.to_string());
        let result = self.flatten_content_text(&declared);
        self.entity_expansion_stack.pop();
        let result = result?;
        self.content_entity_cache.insert(name.to_string(), result.clone());
        Ok(result)
    }

    /// Exploratory (explore/utf8-byte-path): byte-path counterpart to
    /// `flatten_content_entity_cached`. Encodes the (already memoized)
    /// flattened `[char]` text to UTF-8 exactly once per entity name and
    /// caches that too, so a byte-mode document referencing the same
    /// entity repeatedly skips the chars -> UTF-8 encode step as well,
    /// not just the nested-reference resolution.
    #[allow(dead_code)]
    fn flatten_content_entity_bytes_cached(&mut self, name: &str) -> ParseResult<Option<Rc<str>>> {
        if let Some(cached) = self.content_entity_byte_cache.get(name) {
            return Ok(cached.clone());
        }
        let result = self
            .flatten_content_entity_cached(name)?
            .map(|chars| Rc::from(chars.iter().collect::<String>().as_str()));
        self.content_entity_byte_cache.insert(name.to_string(), result.clone());
        Ok(result)
    }

    /// Resolves a nested entity reference found while flattening: unlike
    /// the top-level entry point, nothing has checked referenceability for
    /// this name yet, so this does so itself — propagating any WFC/VC
    /// violation as a real error, exactly like the real recursive-scan
    /// path would if it ever reached this reference directly.
    fn flatten_content_entity_nested(&mut self, name: &str) -> ParseResult<Option<Rc<[char]>>> {
        if !self.check_entity_referenceable(name, true)? {
            return Ok(None);
        }
        self.flatten_content_entity_cached(name)
    }

    /// Walks `text` (an entity's raw declared replacement text), inlining
    /// *only* nested general-entity references, into plain characters.
    /// Returns `Ok(None)` the moment anything isn't safely flattenable
    /// this way.
    ///
    /// Deliberately conservative: predefined entities (`&amp;` etc.) and
    /// numeric character references *always* bail too, not just when they
    /// resolve to a structurally awkward character. Two independent
    /// correctness hazards motivate this, both found via the full xmlconf
    /// run after an earlier, more permissive version of this function:
    ///
    /// 1. A resolved `<` or `&` re-enters the flattened buffer as a plain
    ///    character, but the *real* scan that later runs over this text
    ///    can't tell "resolved" from "literal" — it would misparse a
    ///    resolved `<` as real markup (xmltest valid-sa-088: `&lt;foo>`
    ///    must stay text "<foo>", not become a start tag).
    /// 2. Character-reference-produced whitespace must always be reported
    ///    as non-ignorable (errata E15h) — `scan_content`'s handling of a
    ///    decoded reference hard-codes `ignorable=false` specifically
    ///    *because* it knows it's looking at a reference, not literal
    ///    text. Once flattened into a plain character, that provenance is
    ///    gone, and a plain space would wrongly fall into the normal
    ///    literal-whitespace path instead.
    ///
    /// Nested *general* entities don't have either problem: the real scan
    /// already treats their replacement text as effectively inlined
    /// literal text (not reference-produced) for whitespace-ignorability
    /// purposes, and this function's own literal-vs-`&` handling below
    /// means a successfully-flattened nested entity can never itself
    /// contain a resolved `<` or `&` (the same guarantee applies
    /// recursively). So restricting the fast path to "literal characters
    /// plus nested general-entity references" is enough to make it
    /// provably safe, at the cost of not flattening entities that also
    /// use predefined or numeric references — falling back to the
    /// existing, already-correct recursive scan for those.
    fn flatten_content_text(&mut self, text: &[char]) -> ParseResult<Option<Rc<[char]>>> {
        let len = text.len();
        let mut out: Vec<char> = Vec::with_capacity(len);
        let mut q = 0;
        while q < len {
            let c = text[q];
            if c == '<' {
                return Ok(None);
            }
            if c != '&' {
                out.push(c);
                q += 1;
                continue;
            }
            let name_start = q + 1;
            if name_start < len && text[name_start] == '#' {
                // Numeric character reference: always bail (see doc
                // comment) rather than trying to determine per-value
                // whether this particular one would be safe.
                return Ok(None);
            }
            let mut p = name_start;
            while p < len && is_name_char(text[p]) {
                p += 1;
            }
            if p >= len || p == name_start || text[p] != ';' {
                return Ok(None);
            }
            if match_predefined(text, name_start, p - name_start).is_some() {
                // Predefined entity: same reasoning as numeric refs above.
                return Ok(None);
            }
            let ref_name: String = text[name_start..p].iter().collect();
            match self.flatten_content_entity_nested(&ref_name)? {
                Some(nested) => out.extend(nested.iter().copied()),
                None => return Ok(None),
            }
            q = p + 1;
        }
        Ok(Some(Rc::from(out.into_boxed_slice())))
    }

    fn expand_general_entity_in_content(&mut self, name: &str) -> ParseResult<()> {
        if !self.check_entity_referenceable(name, true)? {
            return Ok(());
        }
        let external = self.external_entity_names.get(name).cloned();
        self.handler.start_entity(name)?;
        let replacement_chars: Vec<char>;
        if let Some(ext) = external {
            if !self.settings.external_general_entities {
                self.handler.end_entity(name)?;
                return Ok(());
            }
            let fetched = self.fetch_external_entity(
                name,
                ext.public_id.as_deref(),
                ext.system_id.as_deref(),
            )?;
            replacement_chars = self.strip_declaration(&fetched)?;
        } else {
            // Try the fast path first: if this entity (and everything
            // nested inside it) can be fully resolved to plain text ahead
            // of time, reuse that -- one nested-reference-graph walk
            // total, memoized, instead of redoing it on every occurrence.
            // A real, measured hot path: relaxng/good.xml in the
            // benchmark corpus references one entity ~300 times, each
            // nested 3 levels deep; unflattened, every single occurrence
            // redid the whole nested walk from scratch.
            //
            // self.buf must be a uniquely-owned Vec<char> (see
            // expand_parameter_entity_reference) — a plain slice memcpy
            // from the shared Rc, not a UTF-8 re-decode.
            replacement_chars = match self.flatten_content_entity_cached(name)? {
                Some(flat) => flat.to_vec(),
                None => self.general_entities.get(name).unwrap().to_vec(),
            };
        }

        self.entity_expansion_stack.push(name.to_string());
        let saved_buf = std::mem::replace(self.buf.as_chars_mut(), replacement_chars);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_content_run_open = self.content_run_open;
        let saved_allow_restricted = self.allow_restricted_char_in_content;
        let stack_depth_at_entry = self.element_stack.len();

        self.pos = 0;
        self.limit = self.buf.as_chars().len();
        self.content_run_open = false;
        self.allow_restricted_char_in_content = self.restricted_char_entities.contains(name);
        self.entity_stack_floors.push(stack_depth_at_entry);

        let scan_result = self.scan();

        let final_result = (|| -> ParseResult<()> {
            scan_result?;
            if self.pos != self.limit
                || self.in_start_tag
                || self.in_attribute_value
                || self.in_pi
                || self.in_comment
                || self.in_cdata
                || self.in_doctype
            {
                let msg = format!("Entity \"{name}\" replacement text is not well-formed");
                return Err(self.fatal(&msg));
            }
            if self.element_stack.len() != stack_depth_at_entry {
                let msg = format!(
                    "Well-Formedness Constraint: Parsed Entity (Section 4.1). Entity \"{name}\" replacement text is not well-formed: element boundaries must nest within entity boundaries"
                );
                return Err(self.fatal(&msg));
            }
            if self.content_run_open {
                let ws = self.content_run_is_whitespace;
                self.emit_content_empty(true, ws)?;
            }
            self.handler.end_entity(name)?;
            Ok(())
        })();

        *self.buf.as_chars_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.content_run_open = saved_content_run_open;
        self.allow_restricted_char_in_content = saved_allow_restricted;
        self.entity_expansion_stack.pop();
        self.entity_stack_floors.pop();

        final_result
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `expand_general_entity_in_content`. `fetch_external_entity`/
    /// `strip_declaration` are reused unchanged (neither touches
    /// `self.buf`); the replacement text is re-encoded to UTF-8 once
    /// before swapping it in, and the recursive parse goes through
    /// `scan_bytes` (the byte-native top-level dispatch loop) instead of
    /// `scan` — general entity replacement text in content can contain
    /// arbitrary well-formed markup (tags, comments, PIs, nested entity
    /// refs), unlike a parameter entity's replacement text in the DTD.
    #[allow(dead_code)]
    fn expand_general_entity_in_content_bytes(&mut self, name: &str) -> ParseResult<()> {
        if !self.check_entity_referenceable(name, true)? {
            return Ok(());
        }
        let external = self.external_entity_names.get(name).cloned();
        self.handler.start_entity(name)?;
        let replacement_bytes: BytesMut;
        if let Some(ext) = external {
            if !self.settings.external_general_entities {
                self.handler.end_entity(name)?;
                return Ok(());
            }
            let fetched =
                self.fetch_external_entity(name, ext.public_id.as_deref(), ext.system_id.as_deref())?;
            let stripped = self.strip_declaration(&fetched)?;
            let encoded: String = stripped.iter().collect();
            replacement_bytes = BytesMut::from(encoded.as_bytes());
        } else {
            // Unlike the char path (which caches flattened `[char]` text
            // and clones it per use), the byte path caches the flattened
            // text pre-encoded to UTF-8 too — so a repeat reference skips
            // straight to a byte copy instead of re-encoding chars ->
            // UTF-8 on every single occurrence.
            replacement_bytes = match self.flatten_content_entity_bytes_cached(name)? {
                Some(flat) => BytesMut::from(flat.as_bytes()),
                None => {
                    let raw = self.general_entities.get(name).cloned().unwrap_or_default();
                    let encoded: String = raw.iter().collect();
                    BytesMut::from(encoded.as_bytes())
                }
            };
        }

        self.entity_expansion_stack.push(name.to_string());
        let saved_buf = std::mem::replace(self.buf.as_bytes_mut(), replacement_bytes);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_content_run_open = self.content_run_open;
        let saved_allow_restricted = self.allow_restricted_char_in_content;
        let stack_depth_at_entry = self.element_stack.len();

        self.pos = 0;
        self.limit = self.buf.as_bytes().len();
        self.content_run_open = false;
        self.allow_restricted_char_in_content = self.restricted_char_entities.contains(name);
        self.entity_stack_floors.push(stack_depth_at_entry);

        let scan_result = self.scan_bytes();

        let final_result = (|| -> ParseResult<()> {
            scan_result?;
            if self.pos != self.limit
                || self.in_start_tag
                || self.in_attribute_value
                || self.in_pi
                || self.in_comment
                || self.in_cdata
                || self.in_doctype
            {
                let msg = format!("Entity \"{name}\" replacement text is not well-formed");
                return Err(self.fatal(&msg));
            }
            if self.element_stack.len() != stack_depth_at_entry {
                let msg = format!(
                    "Well-Formedness Constraint: Parsed Entity (Section 4.1). Entity \"{name}\" replacement text is not well-formed: element boundaries must nest within entity boundaries"
                );
                return Err(self.fatal(&msg));
            }
            if self.content_run_open {
                let ws = self.content_run_is_whitespace;
                self.emit_content_empty(true, ws)?;
            }
            self.handler.end_entity(name)?;
            Ok(())
        })();

        *self.buf.as_bytes_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.content_run_open = saved_content_run_open;
        self.allow_restricted_char_in_content = saved_allow_restricted;
        self.entity_expansion_stack.pop();
        self.entity_stack_floors.pop();

        final_result
    }

    fn expand_general_entity_in_attribute_value(&mut self, name: &str) -> ParseResult<String> {
        // check_entity_referenceable runs unconditionally, cache hit or
        // not: it's what enforces the recursive-reference check and the
        // per-reference entity-expansion-count limit, and both need to see
        // every reference, not just the first (a document that references
        // the same entity 100,000 times must still hit the limit, even
        // though each individual expansion is now cheap).
        if !self.check_entity_referenceable(name, false)? {
            return Ok(String::new());
        }
        // A cache hit means resolving this entity's normalized attribute
        // text once already ran the full recursive walk over the DTD's
        // nested entity graph — reuse that result rather than redoing the
        // walk. Without this, a document referencing one N-levels-deep
        // entity M times redoes that whole walk M times, and the walk
        // itself is already doing repeated work per level, compounding
        // multiplicatively (a real, measured hot path: see
        // relaxng/good_attr.xml in the benchmark corpus).
        if let Some(cached) = self.attribute_entity_cache.get(name) {
            return Ok(cached.to_string());
        }
        // A refcount bump, not a String clone + re-decode: the replacement
        // text is identical on every reference to this entity, so there's
        // nothing to gain from copying it fresh each time.
        let replacement: Rc<[char]> = self.general_entities.get(name).cloned().unwrap_or_default();
        self.entity_expansion_stack.push(name.to_string());
        let context = format!("entity \"{name}\"");
        let result = self.resolve_attribute_text(&replacement, &context);
        self.entity_expansion_stack.pop();
        if let Ok(resolved) = &result {
            self.attribute_entity_cache
                .insert(name.to_string(), Rc::from(resolved.as_str()));
        }
        result
    }

    fn resolve_attribute_text(&mut self, text: &[char], context: &str) -> ParseResult<String> {
        let len = text.len();
        let mut sb = String::with_capacity(len);
        let mut q = 0;
        while q < len {
            let c = text[q];
            if c == '<' {
                let msg = format!("'<' is not allowed in an attribute value (via {context})");
                return Err(self.fatal(&msg));
            }
            if is_ws(c) {
                sb.push(' ');
                q += 1;
                continue;
            }
            if c != '&' {
                sb.push(c);
                q += 1;
                continue;
            }
            let name_start = q + 1;
            let mut p = name_start;
            while p < len && is_name_char(text[p]) {
                p += 1;
            }
            if p >= len || text[p] != ';' {
                let msg = format!("Malformed entity reference in {context}");
                return Err(self.fatal(&msg));
            }
            if let Some(predef) = match_predefined(text, name_start, p - name_start) {
                sb.push_str(predef);
            } else {
                let ref_name: String = text[name_start..p].iter().collect();
                let expanded = self.expand_general_entity_in_attribute_value(&ref_name)?;
                sb.push_str(&expanded);
            }
            q = p + 1;
        }
        Ok(sb)
    }

    fn resolve_attlist_default_value(&mut self, raw: &str) -> ParseResult<String> {
        let chars: Vec<char> = raw.chars().collect();
        self.resolve_attribute_text(&chars, "an attribute default value")
    }

    fn check_attlist_default_entities_declared(
        &mut self,
        raw: &str,
        pending: &PendingDecls,
    ) -> ParseResult<()> {
        let text: Vec<char> = raw.chars().collect();
        let len = text.len();
        let mut q = 0;
        while q < len {
            if text[q] != '&' {
                q += 1;
                continue;
            }
            let name_start = q + 1;
            let mut p = name_start;
            while p < len && is_name_char(text[p]) {
                p += 1;
            }
            if p >= len || text[p] != ';' {
                q += 1;
                continue;
            }
            if match_predefined(&text, name_start, p - name_start).is_none() {
                let name: String = text[name_start..p].iter().collect();
                if !pending.entities.contains_key(&name)
                    && !pending.external_names.contains_key(&name)
                    && !self.general_entities.contains_key(&name)
                    && !self.external_entity_names.contains_key(&name)
                {
                    let msg = format!(
                        "Well-Formedness Constraint: Entity Declared (Section 4.1). Entity \"{name}\" referenced in an attribute default value must be declared before the <!ATTLIST> declaration that references it."
                    );
                    return Err(self.fatal(&msg));
                }
            }
            q = p + 1;
        }
        Ok(())
    }

    // ===== External fetching =====

    fn resolve_system_id(&self, system_id: Option<&str>) -> Option<String> {
        let system_id = system_id?;
        match &self.base_system_id {
            None => Some(system_id.to_string()),
            Some(base) => Some(crate::entity::resolve_uri(Some(base), system_id)),
        }
    }

    fn fetch_external_resource(
        &mut self,
        name: &str,
        what: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> ParseResult<Vec<char>> {
        if let Some(sid) = system_id {
            let check_id = if self.settings.resolve_dtd_uris {
                self.resolve_system_id(Some(sid)).unwrap_or_else(|| sid.to_string())
            } else {
                sid.to_string()
            };
            if self.settings.access_external_dtd.trim().is_empty() {
                let msg = format!(
                    "Access to external entity denied by accessExternalDTD property (no protocols allowed): {check_id}"
                );
                return Err(self.fatal(&msg));
            }
            if !protocol_allowed(&check_id, &self.settings.access_external_dtd) {
                let msg = format!("Access to external entity denied by accessExternalDTD property: {check_id}");
                return Err(self.fatal(&msg));
            }
        }

        // Try the resolver first.
        let base = self.base_system_id.clone();
        let resolved_system_for_read = if self.settings.resolve_dtd_uris {
            self.resolve_system_id(system_id)
        } else {
            system_id.map(|s| s.to_string())
        };
        let mut data: Option<Vec<u8>> = None;
        let mut encoding_hint: Option<String> = None;
        let mut resolved_location = resolved_system_for_read.clone();

        if let Some(resolver) = self.entity_resolver.as_mut() {
            // Pass the literal system id with the document base so the
            // resolver can join once. Also try the pre-resolved form.
            let literal = system_id.unwrap_or("");
            let mut resolved =
                resolver.resolve_entity(name, public_id, literal, base.as_deref())?;
            if resolved.is_none() {
                if let Some(ref rsid) = resolved_system_for_read {
                    if rsid != literal {
                        resolved = resolver.resolve_entity(name, public_id, rsid, None)?;
                    }
                }
            }
            if let Some(ent) = resolved {
                data = Some(ent.data.to_vec());
                if let Some(sysid) = ent.system_id {
                    resolved_location = Some(sysid);
                }
                let _ = &mut encoding_hint;
            }
        }

        if data.is_none() {
            let rsid = match &resolved_system_for_read {
                Some(s) => s.clone(),
                None => {
                    let msg = format!("Cannot resolve {what}: no system identifier");
                    return Err(self.fatal(&msg));
                }
            };
            match read_system_id(&rsid) {
                Ok(bytes) => {
                    data = Some(bytes);
                    resolved_location = Some(rsid);
                }
                Err(e) => {
                    let msg = format!("Failed to fetch {what} ({rsid}): {e}");
                    return Err(self.fatal(&msg));
                }
            }
        }

        self.last_resolved_system_id = resolved_location;
        let chars = decoder::decode_bytes(&data.unwrap(), encoding_hint.as_deref());
        self.check_version_compatibility(&chars, what)?;
        Ok(chars)
    }

    fn check_version_compatibility(&mut self, chars: &[char], what: &str) -> ParseResult<()> {
        let v = decoder::extract_version_num(chars);
        match v {
            None => Ok(()),
            Some(ref ver) if ver == "1.0" => Ok(()),
            Some(ref ver) if self.xml11 && ver == "1.1" => Ok(()),
            Some(ver) => {
                let own = if self.xml11 { "1.1" } else { "1.0" };
                let msg = format!(
                    "XML 1.1 Section 4.3.4: {what} declares version \"{ver}\", which is not compatible with this document's own version ({own})"
                );
                Err(self.fatal(&msg))
            }
        }
    }

    fn fetch_external_entity(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> ParseResult<Vec<char>> {
        let what = format!("entity \"{name}\"");
        self.fetch_external_resource(name, &what, public_id, system_id)
    }

    fn strip_declaration(&mut self, chars: &[char]) -> ParseResult<Vec<char>> {
        match decoder::strip_xml_declaration(chars) {
            Ok(v) => Ok(v),
            Err(msg) => Err(self.fatal(&msg)),
        }
    }

    fn parse_external_subset(&mut self, raw_chars: &[char]) -> ParseResult<()> {
        let chars = self.strip_declaration(raw_chars)?;
        let mut pending = PendingDecls::default();

        let saved_buf = std::mem::replace(self.buf.as_chars_mut(), chars);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        self.pos = 0;
        self.limit = self.buf.as_chars().len();
        self.parsing_external_content = true;

        let result = self.parse_markup_decl_seq(false, false, &mut pending);

        let commit_result = if result.is_ok() {
            self.commit_external_subset(&mut pending)
        } else {
            Ok(())
        };

        *self.buf.as_chars_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.parsing_external_content = saved_parsing;

        result?;
        commit_result
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `parse_external_subset`. The fetched content is always `Vec<char>`
    /// (straight out of `fetch_external_resource`'s own decode step,
    /// independent of the live scanner's representation), so it's
    /// re-encoded to UTF-8 once before swapping it in as `self.buf`'s
    /// temporary content -- same swap-parse-restore shape as
    /// `expand_parameter_entity_reference_bytes`, over `parse_markup_decl_seq_bytes`
    /// instead of the char version.
    ///
    /// This function exists because `parse_external_subset` itself
    /// unconditionally swaps `self.buf.as_chars_mut()`, which panics if
    /// the live scanner is currently in byte mode -- unlike every other
    /// "operates on its own data, never touches self.buf" function found
    /// so far in this exploration, this one genuinely reaches into
    /// `self.buf`'s outer representation.
    #[allow(dead_code)]
    fn parse_external_subset_bytes(&mut self, raw_chars: &[char]) -> ParseResult<()> {
        let chars = self.strip_declaration(raw_chars)?;
        let mut pending = PendingDecls::default();

        let encoded: String = chars.iter().collect();
        let saved_buf =
            std::mem::replace(self.buf.as_bytes_mut(), BytesMut::from(encoded.as_bytes()));
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        self.pos = 0;
        self.limit = self.buf.as_bytes().len();
        self.parsing_external_content = true;

        let result = self.parse_markup_decl_seq_bytes(false, false, &mut pending);

        let commit_result = if result.is_ok() {
            self.commit_external_subset(&mut pending)
        } else {
            Ok(())
        };

        *self.buf.as_bytes_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.parsing_external_content = saved_parsing;

        result?;
        commit_result
    }

    fn commit_external_subset(&mut self, pending: &mut PendingDecls) -> ParseResult<()> {
        for (k, v) in pending.entities.drain() {
            if !self.general_entities.contains_key(&k) && !self.external_entity_names.contains_key(&k)
            {
                self.general_entities.insert(k, v);
            }
        }
        let external_names: Vec<(String, ExtEntity)> =
            pending.external_names.drain().collect();
        for (k, v) in external_names {
            if !self.general_entities.contains_key(&k) && !self.external_entity_names.contains_key(&k)
            {
                if let Some(notation) = v.ndata.clone() {
                    self.handler.unparsed_entity_decl(
                        &k,
                        v.public_id.as_deref(),
                        v.system_id.as_deref(),
                        &notation,
                    )?;
                }
                self.external_entity_names.insert(k, v);
            }
        }
        for (k, v) in pending.param_entities.drain() {
            if !self.parameter_entities.contains_key(&k)
                && !self.parameter_entity_external_ids.contains_key(&k)
            {
                self.parameter_entities.insert(k, v);
            }
        }
        for (k, v) in pending.param_external_names.drain() {
            if !self.parameter_entities.contains_key(&k)
                && !self.parameter_entity_external_ids.contains_key(&k)
            {
                self.parameter_entity_external_ids.insert(k, v);
            }
        }
        Ok(())
    }

    fn parse_markup_decl_seq(
        &mut self,
        stop_at_section_end: bool,
        section_opener_from_splice: bool,
        pending: &mut PendingDecls,
    ) -> ParseResult<()> {
        loop {
            self.pos = self.skip_optional_whitespace(self.pos);
            if stop_at_section_end
                && self.pos + 2 < self.limit
                && self.buf[self.pos] == ']'
                && self.buf[self.pos + 1] == ']'
                && self.buf[self.pos + 2] == '>'
            {
                if ((self.pos as i64) < self.last_splice_end) != section_opener_from_splice {
                    self.handler.error(
                        "Validity Constraint: Proper Conditional Section/PE Nesting (Section 3.4). A conditional section's opening and closing delimiters must be contained in the same parameter entity replacement text (or both be literal).",
                    )?;
                }
                self.pos += 3;
                return Ok(());
            }
            if self.pos >= self.limit {
                if stop_at_section_end {
                    return Err(self.fatal("Unterminated INCLUDE conditional section"));
                }
                return Ok(());
            }
            let c = self.buf[self.pos];
            if c == '%' {
                self.expand_parameter_entity_reference(pending)?;
                continue;
            }
            if c != '<' || self.pos + 1 >= self.limit {
                return Err(self.fatal("Malformed markup declaration"));
            }
            let c2 = self.buf[self.pos + 1];
            if c2 == '?' {
                if !self.scan_pi(self.pos)? {
                    return Err(self.fatal("Malformed processing instruction"));
                }
            } else if c2 == '!' {
                if self.pos + 2 >= self.limit {
                    return Err(self.fatal("Malformed markup declaration"));
                }
                if self.buf[self.pos + 2] == '-' {
                    if !self.scan_comment(self.pos)? {
                        return Err(self.fatal("Malformed comment"));
                    }
                } else if self.buf[self.pos + 2] == '[' {
                    self.parse_conditional_section(pending)?;
                } else {
                    match self.match_keyword(self.pos, ENTITY_MARKER) {
                        KwResult::Match => {
                            let start = self.pos + ENTITY_MARKER.len();
                            match self.scan_entity_declaration(start, pending)? {
                                None => return Err(self.fatal("Malformed entity declaration")),
                                Some(r) => self.pos = r,
                            }
                        }
                        _ => match self.match_keyword(self.pos, ATTLIST_MARKER) {
                            KwResult::Match => {
                                let start = self.pos + ATTLIST_MARKER.len();
                                match self.scan_attlist_declaration(start, pending)? {
                                    None => {
                                        return Err(self.fatal("Malformed attribute-list declaration"))
                                    }
                                    Some(r) => self.pos = r,
                                }
                            }
                            _ => match self.match_keyword(self.pos, ELEMENT_MARKER) {
                                KwResult::Match => {
                                    let start = self.pos + ELEMENT_MARKER.len();
                                    match self.scan_element_declaration(start, pending)? {
                                        None => {
                                            return Err(self.fatal("Malformed element declaration"))
                                        }
                                        Some(r) => self.pos = r,
                                    }
                                }
                                _ => match self.match_keyword(self.pos, NOTATION_MARKER) {
                                    KwResult::Match => {
                                        let start = self.pos + NOTATION_MARKER.len();
                                        match self.scan_notation_declaration(start)? {
                                            None => {
                                                return Err(self.fatal("Malformed notation declaration"))
                                            }
                                            Some(r) => self.pos = r,
                                        }
                                    }
                                    _ => {
                                        return Err(self.fatal("Expected an element, attribute-list, entity, or notation declaration"))
                                    }
                                },
                            },
                        },
                    }
                }
            } else {
                return Err(self.fatal("Malformed markup declaration"));
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `parse_markup_decl_seq`. Used by `expand_parameter_entity_reference_bytes`
    /// to parse a parameter entity's replacement text as a standalone
    /// declaration sequence (the rare "PE reference used as a declaration
    /// separator, expanding to one or more full declarations" case) — a
    /// 1:1 structural port dispatching to every byte-native declaration
    /// scanner built so far, plus `parse_conditional_section_bytes` for
    /// nested `INCLUDE`/`IGNORE` sections.
    #[allow(dead_code)]
    fn parse_markup_decl_seq_bytes(
        &mut self,
        stop_at_section_end: bool,
        section_opener_from_splice: bool,
        pending: &mut PendingDecls,
    ) -> ParseResult<()> {
        loop {
            self.pos = self.skip_optional_whitespace_bytes(self.pos);
            if stop_at_section_end
                && self.pos + 2 < self.limit
                && self.buf.as_bytes()[self.pos] == b']'
                && self.buf.as_bytes()[self.pos + 1] == b']'
                && self.buf.as_bytes()[self.pos + 2] == b'>'
            {
                if ((self.pos as i64) < self.last_splice_end) != section_opener_from_splice {
                    self.handler.error(
                        "Validity Constraint: Proper Conditional Section/PE Nesting (Section 3.4). A conditional section's opening and closing delimiters must be contained in the same parameter entity replacement text (or both be literal).",
                    )?;
                }
                self.pos += 3;
                return Ok(());
            }
            if self.pos >= self.limit {
                if stop_at_section_end {
                    return Err(self.fatal("Unterminated INCLUDE conditional section"));
                }
                return Ok(());
            }
            let c = self.buf.as_bytes()[self.pos];
            if c == b'%' {
                self.expand_parameter_entity_reference_bytes(pending)?;
                continue;
            }
            if c != b'<' || self.pos + 1 >= self.limit {
                return Err(self.fatal("Malformed markup declaration"));
            }
            let c2 = self.buf.as_bytes()[self.pos + 1];
            if c2 == b'?' {
                if !self.scan_pi_bytes(self.pos)? {
                    return Err(self.fatal("Malformed processing instruction"));
                }
            } else if c2 == b'!' {
                if self.pos + 2 >= self.limit {
                    return Err(self.fatal("Malformed markup declaration"));
                }
                if self.buf.as_bytes()[self.pos + 2] == b'-' {
                    if !self.scan_comment_bytes(self.pos)? {
                        return Err(self.fatal("Malformed comment"));
                    }
                } else if self.buf.as_bytes()[self.pos + 2] == b'[' {
                    self.parse_conditional_section_bytes(pending)?;
                } else {
                    match self.match_keyword_bytes(self.pos, ENTITY_MARKER) {
                        KwResult::Match => {
                            let start = self.pos + ENTITY_MARKER.len();
                            match self.scan_entity_declaration_bytes(start, pending)? {
                                None => return Err(self.fatal("Malformed entity declaration")),
                                Some(r) => self.pos = r,
                            }
                        }
                        _ => match self.match_keyword_bytes(self.pos, ATTLIST_MARKER) {
                            KwResult::Match => {
                                let start = self.pos + ATTLIST_MARKER.len();
                                match self.scan_attlist_declaration_bytes(start, pending)? {
                                    None => {
                                        return Err(
                                            self.fatal("Malformed attribute-list declaration")
                                        )
                                    }
                                    Some(r) => self.pos = r,
                                }
                            }
                            _ => match self.match_keyword_bytes(self.pos, ELEMENT_MARKER) {
                                KwResult::Match => {
                                    let start = self.pos + ELEMENT_MARKER.len();
                                    match self.scan_element_declaration_bytes(start, pending)? {
                                        None => {
                                            return Err(
                                                self.fatal("Malformed element declaration")
                                            )
                                        }
                                        Some(r) => self.pos = r,
                                    }
                                }
                                _ => match self.match_keyword_bytes(self.pos, NOTATION_MARKER) {
                                    KwResult::Match => {
                                        let start = self.pos + NOTATION_MARKER.len();
                                        match self.scan_notation_declaration_bytes(start)? {
                                            None => {
                                                return Err(
                                                    self.fatal("Malformed notation declaration")
                                                )
                                            }
                                            Some(r) => self.pos = r,
                                        }
                                    }
                                    _ => {
                                        return Err(self.fatal("Expected an element, attribute-list, entity, or notation declaration"))
                                    }
                                },
                            },
                        },
                    }
                }
            } else {
                return Err(self.fatal("Malformed markup declaration"));
            }
        }
    }

    fn parse_conditional_section(&mut self, pending: &mut PendingDecls) -> ParseResult<()> {
        self.pos += 3; // "<!["
        self.pos = self.skip_whitespace_in_declaration(self.pos, pending, false)?;
        let include;
        match self.match_keyword(self.pos, INCLUDE_MARKER) {
            KwResult::Match => {
                include = true;
                self.pos += INCLUDE_MARKER.len();
            }
            _ => match self.match_keyword(self.pos, IGNORE_MARKER) {
                KwResult::Match => {
                    include = false;
                    self.pos += IGNORE_MARKER.len();
                }
                _ => {
                    return Err(
                        self.fatal("Malformed conditional section: expected INCLUDE or IGNORE")
                    )
                }
            },
        }
        self.pos = self.skip_optional_whitespace(self.pos);
        if self.pos >= self.limit || self.buf[self.pos] != '[' {
            return Err(self.fatal("Malformed conditional section"));
        }
        let opener_from_splice = (self.pos as i64) < self.last_splice_end;
        self.pos += 1;
        if include {
            self.parse_markup_decl_seq(true, opener_from_splice, pending)?;
        } else {
            self.skip_ignored_section()?;
        }
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `parse_conditional_section`.
    #[allow(dead_code)]
    fn parse_conditional_section_bytes(&mut self, pending: &mut PendingDecls) -> ParseResult<()> {
        self.pos += 3; // "<!["
        self.pos = self.skip_whitespace_in_declaration_bytes(self.pos, pending, false)?;
        let include;
        match self.match_keyword_bytes(self.pos, INCLUDE_MARKER) {
            KwResult::Match => {
                include = true;
                self.pos += INCLUDE_MARKER.len();
            }
            _ => match self.match_keyword_bytes(self.pos, IGNORE_MARKER) {
                KwResult::Match => {
                    include = false;
                    self.pos += IGNORE_MARKER.len();
                }
                _ => {
                    return Err(
                        self.fatal("Malformed conditional section: expected INCLUDE or IGNORE")
                    )
                }
            },
        }
        self.pos = self.skip_optional_whitespace_bytes(self.pos);
        if self.pos >= self.limit || self.buf.as_bytes()[self.pos] != b'[' {
            return Err(self.fatal("Malformed conditional section"));
        }
        let opener_from_splice = (self.pos as i64) < self.last_splice_end;
        self.pos += 1;
        if include {
            self.parse_markup_decl_seq_bytes(true, opener_from_splice, pending)?;
        } else {
            self.skip_ignored_section_bytes()?;
        }
        Ok(())
    }

    fn skip_ignored_section(&mut self) -> ParseResult<()> {
        let mut depth = 1;
        while depth > 0 {
            if self.pos + 2 < self.limit
                && self.buf[self.pos] == '<'
                && self.buf[self.pos + 1] == '!'
                && self.buf[self.pos + 2] == '['
            {
                depth += 1;
                self.pos += 3;
            } else if self.pos + 2 < self.limit
                && self.buf[self.pos] == ']'
                && self.buf[self.pos + 1] == ']'
                && self.buf[self.pos + 2] == '>'
            {
                depth -= 1;
                self.pos += 3;
            } else if self.pos < self.limit {
                self.pos += 1;
            } else {
                return Err(self.fatal("Unterminated IGNORE conditional section"));
            }
        }
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_ignored_section`. Never interprets a skipped byte as a
    /// character (the char path doesn't either — it only ever compares
    /// against the three ASCII marker bytes), so walking one raw byte at a
    /// time through a multi-byte sequence's non-marker bytes is exactly
    /// equivalent, no decoding needed at all.
    #[allow(dead_code)]
    fn skip_ignored_section_bytes(&mut self) -> ParseResult<()> {
        let mut depth = 1;
        while depth > 0 {
            if self.pos + 2 < self.limit
                && self.buf.as_bytes()[self.pos] == b'<'
                && self.buf.as_bytes()[self.pos + 1] == b'!'
                && self.buf.as_bytes()[self.pos + 2] == b'['
            {
                depth += 1;
                self.pos += 3;
            } else if self.pos + 2 < self.limit
                && self.buf.as_bytes()[self.pos] == b']'
                && self.buf.as_bytes()[self.pos + 1] == b']'
                && self.buf.as_bytes()[self.pos + 2] == b'>'
            {
                depth -= 1;
                self.pos += 3;
            } else if self.pos < self.limit {
                self.pos += 1;
            } else {
                return Err(self.fatal("Unterminated IGNORE conditional section"));
            }
        }
        Ok(())
    }

    fn expand_parameter_entity_reference(&mut self, pending: &mut PendingDecls) -> ParseResult<()> {
        let name_start = self.pos + 1;
        let mut q = name_start;
        while q < self.limit && is_name_char(self.buf[q]) {
            q += 1;
        }
        if q >= self.limit || self.buf[q] != ';' {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        if q == name_start {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        self.check_name_start_char(name_start)?;
        let name = self.slice(name_start, q);
        let resume_at = q + 1;

        if !self.parsing_external_content {
            self.saw_internal_subset_parameter_entity_reference = true;
        }
        let replacement_chars = match self.resolve_parameter_entity_replacement(&name, pending)? {
            Some(v) => v,
            None => return Ok(()),
        };

        if self.parameter_entity_expansion_stack.contains(&name) {
            let msg = format!("Recursive parameter entity reference: %{name};");
            return Err(self.fatal(&msg));
        }
        self.check_entity_expansion_limit(replacement_chars.len() as i64)?;
        self.parameter_entity_expansion_stack.push(name.clone());

        // self.buf must be a uniquely-owned Vec<char> (the recursive parse
        // below writes into it, including further splices) — this copy is
        // a plain slice memcpy from the shared Rc, not a UTF-8 re-decode.
        let saved_buf = std::mem::replace(self.buf.as_chars_mut(), replacement_chars.to_vec());
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        let saved_base = self.base_system_id.clone();
        self.pos = 0;
        self.limit = self.buf.as_chars().len();
        if self.last_param_entity_was_external {
            self.parsing_external_content = true;
            self.base_system_id = self.last_resolved_system_id.clone();
        }

        let result = (|| -> ParseResult<()> {
            self.parse_markup_decl_seq(false, false, pending)?;
            if self.pos != self.limit {
                let msg = format!("Parameter entity \"{name}\" replacement text is not well-formed");
                return Err(self.fatal(&msg));
            }
            Ok(())
        })();

        *self.buf.as_chars_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.parsing_external_content = saved_parsing;
        self.base_system_id = saved_base;
        self.parameter_entity_expansion_stack.pop();
        result?;
        self.pos = resume_at;
        Ok(())
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `expand_parameter_entity_reference`. `resolve_parameter_entity_replacement`
    /// still returns `Rc<[char]>` (entity replacement text is resolved
    /// once and cached that way regardless of which path is scanning), so
    /// the one representation-dependent step is re-encoding it to UTF-8
    /// before swapping it in as `self.buf`'s temporary content — the same
    /// swap-parse-restore shape as the char path, just over a `BytesMut`
    /// instead of a `Vec<char>`.
    #[allow(dead_code)]
    fn expand_parameter_entity_reference_bytes(
        &mut self,
        pending: &mut PendingDecls,
    ) -> ParseResult<()> {
        let name_start = self.pos + 1;
        let q = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore | NameScanBytes::Illegal => {
                return Err(self.fatal("Malformed parameter entity reference"));
            }
            NameScanBytes::End(q) => q,
        };
        if q >= self.limit || self.buf.as_bytes()[q] != b';' {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        if q == name_start {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        self.check_name_start_char_bytes(name_start)?;
        let name = self.slice_bytes(name_start, q);
        let resume_at = q + 1;

        if !self.parsing_external_content {
            self.saw_internal_subset_parameter_entity_reference = true;
        }
        let replacement_chars = match self.resolve_parameter_entity_replacement(&name, pending)? {
            Some(v) => v,
            None => return Ok(()),
        };

        if self.parameter_entity_expansion_stack.contains(&name) {
            let msg = format!("Recursive parameter entity reference: %{name};");
            return Err(self.fatal(&msg));
        }
        self.check_entity_expansion_limit(replacement_chars.len() as i64)?;
        self.parameter_entity_expansion_stack.push(name.clone());

        let encoded: String = replacement_chars.iter().collect();
        let saved_buf =
            std::mem::replace(self.buf.as_bytes_mut(), BytesMut::from(encoded.as_bytes()));
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        let saved_base = self.base_system_id.clone();
        self.pos = 0;
        self.limit = self.buf.as_bytes().len();
        if self.last_param_entity_was_external {
            self.parsing_external_content = true;
            self.base_system_id = self.last_resolved_system_id.clone();
        }

        let result = (|| -> ParseResult<()> {
            self.parse_markup_decl_seq_bytes(false, false, pending)?;
            if self.pos != self.limit {
                let msg = format!("Parameter entity \"{name}\" replacement text is not well-formed");
                return Err(self.fatal(&msg));
            }
            Ok(())
        })();

        *self.buf.as_bytes_mut() = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.parsing_external_content = saved_parsing;
        self.base_system_id = saved_base;
        self.parameter_entity_expansion_stack.pop();
        result?;
        self.pos = resume_at;
        Ok(())
    }

    fn resolve_parameter_entity_replacement(
        &mut self,
        name: &str,
        pending: &PendingDecls,
    ) -> ParseResult<Option<Rc<[char]>>> {
        // `.cloned()` here clones an `Rc` (refcount bump), not the
        // underlying text — repeat references to the same entity (the
        // common case; that's what parameter entities are for) no longer
        // pay to re-decode UTF-8 into a fresh `Vec<char>` every time.
        let literal = pending
            .param_entities
            .get(name)
            .cloned()
            .or_else(|| self.parameter_entities.get(name).cloned());
        if let Some(literal) = literal {
            self.last_param_entity_was_external = false;
            return Ok(Some(literal));
        }
        let external = pending
            .param_external_names
            .get(name)
            .cloned()
            .or_else(|| self.parameter_entity_external_ids.get(name).cloned());
        let external = match external {
            None => {
                let msg = format!("Parameter entity \"%{name};\" was not declared");
                return Err(self.fatal(&msg));
            }
            Some(e) => e,
        };
        if !self.settings.external_parameter_entities {
            self.last_param_entity_was_external = true;
            return Ok(Some(Rc::from([])));
        }
        self.last_param_entity_was_external = true;
        let saved_base = self.base_system_id.clone();
        if external.decl_base.is_some() {
            self.base_system_id = external.decl_base.clone();
        }
        let what = format!("parameter entity \"{name}\"");
        let fetched = self.fetch_external_resource(
            &format!("%{name}"),
            &what,
            external.public_id.as_deref(),
            external.system_id.as_deref(),
        );
        self.base_system_id = saved_base;
        let fetched = fetched?;
        Ok(Some(self.strip_declaration(&fetched)?.into()))
    }

    // ===== PE splicing inside declarations =====

    /// Splices `replacement` into `self.buf[start..end]`, padded with one
    /// leading and one trailing space (per the XML spec's requirement that
    /// a parameter-entity reference used as a declaration separator behave
    /// like whitespace). Writes the padding directly rather than requiring
    /// the caller to pre-build a padded copy — this is on the hot path for
    /// DTDs that use parameter entities as declaration separators, so it's
    /// worth not allocating a throwaway `Vec<char>` per reference.
    fn splice_into_buf(&mut self, start: usize, end: usize, replacement: &[char]) -> usize {
        let old_span = end - start;
        let new_span = replacement.len() + 2;
        let delta = new_span as i64 - old_span as i64;
        if delta > 0 {
            let needed = (self.limit as i64 + delta) as usize;
            if needed > self.buf.as_chars().len() {
                let mut newcap = self.buf.as_chars().len() * 2;
                while newcap < needed {
                    newcap *= 2;
                }
                self.buf.as_chars_mut().resize(newcap, '\u{0}');
            }
        }
        // Move tail.
        if new_span != old_span {
            let tail_len = self.limit - end;
            if delta > 0 {
                // shift right, back to front
                for i in (0..tail_len).rev() {
                    self.buf[start + new_span + i] = self.buf[end + i];
                }
            } else {
                for i in 0..tail_len {
                    self.buf[start + new_span + i] = self.buf[end + i];
                }
            }
        }
        self.buf[start] = ' ';
        for (i, c) in replacement.iter().enumerate() {
            self.buf[start + 1 + i] = *c;
        }
        self.buf[start + 1 + replacement.len()] = ' ';
        self.limit = (self.limit as i64 + delta) as usize;
        self.last_splice_end = (start + new_span) as i64;
        self.saw_splice_since_declaration_start = true;
        start
    }

    fn splice_pe_reference_at(
        &mut self,
        p: usize,
        pending: &mut PendingDecls,
        check_paren_balance: bool,
    ) -> ParseResult<usize> {
        let replacement_chars = match self.resolve_parameter_entity_reference_at(p, pending)? {
            None => return Ok(self.limit),
            Some(v) => v,
        };
        if check_paren_balance {
            self.check_pe_replacement_paren_balance(&replacement_chars)?;
        }
        let end = self.last_pe_reference_end;
        Ok(self.splice_into_buf(p, end, &replacement_chars))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `splice_into_buf`. The one genuinely representation-dependent step
    /// in the whole PE-splicing subsystem: `replacement` (always `[char]`,
    /// since entity replacement text is resolved once at declaration time
    /// and cached that way regardless of which path is scanning) has to be
    /// re-encoded to UTF-8 bytes before it can be spliced into a byte
    /// buffer -- unlike the char path, where a `char` is a `char` is a
    /// `char` and no re-encoding step exists at all. Everything else
    /// (capacity growth, tail-shifting, padding) is the same algorithm,
    /// just measured in bytes instead of chars.
    #[allow(dead_code)]
    fn splice_into_buf_bytes(&mut self, start: usize, end: usize, replacement: &[char]) -> usize {
        let encoded_string: String = replacement.iter().collect();
        let encoded = encoded_string.as_bytes();

        let old_span = end - start;
        let new_span = encoded.len() + 2;
        let delta = new_span as i64 - old_span as i64;
        if delta > 0 {
            let needed = (self.limit as i64 + delta) as usize;
            if needed > self.buf.as_bytes().len() {
                let mut newcap = self.buf.as_bytes().len().max(1) * 2;
                while newcap < needed {
                    newcap *= 2;
                }
                self.buf.as_bytes_mut().resize(newcap, 0);
            }
        }
        // Move tail.
        if new_span != old_span {
            let tail_len = self.limit - end;
            if delta > 0 {
                // shift right, back to front
                for i in (0..tail_len).rev() {
                    self.buf.as_bytes_mut()[start + new_span + i] = self.buf.as_bytes()[end + i];
                }
            } else {
                for i in 0..tail_len {
                    self.buf.as_bytes_mut()[start + new_span + i] = self.buf.as_bytes()[end + i];
                }
            }
        }
        self.buf.as_bytes_mut()[start] = b' ';
        self.buf.as_bytes_mut()[start + 1..start + 1 + encoded.len()].copy_from_slice(encoded);
        self.buf.as_bytes_mut()[start + 1 + encoded.len()] = b' ';
        self.limit = (self.limit as i64 + delta) as usize;
        self.last_splice_end = (start + new_span) as i64;
        self.saw_splice_since_declaration_start = true;
        start
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `splice_pe_reference_at`.
    #[allow(dead_code)]
    fn splice_pe_reference_at_bytes(
        &mut self,
        p: usize,
        pending: &mut PendingDecls,
        check_paren_balance: bool,
    ) -> ParseResult<usize> {
        let replacement_chars = match self.resolve_parameter_entity_reference_at_bytes(p, pending)?
        {
            None => return Ok(self.limit),
            Some(v) => v,
        };
        if check_paren_balance {
            self.check_pe_replacement_paren_balance(&replacement_chars)?;
        }
        let end = self.last_pe_reference_end;
        Ok(self.splice_into_buf_bytes(p, end, &replacement_chars))
    }

    fn check_pe_replacement_paren_balance(&mut self, replacement_chars: &[char]) -> ParseResult<()> {
        let mut depth = 0i32;
        for c in replacement_chars {
            if *c == '(' {
                depth += 1;
            } else if *c == ')' {
                depth -= 1;
                if depth < 0 {
                    break;
                }
            }
        }
        if depth != 0 {
            self.handler.error(
                "Validity Constraint: Proper Group/PE Nesting (Section 3.2.1). A parameter entity's replacement text must contain both parentheses of any choice/seq/Mixed group it contributes one of.",
            )?;
        }
        Ok(())
    }

    fn check_not_from_pe_splice(&mut self, p: usize, what: &str) -> ParseResult<()> {
        if self.saw_splice_since_declaration_start && (p as i64) < self.last_splice_end {
            let msg = format!(
                "Validity Constraint: Proper Declaration/PE Nesting (Section 3.2.1). The closing delimiter of {what} must be contained in the same parameter entity replacement text as its opening delimiter (here, the opening delimiter is literal, not from a parameter entity)."
            );
            self.handler.error(&msg)?;
        }
        Ok(())
    }

    fn resolve_parameter_entity_reference_at(
        &mut self,
        p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<Rc<[char]>>> {
        let name_start = p + 1;
        let mut q = name_start;
        while q < self.limit && is_name_char(self.buf[q]) {
            q += 1;
        }
        if q >= self.limit {
            return Ok(None);
        }
        if q == name_start || self.buf[q] != ';' {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        self.check_name_start_char(name_start)?;
        if !self.parsing_external_content {
            return Err(self.fatal(
                "Well-Formedness Constraint: PEs in Internal Subset (Section 2.8). A parameter entity reference may not occur within a markup declaration in the internal DTD subset.",
            ));
        }
        let name = self.slice(name_start, q);
        let replacement = match self.resolve_parameter_entity_replacement(&name, pending)? {
            Some(v) => v,
            None => return Ok(None),
        };
        self.check_entity_expansion_limit(replacement.len() as i64)?;
        self.last_pe_reference_end = q + 1;
        Ok(Some(replacement))
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `resolve_parameter_entity_reference_at`. Only the name-scanning
    /// step is representation-dependent -- `resolve_parameter_entity_replacement`
    /// already operates purely on entity tables and returns `Rc<[char]>`
    /// regardless of which path resolved the name, so it's reused
    /// unchanged. Buffer splicing itself (`splice_into_buf`) is a
    /// separate, still-char-only concern this hands off to (used for PE
    /// references as declaration separators, not from within a quoted
    /// literal).
    #[allow(dead_code)]
    fn resolve_parameter_entity_reference_at_bytes(
        &mut self,
        p: usize,
        pending: &mut PendingDecls,
    ) -> ParseResult<Option<Rc<[char]>>> {
        let name_start = p + 1;
        let q = match self.scan_name_chars_bytes(name_start) {
            NameScanBytes::NeedMore => return Ok(None),
            NameScanBytes::Illegal => {
                return Err(self.fatal("Malformed parameter entity reference"));
            }
            NameScanBytes::End(q) => q,
        };
        if q == name_start || self.buf.as_bytes()[q] != b';' {
            return Err(self.fatal("Malformed parameter entity reference"));
        }
        self.check_name_start_char_bytes(name_start)?;
        if !self.parsing_external_content {
            return Err(self.fatal(
                "Well-Formedness Constraint: PEs in Internal Subset (Section 2.8). A parameter entity reference may not occur within a markup declaration in the internal DTD subset.",
            ));
        }
        let name = self.slice_bytes(name_start, q);
        let replacement = match self.resolve_parameter_entity_replacement(&name, pending)? {
            Some(v) => v,
            None => return Ok(None),
        };
        self.check_entity_expansion_limit(replacement.len() as i64)?;
        self.last_pe_reference_end = q + 1;
        Ok(Some(replacement))
    }

    fn skip_whitespace_in_declaration(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
        check_paren_balance: bool,
    ) -> ParseResult<usize> {
        loop {
            p = self.skip_optional_whitespace(p);
            if p >= self.limit || self.buf[p] != '%' {
                return Ok(p);
            }
            p = self.splice_pe_reference_at(p, pending, check_paren_balance)?;
            if p >= self.limit {
                return Ok(p);
            }
        }
    }

    /// Exploratory (explore/utf8-byte-path): byte-native counterpart to
    /// `skip_whitespace_in_declaration`.
    #[allow(dead_code)]
    fn skip_whitespace_in_declaration_bytes(
        &mut self,
        mut p: usize,
        pending: &mut PendingDecls,
        check_paren_balance: bool,
    ) -> ParseResult<usize> {
        loop {
            p = self.skip_optional_whitespace_bytes(p);
            if p >= self.limit || self.buf.as_bytes()[p] != b'%' {
                return Ok(p);
            }
            p = self.splice_pe_reference_at_bytes(p, pending, check_paren_balance)?;
            if p >= self.limit {
                return Ok(p);
            }
        }
    }

    // ===== Attribute defaults =====

    fn apply_attribute_defaults(&mut self, element_name: &str) -> ParseResult<()> {
        let declared_list = match self.dtd_model.get_attributes(element_name) {
            None => return Ok(()),
            Some(d) => d,
        };
        // Common case: every declared attribute was explicitly specified,
        // so there's nothing to default and no REQUIRED-but-absent check
        // to run. Cloning the declared list (String/AttDef allocations) is
        // wasted work on every element in that case — skip it.
        if declared_list.iter().all(|(name, _)| self.was_attribute_seen(name)) {
            return Ok(());
        }
        let declared: Vec<(String, crate::dtd::AttDef)> = declared_list.clone();
        for (name, def) in declared {
            if self.was_attribute_seen(&name) {
                continue;
            }
            if self.validation_enabled && def.mode == Mode::Required {
                let msg = format!(
                    "Validity Constraint: Required Attribute (Section 3.3.2). Attribute \"{name}\" is required on element \"{element_name}\" but was not specified."
                );
                self.handler.error(&msg)?;
            }
            let default_value = match &def.default_value {
                None => continue,
                Some(v) => v.clone(),
            };
            if self.validation_enabled && self.standalone && def.declared_externally {
                let msg = format!(
                    "Validity Constraint: Standalone Document Declaration (Section 2.9). Document has standalone=\"yes\" but attribute \"{name}\" of element \"{element_name}\" has a default value declared in external markup, and was not specified."
                );
                self.handler.error(&msg)?;
            }
            self.handler.start_attribute(&name, &def.attr_type, true, false)?;
            self.handler.attribute_value_content(&default_value, true)?;
        }
        Ok(())
    }

    // ===== Runtime attribute VC checks =====

    fn check_attribute_value_vcs(
        &mut self,
        element_name: &str,
        attr_name: &str,
        ty: &str,
        value: &str,
    ) -> ParseResult<()> {
        match ty {
            "ID" => {
                self.check_name_production(attr_name, value, "ID")?;
                self.check_no_colon(attr_name, value, "ID")?;
                if self.declared_ids.is_none() {
                    self.declared_ids = Some(HashSet::new());
                }
                if !self.declared_ids.as_mut().unwrap().insert(value.to_string()) {
                    let msg = format!(
                        "Validity Constraint: ID (Section 3.3.1). ID value \"{value}\" appears more than once in the document."
                    );
                    self.handler.error(&msg)?;
                }
            }
            "IDREF" => {
                self.check_name_production(attr_name, value, "IDREF")?;
                self.check_no_colon(attr_name, value, "IDREF")?;
                self.record_pending_idref(value.to_string());
            }
            "IDREFS" => {
                let tokens = split_tokens(value);
                if tokens.is_empty() {
                    self.report_bad_attribute_value_format(attr_name, value, "IDREFS", "IDREFS")?;
                }
                for token in tokens {
                    self.check_name_production(attr_name, &token, "IDREFS")?;
                    self.check_no_colon(attr_name, &token, "IDREFS")?;
                    self.record_pending_idref(token);
                }
            }
            "NMTOKEN" => self.check_nmtoken_production(attr_name, value, "NMTOKEN")?,
            "NMTOKENS" => {
                let tokens = split_tokens(value);
                if tokens.is_empty() {
                    self.report_bad_attribute_value_format(attr_name, value, "NMTOKENS", "NMTOKENS")?;
                }
                for token in tokens {
                    self.check_nmtoken_production(attr_name, &token, "NMTOKENS")?;
                }
            }
            "ENUMERATION" | "NOTATION" => {
                self.check_enumeration_membership(element_name, attr_name, ty, value)?
            }
            "ENTITY" => {
                self.check_name_production(attr_name, value, "ENTITY")?;
                self.check_unparsed_entity_name(attr_name, value)?;
            }
            "ENTITIES" => {
                for token in split_tokens(value) {
                    self.check_name_production(attr_name, &token, "ENTITIES")?;
                    self.check_unparsed_entity_name(attr_name, &token)?;
                }
            }
            _ => {}
        }
        self.check_fixed_value(element_name, attr_name, value)?;
        Ok(())
    }

    fn check_unparsed_entity_name(&mut self, attr_name: &str, value: &str) -> ParseResult<()> {
        let ok = self
            .external_entity_names
            .get(value)
            .map(|ids| ids.ndata.is_some())
            .unwrap_or(false);
        if !ok {
            let msg = format!(
                "Validity Constraint: Entity Name (Section 3.3.1). Value \"{value}\" of attribute \"{attr_name}\" does not name a declared unparsed entity."
            );
            self.handler.error(&msg)?;
        }
        Ok(())
    }

    fn record_pending_idref(&mut self, value: String) {
        if self.pending_idrefs.is_none() {
            self.pending_idrefs = Some(Vec::new());
        }
        self.pending_idrefs.as_mut().unwrap().push(value);
    }

    fn check_name_production(&mut self, attr_name: &str, value: &str, type_label: &str) -> ParseResult<()> {
        if !matches_name_production(value) {
            self.report_bad_attribute_value_format(attr_name, value, type_label, "Name")?;
        }
        Ok(())
    }

    fn check_nmtoken_production(
        &mut self,
        attr_name: &str,
        value: &str,
        type_label: &str,
    ) -> ParseResult<()> {
        if !matches_nmtoken_production(value) {
            self.report_bad_attribute_value_format(attr_name, value, type_label, "Nmtoken")?;
        }
        Ok(())
    }

    fn check_no_colon(&mut self, attr_name: &str, value: &str, type_label: &str) -> ParseResult<()> {
        if value.contains(':') {
            let msg = format!(
                "Validity Constraint: {type_label} Attribute (Section 3.3.1). Value \"{value}\" of attribute \"{attr_name}\" must not contain a colon (Namespaces in XML)."
            );
            self.handler.error(&msg)?;
        }
        Ok(())
    }

    fn check_no_colon_in_namespace_mode(&mut self, name: &str, what: &str) -> ParseResult<()> {
        if self.namespace_aware && name.contains(':') {
            let msg = format!("WFC (Namespaces in XML): {what} name \"{name}\" must not contain a colon");
            return Err(self.fatal(&msg));
        }
        Ok(())
    }

    fn report_bad_attribute_value_format(
        &mut self,
        attr_name: &str,
        value: &str,
        type_label: &str,
        production: &str,
    ) -> ParseResult<()> {
        let msg = format!(
            "Validity Constraint: Attribute Value Type (Section 3.3.1). Value \"{value}\" of {type_label} attribute \"{attr_name}\" does not match the {production} production."
        );
        self.handler.error(&msg)
    }

    fn check_enumeration_membership(
        &mut self,
        element_name: &str,
        attr_name: &str,
        ty: &str,
        value: &str,
    ) -> ParseResult<()> {
        let ok = match self.dtd_model.get_att_def(element_name, attr_name) {
            None => true,
            Some(def) => match &def.enumeration {
                None => true,
                Some(en) => en.iter().any(|v| v == value),
            },
        };
        if ok {
            return Ok(());
        }
        let label = if ty == "NOTATION" {
            "Notation Attributes"
        } else {
            "Enumeration"
        };
        let msg = format!(
            "Validity Constraint: {label} (Section 3.3.1). Value \"{value}\" of attribute \"{attr_name}\" is not one of the declared values for element \"{element_name}\"."
        );
        self.handler.error(&msg)
    }

    fn check_attlist_defaults_legal(&mut self) -> ParseResult<()> {
        let snapshot = self.dtd_model.attlists_snapshot();
        for (element_name, attr_name, def) in snapshot {
            if def.default_value.is_none() {
                continue;
            }
            self.check_attribute_default_legal(&element_name, &attr_name, &def)?;
        }
        Ok(())
    }

    fn check_attribute_default_legal(
        &mut self,
        _element_name: &str,
        attr_name: &str,
        def: &crate::dtd::AttDef,
    ) -> ParseResult<()> {
        let value = def.default_value.as_deref().unwrap_or("");
        match def.attr_type.as_str() {
            "IDREF" | "ENTITY" => {
                if !matches_name_production(value) {
                    self.report_bad_default_format(attr_name, value, "Name")?;
                }
            }
            "IDREFS" | "ENTITIES" => {
                for token in split_tokens(value) {
                    if !matches_name_production(&token) {
                        self.report_bad_default_format(attr_name, value, "Names")?;
                    }
                }
            }
            "NMTOKEN" => {
                if !matches_nmtoken_production(value) {
                    self.report_bad_default_format(attr_name, value, "Nmtoken")?;
                }
            }
            "NMTOKENS" => {
                for token in split_tokens(value) {
                    if !matches_nmtoken_production(&token) {
                        self.report_bad_default_format(attr_name, value, "Nmtokens")?;
                    }
                }
            }
            "ENUMERATION" | "NOTATION" => {
                if let Some(en) = &def.enumeration {
                    if !en.iter().any(|v| v == value) {
                        let msg = format!(
                            "Validity Constraint: Attribute Default Legal (Section 3.3.2). Default value \"{value}\" of attribute \"{attr_name}\" is not one of its declared enumerated values."
                        );
                        self.handler.error(&msg)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn report_bad_default_format(
        &mut self,
        attr_name: &str,
        value: &str,
        production: &str,
    ) -> ParseResult<()> {
        let msg = format!(
            "Validity Constraint: Attribute Default Legal (Section 3.3.2). Default value \"{value}\" of attribute \"{attr_name}\" does not match the {production} production."
        );
        self.handler.error(&msg)
    }

    fn check_fixed_value(
        &mut self,
        element_name: &str,
        attr_name: &str,
        value: &str,
    ) -> ParseResult<()> {
        let fixed = self
            .dtd_model
            .get_att_def(element_name, attr_name)
            .filter(|d| d.mode == Mode::Fixed)
            .map(|d| d.default_value.clone().unwrap_or_default());
        if let Some(expected) = fixed {
            if value != expected {
                let msg = format!(
                    "Validity Constraint: Fixed Attribute Default (Section 3.3.2). Value \"{value}\" of attribute \"{attr_name}\" does not match its declared #FIXED value \"{expected}\"."
                );
                self.handler.error(&msg)?;
            }
        }
        Ok(())
    }

    fn check_pending_idrefs(&mut self) -> ParseResult<()> {
        let pending = match self.pending_idrefs.take() {
            None => return Ok(()),
            Some(p) => p,
        };
        for value in &pending {
            let ok = self
                .declared_ids
                .as_ref()
                .map(|ids| ids.contains(value))
                .unwrap_or(false);
            if !ok {
                let msg = format!(
                    "Validity Constraint: IDREF (Section 3.3.1). IDREF value \"{value}\" does not match the value of any ID attribute in the document."
                );
                self.handler.error(&msg)?;
            }
        }
        Ok(())
    }
}

// ===== Free helper functions =====

fn format_attribute_decl_type(ty: &str, enumeration: Option<&Vec<String>>) -> String {
    match enumeration {
        None => ty.to_string(),
        Some(en) if en.is_empty() => ty.to_string(),
        Some(en) => {
            let mut sb = String::new();
            if ty == "NOTATION" {
                sb.push_str("NOTATION ");
            }
            sb.push('(');
            for (i, v) in en.iter().enumerate() {
                if i > 0 {
                    sb.push('|');
                }
                sb.push_str(v);
            }
            sb.push(')');
            sb
        }
    }
}

fn format_attribute_decl_mode(mode: Mode) -> Option<&'static str> {
    match mode {
        Mode::Required => Some("#REQUIRED"),
        Mode::Implied => Some("#IMPLIED"),
        Mode::Fixed => Some("#FIXED"),
        Mode::None => None,
    }
}

fn protocol_allowed(system_id: &str, access: &str) -> bool {
    let access = access.trim();
    if access.is_empty() {
        return false;
    }
    if access.eq_ignore_ascii_case("all") {
        return true;
    }
    let protocol = system_id.split_once(':').map(|(p, _)| p).unwrap_or("file");
    access
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case(protocol))
}

/// Reads a resolved system identifier (a `file:` URI or a plain path) as bytes.
fn read_system_id(resolved: &str) -> std::io::Result<Vec<u8>> {
    let path = if let Some(rest) = resolved.strip_prefix("file:") {
        if let Some(stripped) = rest.strip_prefix("///") {
            format!("/{stripped}")
        } else if let Some(stripped) = rest.strip_prefix("//localhost/") {
            format!("/{stripped}")
        } else {
            rest.trim_start_matches("//").to_string()
        }
    } else {
        resolved.to_string()
    };
    std::fs::read(&path)
}

/// Exploratory (explore/utf8-byte-path): correctness tests for the
/// byte-native content-run scanner, checked directly against real
/// `Scanner` state — not a standalone reimplementation like the earlier
/// scratchpad microbenchmark — and, where it matters, against the
/// existing char-based path on identical input.
#[cfg(test)]
mod byte_path_tests {
    use super::*;
    use std::cell::RefCell;

    use crate::features::FeatureSet;
    use crate::handler::DefaultHandler;

    fn make_scanner(handler: &mut dyn XmlHandler, xml11: bool) -> Scanner<'_> {
        let features = FeatureSet::default();
        let settings = features.scanner_settings();
        Scanner::new(handler, xml11, None, None, None, false, true, settings, false).unwrap()
    }

    #[test]
    fn ascii_stops_at_lt() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"hello<world");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
        assert_eq!(s.pos, 5);
    }

    #[test]
    fn ascii_stops_at_amp() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a & b");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
        assert_eq!(s.pos, 2);
    }

    #[test]
    fn no_stop_byte_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"hello world");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::NeedMore);
        assert_eq!(s.pos, s.limit);
    }

    #[test]
    fn cdata_end_marker_outside_cdata_is_illegal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"]]>");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Illegal);
    }

    #[test]
    fn single_bracket_is_not_illegal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a]b>c<");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
        assert_eq!(s.pos, 5);
    }

    #[test]
    fn bare_control_char_is_illegal_in_xml10() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"ok\x01more");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Illegal);
    }

    #[test]
    fn restricted_char_allowed_when_flagged_in_xml11() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, true);
        s.switch_to_bytes_mode();
        s.allow_restricted_char_in_content = true;
        s.append_bytes(b"ok\x01more<");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
    }

    #[test]
    fn restricted_char_illegal_in_xml11_when_not_flagged() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, true);
        s.switch_to_bytes_mode();
        s.append_bytes(b"ok\x01more");
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Illegal);
    }

    #[test]
    fn multibyte_sequence_passes_through_as_legal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes("café<x".as_bytes());
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "café");
    }

    #[test]
    fn multibyte_sequence_split_across_receive_calls() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        let full = "café<x";
        let bytes = full.as_bytes();
        // Split right after the lead byte of 'é' (0xC3 0xA9), before its
        // continuation byte arrives — a chunk boundary can legitimately
        // land here.
        let split_at = bytes.iter().position(|&b| b == 0xC3).unwrap() + 1;

        s.append_bytes(&bytes[..split_at]);
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::NeedMore);

        s.append_bytes(&bytes[split_at..]);
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Stop);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "é");
    }

    #[test]
    fn ill_formed_utf8_is_illegal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        // 0xC3 followed by an ASCII byte is not a valid continuation.
        s.append_bytes(&[b'o', b'k', 0xC3, b'x']);
        assert_eq!(s.scan_content_run_bytes(), ContentRunBytes::Illegal);
    }

    /// Parity check against the existing, fully-tested char path: same
    /// input, same outcome, same consumed text — compared as text (not
    /// raw position numbers, since those are in different units on the
    /// two paths) so the comparison doesn't depend on either
    /// representation's internal bookkeeping.
    #[test]
    fn matches_char_path_on_mixed_content() {
        let text = "héllo wörld<tag";

        let mut app_b = DefaultHandler;
        let mut sb = make_scanner(&mut app_b, false);
        sb.switch_to_bytes_mode();
        sb.append_bytes(text.as_bytes());
        assert_eq!(sb.scan_content_run_bytes(), ContentRunBytes::Stop);
        let consumed_bytes = std::str::from_utf8(&sb.buf.as_bytes()[..sb.pos]).unwrap();

        let mut app_c = DefaultHandler;
        let mut sc = make_scanner(&mut app_c, false);
        sc.append(text);
        assert!(sc.scan_content_run_fast().is_ok());
        let consumed_chars: String = sc.buf.as_chars()[..sc.pos].iter().collect();

        assert_eq!(consumed_bytes, consumed_chars);
        assert_eq!(consumed_bytes, "héllo wörld");
    }

    #[test]
    fn attr_value_stops_at_quote() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"value\"rest");
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Quote);
        assert_eq!(s.pos, 5);
    }

    #[test]
    fn attr_value_stops_at_amp() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a&amp;b\"");
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Amp);
        assert_eq!(s.pos, 1);
    }

    #[test]
    fn attr_value_lt_is_illegal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a<b\"");
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Illegal);
    }

    #[test]
    fn attr_value_no_stop_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"just text");
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::NeedMore);
    }

    #[test]
    fn attr_value_normalizes_tab_newline_cr_to_space_in_place() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a\tb\nc\rd\"");
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Quote);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "a b c d");
    }

    #[test]
    fn attr_value_different_quote_char_passes_through() {
        // Single-quoted attribute: double quote is ordinary content.
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"say \"hi\"'rest");
        assert_eq!(s.scan_attr_value_run_bytes(b'\''), AttrValueRunBytes::Quote);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "say \"hi\"");
    }

    #[test]
    fn attr_value_multibyte_passes_through() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes("café\"".as_bytes());
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Quote);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "café");
    }

    #[test]
    fn attr_value_multibyte_split_across_receive_calls() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        let full = "café\"";
        let bytes = full.as_bytes();
        let split_at = bytes.iter().position(|&b| b == 0xC3).unwrap() + 1;

        s.append_bytes(&bytes[..split_at]);
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::NeedMore);

        s.append_bytes(&bytes[split_at..]);
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Quote);
        let consumed = std::str::from_utf8(&s.buf.as_bytes()[..s.pos]).unwrap();
        assert_eq!(consumed, "é");
    }

    #[test]
    fn attr_value_ill_formed_utf8_is_illegal() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(&[b'o', b'k', 0xC3, b'x']);
        assert_eq!(s.scan_attr_value_run_bytes(b'"'), AttrValueRunBytes::Illegal);
    }

    /// Parity check against `is_attr_stop`, char by char, on mixed
    /// content — the byte scanner should stop at exactly the same
    /// logical position `is_attr_stop` would call a stop, for both the
    /// quote-terminated and the ampersand-terminated cases.
    #[test]
    fn attr_value_matches_is_attr_stop_char_by_char() {
        let text = "héllo\"wörld&x\"";
        let quote = '"';

        let mut app_c = DefaultHandler;
        let sc = make_scanner(&mut app_c, false);
        let mut char_pos = None;
        for (i, c) in text.chars().enumerate() {
            if sc.is_attr_stop(c, quote) {
                char_pos = Some(i);
                break;
            }
        }
        let stop_char = text.chars().nth(char_pos.unwrap()).unwrap();

        let mut app_b = DefaultHandler;
        let mut sb = make_scanner(&mut app_b, false);
        sb.switch_to_bytes_mode();
        sb.append_bytes(text.as_bytes());
        let result = sb.scan_attr_value_run_bytes(quote as u8);
        let consumed = std::str::from_utf8(&sb.buf.as_bytes()[..sb.pos]).unwrap();

        let expected_consumed: String = text.chars().take(char_pos.unwrap()).collect();
        assert_eq!(consumed, expected_consumed);
        match stop_char {
            '"' => assert_eq!(result, AttrValueRunBytes::Quote),
            '&' => assert_eq!(result, AttrValueRunBytes::Amp),
            _ => panic!("unexpected stop char {stop_char:?}"),
        }
    }

    /// Records `attribute_value_content` calls exactly as the real
    /// handler would see them, to prove `scan_attribute_value_streaming_bytes`
    /// drives the genuine, unmodified handler-facing layer correctly —
    /// not a byte-native stand-in for it. Shares its call log via
    /// `Rc<RefCell<..>>` rather than owning it directly, since the
    /// `Scanner` under test holds `&mut` the handler for its whole
    /// lifetime and tests need to inspect calls while `s` is still alive
    /// (between chunks, mid-scan).
    #[derive(Default, Clone)]
    struct RecordingHandler {
        calls: Rc<RefCell<Vec<(String, bool)>>>,
    }

    impl XmlHandler for RecordingHandler {
        fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
            self.calls.borrow_mut().push((value.to_string(), end));
            Ok(())
        }
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_emits_to_real_handler() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"hello\"rest");
        let result = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(result, AttrValueScanBytes::Done);
        assert_eq!(*calls.borrow(), vec![("hello".to_string(), true)]);
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_emits_multibyte_content() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes("café\"".as_bytes());
        let result = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(result, AttrValueScanBytes::Done);
        assert_eq!(*calls.borrow(), vec![("café".to_string(), true)]);
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_emits_partial_then_final_chunk() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"partial");
        let r1 = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(r1, AttrValueScanBytes::NeedMore);
        assert_eq!(*calls.borrow(), vec![("partial".to_string(), false)]);

        s.append_bytes(b" rest\"tail");
        let r2 = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(r2, AttrValueScanBytes::Done);
        assert_eq!(
            *calls.borrow(),
            vec![
                ("partial".to_string(), false),
                (" rest".to_string(), true),
            ]
        );
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_resolves_predefined_entity() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"pre&amp;post\"");
        let result = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(result, AttrValueScanBytes::Done);
        assert_eq!(
            *calls.borrow(),
            vec![
                ("pre".to_string(), false),
                ("&".to_string(), false),
                ("post".to_string(), true),
            ]
        );
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_resolves_general_entity() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.general_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"pre&foo;post\"");
        let result = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(result, AttrValueScanBytes::Done);
        assert_eq!(
            *calls.borrow(),
            vec![
                ("pre".to_string(), false),
                ("bar".to_string(), false),
                ("post".to_string(), true),
            ]
        );
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_undeclared_entity_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"pre&undeclared;post\"");
        assert!(s.scan_attribute_value_streaming_bytes(b'"').is_err());
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_needs_more_mid_entity_name() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.general_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"pre&fo");
        let r1 = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(r1, AttrValueScanBytes::NeedMore);
        assert_eq!(*calls.borrow(), vec![("pre".to_string(), false)]);

        s.append_bytes(b"o;post\"");
        let r2 = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(r2, AttrValueScanBytes::Done);
        assert_eq!(
            *calls.borrow(),
            vec![
                ("pre".to_string(), false),
                ("bar".to_string(), false),
                ("post".to_string(), true),
            ]
        );
    }

    #[test]
    fn scan_attribute_value_streaming_bytes_normalizes_whitespace() {
        let mut app = RecordingHandler::default();
        let calls = Rc::clone(&app.calls);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"a\tb\nc\"");
        let result = s.scan_attribute_value_streaming_bytes(b'"').unwrap();
        assert_eq!(result, AttrValueScanBytes::Done);
        assert_eq!(*calls.borrow(), vec![("a b c".to_string(), true)]);
    }

    // ===== decode_entity_ref_bytes =====

    #[test]
    fn decimal_char_ref() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#65;rest");
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::Decoded("A".to_string()));
        assert_eq!(s.pos, 5);
    }

    #[test]
    fn hex_char_ref() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#x41;rest");
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::Decoded("A".to_string()));
        assert_eq!(s.pos, 6);
    }

    #[test]
    fn predefined_named_entities() {
        for (input, expected) in [
            (&b"&amp;"[..], "&"),
            (&b"&lt;"[..], "<"),
            (&b"&gt;"[..], ">"),
            (&b"&apos;"[..], "'"),
            (&b"&quot;"[..], "\""),
        ] {
            let mut app = DefaultHandler;
            let mut s = make_scanner(&mut app, false);
            s.switch_to_bytes_mode();
            s.append_bytes(input);
            let result = s.decode_entity_ref_bytes().unwrap();
            assert_eq!(result, RefResult::Decoded(expected.to_string()));
            assert_eq!(s.pos, input.len());
        }
    }

    #[test]
    fn general_named_entity() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&myentity;rest");
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::General("myentity".to_string()));
        assert_eq!(s.pos, 10);
    }

    #[test]
    fn general_named_entity_with_multibyte_name_char() {
        // Combining characters and other non-ASCII NameChars are legal
        // inside an XML Name after the first character; exercise the
        // multi-byte decode-on-demand path in the name-scanning loop.
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        let input = "&café;rest".as_bytes();
        s.append_bytes(input);
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::General("café".to_string()));
        assert_eq!(s.pos, "&café;".len());
    }

    #[test]
    fn empty_char_ref_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#;rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn invalid_decimal_digit_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#6z;rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn invalid_hex_digit_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#xzz;rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn out_of_range_char_ref_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#xFFFFFFFF;rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn bad_name_start_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&1bad;rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn missing_terminating_semicolon_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&amp rest");
        assert!(s.decode_entity_ref_bytes().is_err());
    }

    #[test]
    fn truncated_numeric_ref_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#65");
        assert_eq!(s.decode_entity_ref_bytes().unwrap(), RefResult::NeedMore);

        s.append_bytes(b";rest");
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::Decoded("A".to_string()));
    }

    #[test]
    fn truncated_named_ref_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&am");
        assert_eq!(s.decode_entity_ref_bytes().unwrap(), RefResult::NeedMore);

        s.append_bytes(b"p;rest");
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::Decoded("&".to_string()));
    }

    #[test]
    fn named_ref_split_mid_multibyte_char_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        let full = "&café;rest".as_bytes();
        // Split right after the lead byte of 'é' (0xC3 0xA9), before its
        // continuation byte arrives.
        let split_at = full.iter().position(|&b| b == 0xC3).unwrap() + 1;

        s.append_bytes(&full[..split_at]);
        assert_eq!(s.decode_entity_ref_bytes().unwrap(), RefResult::NeedMore);

        s.append_bytes(&full[split_at..]);
        let result = s.decode_entity_ref_bytes().unwrap();
        assert_eq!(result, RefResult::General("café".to_string()));
    }

    #[test]
    fn matches_char_path_on_identical_input() {
        let cases: &[&[u8]] = &[
            b"&#65;",
            b"&#x41;",
            b"&amp;",
            b"&lt;",
            b"&myentity;",
        ];
        for input in cases {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input);
            let byte_result = sb.decode_entity_ref_bytes().unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            let text: String = input.iter().map(|&b| b as char).collect();
            sc.append(&text);
            let char_result = sc.decode_entity_ref().unwrap();

            assert_eq!(byte_result, char_result);
            assert_eq!(sb.pos, sc.pos);
        }
    }

    // ===== scan_start_tag_bytes / scan_attributes_and_tag_end_bytes =====

    /// Records element/attribute events as formatted strings, to prove
    /// `scan_start_tag_bytes`/`scan_attributes_and_tag_end_bytes` drive the
    /// genuine, unmodified handler-facing layer -- same rationale as
    /// `RecordingHandler` above, just covering the wider event vocabulary
    /// these two functions touch.
    #[derive(Default, Clone)]
    struct TagRecordingHandler {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl XmlHandler for TagRecordingHandler {
        fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("start_element({q_name})"));
            Ok(())
        }
        fn start_attribute(
            &mut self,
            name: &str,
            ty: &str,
            declared: bool,
            specified: bool,
        ) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("start_attribute({name},{ty},{declared},{specified})"));
            Ok(())
        }
        fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("attr_value({value:?},{end})"));
            Ok(())
        }
        fn end_attributes(&mut self) -> ParseResult<()> {
            self.events.borrow_mut().push("end_attributes".to_string());
            Ok(())
        }
        fn end_element(&mut self) -> ParseResult<()> {
            self.events.borrow_mut().push("end_element".to_string());
            Ok(())
        }
        fn start_comment(&mut self) -> ParseResult<()> {
            self.events.borrow_mut().push("start_comment".to_string());
            Ok(())
        }
        fn comment_data(&mut self, text: &str, end: bool) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("comment_data({text:?},{end})"));
            Ok(())
        }
        fn start_cdata(&mut self) -> ParseResult<()> {
            self.events.borrow_mut().push("start_cdata".to_string());
            Ok(())
        }
        fn characters(&mut self, text: &str, ignorable: bool, end: bool) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("characters({text:?},{ignorable},{end})"));
            Ok(())
        }
        fn end_cdata(&mut self) -> ParseResult<()> {
            self.events.borrow_mut().push("end_cdata".to_string());
            Ok(())
        }
        fn pi_target(&mut self, target: &str) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("pi_target({target})"));
            Ok(())
        }
        fn pi_data(&mut self, data: &str, end: bool) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("pi_data({data:?},{end})"));
            Ok(())
        }
        fn start_entity(&mut self, name: &str) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("start_entity({name})"));
            Ok(())
        }
        fn end_entity(&mut self, name: &str) -> ParseResult<()> {
            self.events
                .borrow_mut()
                .push(format!("end_entity({name})"));
            Ok(())
        }
    }

    #[test]
    fn scan_start_tag_bytes_self_closing_no_attributes() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<foo/>");
        assert!(s.scan_start_tag_bytes(0).unwrap());
        assert!(s.scan_attributes_and_tag_end_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_element(foo)".to_string(),
                "end_attributes".to_string(),
                "end_element".to_string(),
            ]
        );
    }

    #[test]
    fn scan_start_tag_bytes_with_attributes_not_self_closing() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<foo a=\"1\" b='2'>");
        assert!(s.scan_start_tag_bytes(0).unwrap());
        assert!(s.scan_attributes_and_tag_end_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_element(foo)".to_string(),
                "start_attribute(a,CDATA,false,true)".to_string(),
                "attr_value(\"1\",true)".to_string(),
                "start_attribute(b,CDATA,false,true)".to_string(),
                "attr_value(\"2\",true)".to_string(),
                "end_attributes".to_string(),
            ]
        );
    }

    #[test]
    fn scan_attributes_and_tag_end_bytes_resolves_entity_in_value() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<foo a=\"x&amp;y\">");
        assert!(s.scan_start_tag_bytes(0).unwrap());
        assert!(s.scan_attributes_and_tag_end_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_element(foo)".to_string(),
                "start_attribute(a,CDATA,false,true)".to_string(),
                "attr_value(\"x\",false)".to_string(),
                "attr_value(\"&\",false)".to_string(),
                "attr_value(\"y\",true)".to_string(),
                "end_attributes".to_string(),
            ]
        );
    }

    #[test]
    fn scan_start_tag_bytes_split_across_receive_calls() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<fo");
        assert!(!s.scan_start_tag_bytes(0).unwrap());
        assert_eq!(s.pos, 0);

        s.append_bytes(b"o/>");
        assert!(s.scan_start_tag_bytes(0).unwrap());
        assert!(s.scan_attributes_and_tag_end_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_element(foo)".to_string(),
                "end_attributes".to_string(),
                "end_element".to_string(),
            ]
        );
    }

    #[test]
    fn scan_start_tag_bytes_bad_name_start_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<1abc>");
        assert!(s.scan_start_tag_bytes(0).is_err());
    }

    #[test]
    fn scan_attributes_and_tag_end_bytes_duplicate_attribute_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<foo a=\"1\" a=\"2\">");
        assert!(s.scan_start_tag_bytes(0).unwrap());
        assert!(s.scan_attributes_and_tag_end_bytes().is_err());
    }

    #[test]
    fn tag_scanning_matches_char_path_on_identical_input() {
        let inputs: &[&str] = &["<foo/>", "<foo a=\"1\" b='2'>", "<foo a=\"x&amp;y\">"];
        for input in inputs {
            let mut app_bytes = TagRecordingHandler::default();
            let bytes_events = Rc::clone(&app_bytes.events);
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let start_ok = sb.scan_start_tag_bytes(0).unwrap();
            assert!(start_ok);
            sb.scan_attributes_and_tag_end_bytes().unwrap();

            let mut app_chars = TagRecordingHandler::default();
            let char_events = Rc::clone(&app_chars.events);
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            assert!(sc.scan_start_tag(0).unwrap());
            sc.scan_attributes_and_tag_end().unwrap();

            assert_eq!(*bytes_events.borrow(), *char_events.borrow());
        }
    }

    // ===== scan_end_tag_bytes =====

    #[test]
    fn scan_end_tag_bytes_fast_path_match() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("foo"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"</foo>rest");
        assert!(s.scan_end_tag_bytes(0).unwrap());
        assert_eq!(s.pos, 6);
        assert!(s.element_stack.is_empty());
        assert_eq!(*events.borrow(), vec!["end_element".to_string()]);
    }

    #[test]
    fn scan_end_tag_bytes_general_path_with_whitespace() {
        let mut app = TagRecordingHandler::default();
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("foo"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"</foo  >rest");
        assert!(s.scan_end_tag_bytes(0).unwrap());
        assert_eq!(s.pos, 8);
        assert!(s.element_stack.is_empty());
    }

    #[test]
    fn scan_end_tag_bytes_split_across_receive_calls() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("foo"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"</fo");
        assert!(!s.scan_end_tag_bytes(0).unwrap());
        assert_eq!(s.pos, 0);

        s.append_bytes(b"o>");
        assert!(s.scan_end_tag_bytes(0).unwrap());
        assert!(s.element_stack.is_empty());
    }

    #[test]
    fn scan_end_tag_bytes_mismatched_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("foo"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"</bar>");
        assert!(s.scan_end_tag_bytes(0).is_err());
    }

    #[test]
    fn scan_end_tag_bytes_no_matching_start_tag_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"</foo>");
        assert!(s.scan_end_tag_bytes(0).is_err());
    }

    #[test]
    fn scan_end_tag_bytes_bad_name_start_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        // Push a different name so the fast path (which trusts a literal
        // match without checking NameStartChar, same as the char path)
        // doesn't short-circuit before the general path's validation runs.
        s.element_stack.push(Rc::from("foo"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"</1bad>");
        assert!(s.scan_end_tag_bytes(0).is_err());
    }

    #[test]
    fn end_tag_scanning_matches_char_path_on_identical_input() {
        for input in ["</foo>", "</foo  >"] {
            let mut app_bytes = TagRecordingHandler::default();
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.element_stack.push(Rc::from("foo"));
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let byte_ok = sb.scan_end_tag_bytes(0).unwrap();

            let mut app_chars = TagRecordingHandler::default();
            let mut sc = make_scanner(&mut app_chars, false);
            sc.element_stack.push(Rc::from("foo"));
            sc.append(input);
            let char_ok = sc.scan_end_tag(0).unwrap();

            assert_eq!(byte_ok, char_ok);
            assert_eq!(sb.pos, sc.pos);
        }
    }

    // ===== scan_comment_bytes =====

    #[test]
    fn scan_comment_bytes_full_comment() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!--hello-->rest");
        assert!(s.scan_comment_bytes(0).unwrap());
        assert_eq!(s.pos, 12);
        assert_eq!(
            *events.borrow(),
            vec![
                "start_comment".to_string(),
                "comment_data(\"hello\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn scan_comment_bytes_needs_more() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!--hel");
        assert!(!s.scan_comment_bytes(0).unwrap());

        s.append_bytes(b"lo-->rest");
        assert!(s.scan_comment_data_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_comment".to_string(),
                "comment_data(\"hel\",false)".to_string(),
                "comment_data(\"lo\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn scan_comment_bytes_double_dash_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!--a--b-->");
        assert!(s.scan_comment_bytes(0).is_err());
    }

    #[test]
    fn scan_comment_bytes_illegal_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!--a\x01b-->");
        assert!(s.scan_comment_bytes(0).is_err());
    }

    #[test]
    fn scan_comment_bytes_malformed_declaration_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!-x-->");
        assert!(s.scan_comment_bytes(0).is_err());
    }

    #[test]
    fn scan_comment_bytes_multibyte_content() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes("<!--café-->rest".as_bytes());
        assert!(s.scan_comment_bytes(0).unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_comment".to_string(),
                "comment_data(\"café\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn comment_scanning_matches_char_path() {
        let mut app_bytes = TagRecordingHandler::default();
        let bytes_events = Rc::clone(&app_bytes.events);
        let mut sb = make_scanner(&mut app_bytes, false);
        sb.switch_to_bytes_mode();
        sb.append_bytes(b"<!--hello-->rest");
        sb.scan_comment_bytes(0).unwrap();

        let mut app_chars = TagRecordingHandler::default();
        let char_events = Rc::clone(&app_chars.events);
        let mut sc = make_scanner(&mut app_chars, false);
        sc.append("<!--hello-->rest");
        sc.scan_comment(0).unwrap();

        assert_eq!(*bytes_events.borrow(), *char_events.borrow());
        assert_eq!(sb.pos, sc.pos);
    }

    // ===== scan_cdata_bytes =====

    #[test]
    fn scan_cdata_bytes_full_section() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("root"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"<![CDATA[hi]]>rest");
        assert!(s.scan_cdata_bytes(0).unwrap());
        assert_eq!(s.pos, 14);
        assert_eq!(
            *events.borrow(),
            vec![
                "start_cdata".to_string(),
                "characters(\"hi\",false,true)".to_string(),
                "end_cdata".to_string(),
            ]
        );
    }

    #[test]
    fn scan_cdata_bytes_outside_element_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<![CDATA[hi]]>rest");
        assert!(s.scan_cdata_bytes(0).is_err());
    }

    #[test]
    fn scan_cdata_bytes_needs_more_mid_marker() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("root"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"<![CDA");
        assert!(!s.scan_cdata_bytes(0).unwrap());
        assert_eq!(s.pos, 0);

        s.append_bytes(b"TA[hi]]>rest");
        assert!(s.scan_cdata_bytes(0).unwrap());
    }

    #[test]
    fn scan_cdata_bytes_needs_more_mid_content() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("root"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"<![CDATA[hi");
        assert!(!s.scan_cdata_bytes(0).unwrap());

        s.append_bytes(b"]]>rest");
        assert!(s.scan_cdata_content_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_cdata".to_string(),
                "characters(\"hi\",false,false)".to_string(),
                "characters(\"\",false,true)".to_string(),
                "end_cdata".to_string(),
            ]
        );
    }

    #[test]
    fn scan_cdata_bytes_single_bracket_is_not_end_marker() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.element_stack.push(Rc::from("root"));
        s.switch_to_bytes_mode();
        s.append_bytes(b"<![CDATA[a]b]]>rest");
        assert!(s.scan_cdata_bytes(0).unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "start_cdata".to_string(),
                "characters(\"a]b\",false,true)".to_string(),
                "end_cdata".to_string(),
            ]
        );
    }

    #[test]
    fn cdata_scanning_matches_char_path() {
        let mut app_bytes = TagRecordingHandler::default();
        let bytes_events = Rc::clone(&app_bytes.events);
        let mut sb = make_scanner(&mut app_bytes, false);
        sb.element_stack.push(Rc::from("root"));
        sb.switch_to_bytes_mode();
        sb.append_bytes(b"<![CDATA[a]b]]>rest");
        sb.scan_cdata_bytes(0).unwrap();

        let mut app_chars = TagRecordingHandler::default();
        let char_events = Rc::clone(&app_chars.events);
        let mut sc = make_scanner(&mut app_chars, false);
        sc.element_stack.push(Rc::from("root"));
        sc.append("<![CDATA[a]b]]>rest");
        sc.scan_cdata(0).unwrap();

        assert_eq!(*bytes_events.borrow(), *char_events.borrow());
        assert_eq!(sb.pos, sc.pos);
    }

    // ===== scan_pi_bytes =====

    #[test]
    fn scan_pi_bytes_full_pi_with_data() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<?foo bar?>rest");
        assert!(s.scan_pi_bytes(0).unwrap());
        assert_eq!(s.pos, 11);
        assert_eq!(
            *events.borrow(),
            vec![
                "pi_target(foo)".to_string(),
                "pi_data(\"bar\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn scan_pi_bytes_no_data() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<?foo?>rest");
        assert!(s.scan_pi_bytes(0).unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "pi_target(foo)".to_string(),
                "pi_data(\"\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn scan_pi_bytes_reserved_xml_target_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<?xml version=\"1.0\"?>");
        assert!(s.scan_pi_bytes(0).is_err());
    }

    #[test]
    fn scan_pi_bytes_needs_more_mid_target() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<?fo");
        assert!(!s.scan_pi_bytes(0).unwrap());
        assert_eq!(s.pos, 0);

        s.append_bytes(b"o bar?>rest");
        assert!(s.scan_pi_bytes(0).unwrap());
    }

    #[test]
    fn scan_pi_bytes_needs_more_mid_data() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<?foo ba");
        assert!(!s.scan_pi_bytes(0).unwrap());

        s.append_bytes(b"r?>rest");
        assert!(s.scan_pi_data_bytes().unwrap());
        assert_eq!(
            *events.borrow(),
            vec![
                "pi_target(foo)".to_string(),
                "pi_data(\"ba\",false)".to_string(),
                "pi_data(\"r\",true)".to_string(),
            ]
        );
    }

    #[test]
    fn pi_scanning_matches_char_path() {
        for input in ["<?foo bar?>rest", "<?foo?>rest"] {
            let mut app_bytes = TagRecordingHandler::default();
            let bytes_events = Rc::clone(&app_bytes.events);
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            sb.scan_pi_bytes(0).unwrap();

            let mut app_chars = TagRecordingHandler::default();
            let char_events = Rc::clone(&app_chars.events);
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            sc.scan_pi(0).unwrap();

            assert_eq!(*bytes_events.borrow(), *char_events.borrow());
            assert_eq!(sb.pos, sc.pos);
        }
    }

    // ===== skip_external_id_bytes =====

    #[test]
    fn skip_external_id_bytes_system_only() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"SYSTEM \"http://example.com/a.dtd\"X");
        let r = s.skip_external_id_bytes(0).unwrap();
        assert_eq!(s.last_external_id_public_id, None);
        assert_eq!(
            s.last_external_id_system_id,
            Some("http://example.com/a.dtd".to_string())
        );
        assert_eq!(r, Some(33));
    }

    #[test]
    fn skip_external_id_bytes_public_and_system() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"PUBLIC \"-//A//B\" \"sys.dtd\"X");
        let r = s.skip_external_id_bytes(0).unwrap();
        assert_eq!(s.last_external_id_public_id, Some("-//A//B".to_string()));
        assert_eq!(s.last_external_id_system_id, Some("sys.dtd".to_string()));
        assert!(r.is_some());
    }

    #[test]
    fn skip_external_id_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"SYSTEM \"http");
        assert_eq!(s.skip_external_id_bytes(0).unwrap(), None);

        s.append_bytes(b"://x\"Y");
        let r = s.skip_external_id_bytes(0).unwrap();
        assert_eq!(s.last_external_id_system_id, Some("http://x".to_string()));
        assert!(r.is_some());
    }

    #[test]
    fn skip_external_id_bytes_missing_keyword_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"FOO \"bar\"");
        assert!(s.skip_external_id_bytes(0).is_err());
    }

    #[test]
    fn skip_external_id_matches_char_path() {
        for input in ["SYSTEM \"sys.dtd\"X", "PUBLIC \"-//A//B\" \"sys.dtd\"X"] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let br = sb.skip_external_id_bytes(0).unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let cr = sc.skip_external_id(0).unwrap();

            assert_eq!(br, cr);
            assert_eq!(sb.last_external_id_public_id, sc.last_external_id_public_id);
            assert_eq!(sb.last_external_id_system_id, sc.last_external_id_system_id);
        }
    }

    // ===== scan_notation_declaration_bytes =====

    #[test]
    fn scan_notation_declaration_bytes_system() {
        let mut app = TagRecordingHandler::default();
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo SYSTEM \"sys.dtd\">rest");
        let r = s.scan_notation_declaration_bytes(0).unwrap();
        assert!(r.is_some());
        assert!(s.declared_notations.contains("foo"));
        assert_eq!(
            s.notation_external_ids.get("foo").unwrap().system_id,
            Some("sys.dtd".to_string())
        );
    }

    #[test]
    fn scan_notation_declaration_bytes_public_with_system() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo PUBLIC \"-//A//B\" \"sys.dtd\">rest");
        s.scan_notation_declaration_bytes(0).unwrap();
        let ext = s.notation_external_ids.get("foo").unwrap();
        assert_eq!(ext.public_id, Some("-//A//B".to_string()));
        assert_eq!(ext.system_id, Some("sys.dtd".to_string()));
    }

    #[test]
    fn scan_notation_declaration_bytes_public_only() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo PUBLIC \"-//A//B\">rest");
        s.scan_notation_declaration_bytes(0).unwrap();
        let ext = s.notation_external_ids.get("foo").unwrap();
        assert_eq!(ext.public_id, Some("-//A//B".to_string()));
        assert_eq!(ext.system_id, None);
    }

    #[test]
    fn scan_notation_declaration_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo SYSTEM \"sys");
        assert_eq!(s.scan_notation_declaration_bytes(0).unwrap(), None);

        s.append_bytes(b".dtd\">rest");
        let r = s.scan_notation_declaration_bytes(0).unwrap();
        assert!(r.is_some());
        assert!(s.declared_notations.contains("foo"));
    }

    #[test]
    fn scan_notation_declaration_bytes_bad_name_start_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" 1foo SYSTEM \"sys.dtd\">rest");
        assert!(s.scan_notation_declaration_bytes(0).is_err());
    }

    #[test]
    fn notation_declaration_matches_char_path() {
        for input in [
            " foo SYSTEM \"sys.dtd\">rest",
            " foo PUBLIC \"-//A//B\" \"sys.dtd\">rest",
            " foo PUBLIC \"-//A//B\">rest",
        ] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let br = sb.scan_notation_declaration_bytes(0).unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let cr = sc.scan_notation_declaration(0).unwrap();

            assert_eq!(br, cr);
            assert_eq!(sb.notation_external_ids, sc.notation_external_ids);
        }
    }

    // ===== decode_char_ref_into_bytes =====

    #[test]
    fn decode_char_ref_into_bytes_decimal_and_hex() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#65;rest");
        let mut sb = String::new();
        let r = s.decode_char_ref_into_bytes(&mut sb, 0).unwrap();
        assert_eq!(sb, "A");
        assert_eq!(r, Some(5));

        let mut app2 = DefaultHandler;
        let mut s2 = make_scanner(&mut app2, false);
        s2.switch_to_bytes_mode();
        s2.append_bytes(b"&#x41;rest");
        let mut sb2 = String::new();
        let r2 = s2.decode_char_ref_into_bytes(&mut sb2, 0).unwrap();
        assert_eq!(sb2, "A");
        assert_eq!(r2, Some(6));
    }

    #[test]
    fn decode_char_ref_into_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&#65");
        let mut sb = String::new();
        assert_eq!(s.decode_char_ref_into_bytes(&mut sb, 0).unwrap(), None);
    }

    // ===== scan_reference_name_literal_bytes =====

    #[test]
    fn scan_reference_name_literal_bytes_preserves_literal_text() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&amp;rest");
        let mut sb = String::new();
        let r = s.scan_reference_name_literal_bytes(0, &mut sb, '&').unwrap();
        assert_eq!(sb, "&amp;");
        assert_eq!(r, Some(5));
    }

    #[test]
    fn scan_reference_name_literal_bytes_missing_semicolon_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"&amp rest");
        let mut sb = String::new();
        assert!(s.scan_reference_name_literal_bytes(0, &mut sb, '&').is_err());
    }

    // ===== resolve_parameter_entity_reference_at_bytes =====

    #[test]
    fn resolve_parameter_entity_reference_at_bytes_resolves() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"%foo;rest");
        let mut pending = PendingDecls::default();
        let r = s
            .resolve_parameter_entity_reference_at_bytes(0, &mut pending)
            .unwrap();
        assert_eq!(r, Some(Rc::from(['b', 'a', 'r'])));
        assert_eq!(s.last_pe_reference_end, 5);
    }

    #[test]
    fn resolve_parameter_entity_reference_at_bytes_disallowed_in_internal_subset() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = false;
        s.parameter_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"%foo;rest");
        let mut pending = PendingDecls::default();
        assert!(s
            .resolve_parameter_entity_reference_at_bytes(0, &mut pending)
            .is_err());
    }

    // ===== scan_quoted_literal_with_char_refs_bytes =====

    #[test]
    fn quoted_literal_with_char_refs_bytes_plain_text() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"hello\"rest");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        let r = s
            .scan_quoted_literal_with_char_refs_bytes(0, &mut sb, false, &mut pending)
            .unwrap();
        assert_eq!(sb, "hello");
        assert_eq!(r, Some(7));
    }

    #[test]
    fn quoted_literal_with_char_refs_bytes_resolves_char_ref() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"a&#65;b\"rest");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        s.scan_quoted_literal_with_char_refs_bytes(0, &mut sb, false, &mut pending)
            .unwrap();
        assert_eq!(sb, "aAb");
    }

    #[test]
    fn quoted_literal_with_char_refs_bytes_preserves_entity_ref_literally() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"a&amp;b\"rest");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        s.scan_quoted_literal_with_char_refs_bytes(0, &mut sb, false, &mut pending)
            .unwrap();
        assert_eq!(sb, "a&amp;b");
    }

    #[test]
    fn quoted_literal_with_char_refs_bytes_expands_pe_reference() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("foo".to_string(), Rc::from(['X', 'Y']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"a%foo;b\"rest");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        s.scan_quoted_literal_with_char_refs_bytes(0, &mut sb, true, &mut pending)
            .unwrap();
        assert_eq!(sb, "aXYb");
    }

    #[test]
    fn quoted_literal_with_char_refs_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"hel");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        assert_eq!(
            s.scan_quoted_literal_with_char_refs_bytes(0, &mut sb, false, &mut pending)
                .unwrap(),
            None
        );
    }

    #[test]
    fn quoted_literal_with_char_refs_bytes_illegal_char_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"\"a\x01b\"rest");
        let mut sb = String::new();
        let mut pending = PendingDecls::default();
        assert!(s
            .scan_quoted_literal_with_char_refs_bytes(0, &mut sb, false, &mut pending)
            .is_err());
    }

    #[test]
    fn quoted_literal_with_char_refs_matches_char_path() {
        for input in ["\"hello\"rest", "\"a&#65;b\"rest", "\"a&amp;b\"rest"] {
            let mut app_bytes = DefaultHandler;
            let mut sb_scanner = make_scanner(&mut app_bytes, false);
            sb_scanner.switch_to_bytes_mode();
            sb_scanner.append_bytes(input.as_bytes());
            let mut sb_str = String::new();
            let mut pending_b = PendingDecls::default();
            let br = sb_scanner
                .scan_quoted_literal_with_char_refs_bytes(0, &mut sb_str, false, &mut pending_b)
                .unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let mut sc_str = String::new();
            let mut pending_c = PendingDecls::default();
            let cr = sc
                .scan_quoted_literal_with_char_refs(0, &mut sc_str, false, &mut pending_c)
                .unwrap();

            assert_eq!(br, cr);
            assert_eq!(sb_str, sc_str);
        }
    }

    // ===== scan_entity_declaration_bytes =====

    #[test]
    fn scan_entity_declaration_bytes_internal_general() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo \"bar\">rest");
        let mut pending = PendingDecls::default();
        let r = s.scan_entity_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
        assert_eq!(
            pending.entities.get("foo").unwrap(),
            &Rc::from(['b', 'a', 'r'])
        );
    }

    #[test]
    fn scan_entity_declaration_bytes_internal_parameter() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" % foo \"bar\">rest");
        let mut pending = PendingDecls::default();
        s.scan_entity_declaration_bytes(0, &mut pending).unwrap();
        assert_eq!(
            pending.param_entities.get("foo").unwrap(),
            &Rc::from(['b', 'a', 'r'])
        );
    }

    #[test]
    fn scan_entity_declaration_bytes_external_system() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo SYSTEM \"sys.ent\">rest");
        let mut pending = PendingDecls::default();
        s.scan_entity_declaration_bytes(0, &mut pending).unwrap();
        let ext = pending.external_names.get("foo").unwrap();
        assert_eq!(ext.system_id, Some("sys.ent".to_string()));
        assert_eq!(ext.ndata, None);
    }

    #[test]
    fn scan_entity_declaration_bytes_external_with_ndata() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo SYSTEM \"sys.bin\" NDATA gif>rest");
        let mut pending = PendingDecls::default();
        s.scan_entity_declaration_bytes(0, &mut pending).unwrap();
        let ext = pending.external_names.get("foo").unwrap();
        assert_eq!(ext.ndata, Some("gif".to_string()));
    }

    #[test]
    fn scan_entity_declaration_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo \"ba");
        let mut pending = PendingDecls::default();
        assert_eq!(s.scan_entity_declaration_bytes(0, &mut pending).unwrap(), None);

        s.append_bytes(b"r\">rest");
        let r = s.scan_entity_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
        assert_eq!(
            pending.entities.get("foo").unwrap(),
            &Rc::from(['b', 'a', 'r'])
        );
    }

    #[test]
    fn scan_entity_declaration_bytes_malformed_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" 1foo \"bar\">rest");
        let mut pending = PendingDecls::default();
        assert!(s.scan_entity_declaration_bytes(0, &mut pending).is_err());
    }

    #[test]
    fn entity_declaration_matches_char_path() {
        for input in [
            " foo \"bar\">rest",
            " % foo \"bar\">rest",
            " foo SYSTEM \"sys.ent\">rest",
            " foo SYSTEM \"sys.bin\" NDATA gif>rest",
        ] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let mut pending_b = PendingDecls::default();
            let br = sb.scan_entity_declaration_bytes(0, &mut pending_b).unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let mut pending_c = PendingDecls::default();
            let cr = sc.scan_entity_declaration(0, &mut pending_c).unwrap();

            assert_eq!(br, cr);
            assert_eq!(pending_b.entities, pending_c.entities);
            assert_eq!(pending_b.param_entities, pending_c.param_entities);
            assert_eq!(pending_b.external_names, pending_c.external_names);
        }
    }

    // ===== scan_enumeration_list_bytes =====

    #[test]
    fn scan_enumeration_list_bytes_basic() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"(a|b|c)rest");
        let r = s.scan_enumeration_list_bytes(0, false).unwrap();
        assert!(r.is_some());
        assert_eq!(
            s.last_enumeration_values,
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn scan_enumeration_list_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"(a|b");
        assert_eq!(s.scan_enumeration_list_bytes(0, false).unwrap(), None);

        s.append_bytes(b"|c)rest");
        let r = s.scan_enumeration_list_bytes(0, false).unwrap();
        assert!(r.is_some());
    }

    #[test]
    fn scan_enumeration_list_bytes_malformed_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"(a|)rest");
        assert!(s.scan_enumeration_list_bytes(0, false).is_err());
    }

    #[test]
    fn enumeration_list_matches_char_path() {
        for input in ["(a|b|c)rest", "(only)rest"] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let br = sb.scan_enumeration_list_bytes(0, false).unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let cr = sc.scan_enumeration_list(0, false).unwrap();

            assert_eq!(br, cr);
            assert_eq!(sb.last_enumeration_values, sc.last_enumeration_values);
        }
    }

    // ===== splice_into_buf_bytes / splice_pe_reference_at_bytes =====

    #[test]
    fn splice_pe_reference_at_bytes_grows_buffer() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"before %foo; after");
        let mut pending = PendingDecls::default();
        let p = 7; // position of '%'
        let new_pos = s.splice_pe_reference_at_bytes(p, &mut pending, false).unwrap();
        assert_eq!(new_pos, p);
        let text = std::str::from_utf8(&s.buf.as_bytes()[..s.limit]).unwrap();
        assert_eq!(text, "before  bar  after");
    }

    #[test]
    fn splice_pe_reference_at_bytes_shrinks_buffer() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("longname".to_string(), Rc::from(['x']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"before %longname; after");
        let mut pending = PendingDecls::default();
        let p = 7; // position of '%'
        s.splice_pe_reference_at_bytes(p, &mut pending, false).unwrap();
        let text = std::str::from_utf8(&s.buf.as_bytes()[..s.limit]).unwrap();
        assert_eq!(text, "before  x  after");
    }

    #[test]
    fn skip_whitespace_in_declaration_bytes_expands_pe_as_separator() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("ws".to_string(), Rc::from([]));
        s.switch_to_bytes_mode();
        s.append_bytes(b"%ws;name");
        let mut pending = PendingDecls::default();
        let p = s
            .skip_whitespace_in_declaration_bytes(0, &mut pending, false)
            .unwrap();
        assert_eq!(&s.buf.as_bytes()[p..p + 4], b"name");
    }

    // ===== scan_element_declaration_bytes =====

    #[test]
    fn scan_element_declaration_bytes_empty() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo EMPTY>rest");
        let mut pending = PendingDecls::default();
        let r = s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(decl.content_type, crate::dtd::ContentType::Empty);
    }

    #[test]
    fn scan_element_declaration_bytes_any() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo ANY>rest");
        let mut pending = PendingDecls::default();
        s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(decl.content_type, crate::dtd::ContentType::Any);
    }

    #[test]
    fn scan_element_declaration_bytes_mixed_pcdata_only() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo (#PCDATA)>rest");
        let mut pending = PendingDecls::default();
        s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(decl.content_type, crate::dtd::ContentType::Mixed);
        assert_eq!(decl.content_model.as_ref().unwrap().to_string(), "(#PCDATA)");
    }

    #[test]
    fn scan_element_declaration_bytes_mixed_with_elements() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo (#PCDATA|a|b)*>rest");
        let mut pending = PendingDecls::default();
        s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(
            decl.content_model.as_ref().unwrap().to_string(),
            "(#PCDATA | a | b)*"
        );
    }

    #[test]
    fn scan_element_declaration_bytes_sequence_and_choice_with_occurrence() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo (a,(b|c)?,d+)*>rest");
        let mut pending = PendingDecls::default();
        s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(
            decl.content_model.as_ref().unwrap().to_string(),
            "(a, (b | c)?, d+)*"
        );
    }

    #[test]
    fn scan_element_declaration_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo (a,b");
        let mut pending = PendingDecls::default();
        assert_eq!(
            s.scan_element_declaration_bytes(0, &mut pending).unwrap(),
            None
        );

        s.append_bytes(b")>rest");
        let r = s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
    }

    #[test]
    fn scan_element_declaration_bytes_malformed_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" 1foo EMPTY>rest");
        let mut pending = PendingDecls::default();
        assert!(s.scan_element_declaration_bytes(0, &mut pending).is_err());
    }

    #[test]
    fn scan_element_declaration_bytes_pe_reference_inside_content_model() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.parsing_external_content = true;
        s.parameter_entities
            .insert("children".to_string(), Rc::from(['a', ',', 'b']));
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo (%children;)>rest");
        let mut pending = PendingDecls::default();
        let r = s.scan_element_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
        let decl = s.dtd_model.get_element_declaration("foo").unwrap();
        assert_eq!(decl.content_model.as_ref().unwrap().to_string(), "(a, b)");
    }

    #[test]
    fn element_declaration_matches_char_path() {
        for input in [
            " foo EMPTY>rest",
            " foo ANY>rest",
            " foo (#PCDATA)>rest",
            " foo (#PCDATA|a|b)*>rest",
            " foo (a,(b|c)?,d+)*>rest",
        ] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let mut pending_b = PendingDecls::default();
            let br = sb.scan_element_declaration_bytes(0, &mut pending_b).unwrap();
            let model_b = sb
                .dtd_model
                .get_element_declaration("foo")
                .unwrap()
                .content_model
                .as_ref()
                .map(|m| m.to_string());

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let mut pending_c = PendingDecls::default();
            let cr = sc.scan_element_declaration(0, &mut pending_c).unwrap();
            let model_c = sc
                .dtd_model
                .get_element_declaration("foo")
                .unwrap()
                .content_model
                .as_ref()
                .map(|m| m.to_string());

            assert_eq!(br, cr);
            assert_eq!(model_b, model_c);
        }
    }

    // ===== scan_attlist_declaration_bytes =====

    #[test]
    fn scan_attlist_declaration_bytes_cdata_implied() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar CDATA #IMPLIED>rest");
        let mut pending = PendingDecls::default();
        let r = s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
        let attrs = s.dtd_model.get_attributes("foo").unwrap();
        let (name, def) = &attrs[0];
        assert_eq!(name, "bar");
        assert_eq!(def.attr_type, "CDATA");
        assert_eq!(def.mode, crate::dtd::Mode::Implied);
        assert_eq!(def.default_value, None);
    }

    #[test]
    fn scan_attlist_declaration_bytes_fixed_default_with_entity_ref() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar CDATA #FIXED \"x&amp;y\">rest");
        let mut pending = PendingDecls::default();
        s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        let attrs = s.dtd_model.get_attributes("foo").unwrap();
        let (_, def) = &attrs[0];
        assert_eq!(def.mode, crate::dtd::Mode::Fixed);
        assert_eq!(def.default_value, Some("x&amp;y".to_string()));
    }

    #[test]
    fn scan_attlist_declaration_bytes_enumeration() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar (a|b|c) \"a\">rest");
        let mut pending = PendingDecls::default();
        s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        let attrs = s.dtd_model.get_attributes("foo").unwrap();
        let (_, def) = &attrs[0];
        assert_eq!(def.attr_type, "ENUMERATION");
        assert_eq!(
            def.enumeration,
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(def.default_value, Some("a".to_string()));
    }

    #[test]
    fn scan_attlist_declaration_bytes_notation_enumeration() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar NOTATION (gif|jpeg) #REQUIRED>rest");
        let mut pending = PendingDecls::default();
        s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        let attrs = s.dtd_model.get_attributes("foo").unwrap();
        let (_, def) = &attrs[0];
        assert_eq!(def.attr_type, "NOTATION");
        assert_eq!(
            def.enumeration,
            Some(vec!["gif".to_string(), "jpeg".to_string()])
        );
        assert_eq!(def.mode, crate::dtd::Mode::Required);
    }

    #[test]
    fn scan_attlist_declaration_bytes_multiple_attributes() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo a CDATA #IMPLIED b CDATA #REQUIRED>rest");
        let mut pending = PendingDecls::default();
        s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        let attrs = s.dtd_model.get_attributes("foo").unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, "a");
        assert_eq!(attrs[1].0, "b");
    }

    #[test]
    fn scan_attlist_declaration_bytes_needs_more() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar CDATA #IMP");
        let mut pending = PendingDecls::default();
        assert_eq!(
            s.scan_attlist_declaration_bytes(0, &mut pending).unwrap(),
            None
        );

        s.append_bytes(b"LIED>rest");
        let r = s.scan_attlist_declaration_bytes(0, &mut pending).unwrap();
        assert!(r.is_some());
    }

    #[test]
    fn scan_attlist_declaration_bytes_unrecognised_type_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b" foo bar BOGUS #IMPLIED>rest");
        let mut pending = PendingDecls::default();
        assert!(s.scan_attlist_declaration_bytes(0, &mut pending).is_err());
    }

    #[test]
    fn attlist_declaration_matches_char_path() {
        for input in [
            " foo bar CDATA #IMPLIED>rest",
            " foo bar CDATA #FIXED \"x&amp;y\">rest",
            " foo bar (a|b|c) \"a\">rest",
            " foo bar NOTATION (gif|jpeg) #REQUIRED>rest",
            " foo a CDATA #IMPLIED b CDATA #REQUIRED>rest",
        ] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let mut pending_b = PendingDecls::default();
            let br = sb.scan_attlist_declaration_bytes(0, &mut pending_b).unwrap();
            let attrs_b: Vec<(String, String, crate::dtd::Mode, Option<String>, Option<Vec<String>>)> = sb
                .dtd_model
                .get_attributes("foo")
                .map(|list| {
                    list.iter()
                        .map(|(n, d)| {
                            (
                                n.clone(),
                                d.attr_type.clone(),
                                d.mode,
                                d.default_value.clone(),
                                d.enumeration.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let mut pending_c = PendingDecls::default();
            let cr = sc.scan_attlist_declaration(0, &mut pending_c).unwrap();
            let attrs_c: Vec<(String, String, crate::dtd::Mode, Option<String>, Option<Vec<String>>)> = sc
                .dtd_model
                .get_attributes("foo")
                .map(|list| {
                    list.iter()
                        .map(|(n, d)| {
                            (
                                n.clone(),
                                d.attr_type.clone(),
                                d.mode,
                                d.default_value.clone(),
                                d.enumeration.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            assert_eq!(br, cr);
            assert_eq!(attrs_b, attrs_c);
        }
    }

    // ===== scan_doctype_bytes / scan_doctype_subset_inner_bytes =====

    fn make_scanner_skip_mode(handler: &mut dyn XmlHandler) -> Scanner<'_> {
        let mut features = FeatureSet::default();
        features.doctype_handling = crate::features::DoctypeHandling::Skip;
        let settings = features.scanner_settings();
        Scanner::new(handler, false, None, None, None, false, true, settings, false).unwrap()
    }

    #[test]
    fn scan_doctype_bytes_no_internal_subset() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo>rest");
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.doctype_seen);
        assert_eq!(s.doctype_name, Some("foo".to_string()));
        let text = std::str::from_utf8(&s.buf.as_bytes()[s.pos..s.limit]).unwrap();
        assert_eq!(text, "rest");
    }

    #[test]
    fn scan_doctype_bytes_internal_subset_all_declaration_kinds() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(
            b"<!DOCTYPE foo [\n\
              <!ELEMENT foo (bar)>\n\
              <!ATTLIST foo id ID #IMPLIED>\n\
              <!ENTITY amp2 \"&amp;\">\n\
              <!NOTATION png SYSTEM \"image/png\">\n\
              ]>rest",
        );
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_some());
        assert!(s.dtd_model.get_attributes("foo").is_some());
        // Entity references inside an <!ENTITY> value literal are
        // preserved literally, not resolved (only character references
        // resolve immediately) — see quoted_literal_with_char_refs_bytes_
        // preserves_entity_ref_literally.
        assert_eq!(
            s.general_entities.get("amp2").unwrap(),
            &Rc::from(['&', 'a', 'm', 'p', ';'])
        );
        assert!(s.declared_notations.contains("png"));
    }

    #[test]
    fn scan_doctype_bytes_internal_subset_with_comment_and_pi() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo [<!--c--><?pi d?><!ELEMENT foo EMPTY>]>rest");
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_some());
    }

    #[test]
    fn scan_doctype_bytes_pe_reference_expands_to_full_declaration() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(
            b"<!DOCTYPE foo [<!ENTITY % decl \"<!ELEMENT bar EMPTY>\">%decl;]>rest",
        );
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("bar").is_some());
    }

    #[test]
    fn scan_doctype_bytes_pe_reference_expands_to_include_section() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(
            b"<!DOCTYPE foo [<!ENTITY % sect \"<![INCLUDE[<!ELEMENT baz EMPTY>]]>\">%sect;]>rest",
        );
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("baz").is_some());
    }

    #[test]
    fn scan_doctype_bytes_pe_reference_expands_to_ignore_section() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(
            b"<!DOCTYPE foo [<!ENTITY % sect2 \"<![IGNORE[<!ELEMENT qux EMPTY>]]>\">%sect2;]>rest",
        );
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("qux").is_none());
    }

    #[test]
    fn scan_doctype_bytes_needs_more_mid_subset() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo [<!ELEMENT foo EM");
        assert!(!s.scan_doctype_bytes(0).unwrap());

        // append_bytes compacts the buffer (advances past already-consumed
        // bytes), so position 0 is no longer the start of the DOCTYPE
        // declaration — resumption must continue via
        // scan_doctype_subset_bytes() from self.pos, exactly like the
        // real dispatcher's `in_doctype` branch does, not by re-entering
        // scan_doctype_bytes at a stale tag_start.
        s.append_bytes(b"PTY>]>rest");
        let r = s.scan_doctype_subset_bytes().unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_some());
    }

    #[test]
    fn scan_doctype_bytes_only_one_allowed_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.doctype_seen = true;
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo>rest");
        assert!(s.scan_doctype_bytes(0).is_err());
    }

    #[test]
    fn scan_doctype_bytes_malformed_is_error() {
        let mut app = DefaultHandler;
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE 1foo>rest");
        assert!(s.scan_doctype_bytes(0).is_err());
    }

    #[test]
    fn scan_doctype_bytes_skip_mode_ignores_declarations() {
        let mut app = DefaultHandler;
        let mut s = make_scanner_skip_mode(&mut app);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo [<!ELEMENT foo (bar)><!--c--><?pi d?>]>rest");
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_none());
        assert!(s.doctype_seen);
    }

    #[test]
    fn scan_doctype_bytes_skip_mode_needs_more_mid_skipped_declaration() {
        let mut app = DefaultHandler;
        let mut s = make_scanner_skip_mode(&mut app);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo [<!ELEMENT foo (b");
        assert!(!s.scan_doctype_bytes(0).unwrap());

        // Same buffer-compaction reasoning as the Process-mode test above;
        // resume via skip_doctype_subset_inner_bytes() directly.
        s.append_bytes(b"ar)>]>rest");
        let r = s.skip_doctype_subset_inner_bytes().unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_none());
    }

    #[test]
    fn doctype_matches_char_path() {
        for input in [
            "<!DOCTYPE foo>rest",
            "<!DOCTYPE foo [<!ELEMENT foo (bar)><!ATTLIST foo id ID #IMPLIED><!ENTITY amp2 \"&amp;\"><!NOTATION png SYSTEM \"image/png\">]>rest",
            "<!DOCTYPE foo [<!ENTITY % decl \"<!ELEMENT bar EMPTY>\">%decl;]>rest",
        ] {
            let mut app_bytes = DefaultHandler;
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            let br = sb.scan_doctype_bytes(0).unwrap();

            let mut app_chars = DefaultHandler;
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            let cr = sc.scan_doctype(0).unwrap();

            assert_eq!(br, cr);
            assert_eq!(sb.doctype_name, sc.doctype_name);
            assert_eq!(sb.general_entities, sc.general_entities);
            assert_eq!(
                sb.dtd_model.get_element_declaration("foo").is_some(),
                sc.dtd_model.get_element_declaration("foo").is_some()
            );
        }
    }

    // ===== finish_doctype_external_subset / fetch_external_resource =====
    //
    // Neither needed a byte-native port at all: `fetch_external_resource`
    // fetches raw bytes via an EntityResolver/filesystem and decodes them
    // into a fresh Vec<char>, never touching self.buf; `parse_external_subset`
    // always parses that fetched content through its own temporary
    // Vec<char> swap, regardless of what representation the live scanner
    // is in. scan_doctype_bytes already calls finish_doctype_external_subset
    // unchanged -- this test just confirms that wiring actually resolves
    // and parses an external subset end-to-end from the byte path.

    struct StaticResolver {
        content: &'static [u8],
    }

    impl crate::entity::EntityResolver for StaticResolver {
        fn resolve(
            &mut self,
            _public_id: Option<&str>,
            _system_id: &str,
            _base_uri: Option<&str>,
        ) -> ParseResult<Option<crate::entity::ResolvedEntity>> {
            Ok(Some(crate::entity::ResolvedEntity::new(self.content)))
        }
    }

    #[test]
    fn scan_doctype_bytes_fetches_and_parses_external_subset() {
        let mut app = DefaultHandler;
        let mut features = FeatureSet::default();
        features.external_parameter_entities = true;
        features.access_external_dtd = "all".to_string();
        let settings = features.scanner_settings();
        let resolver = StaticResolver {
            content: b"<!ELEMENT foo (bar)>",
        };
        let mut s = Scanner::new(
            &mut app,
            false,
            Some(Box::new(resolver)),
            None,
            None,
            false,
            true,
            settings,
            false,
        )
        .unwrap();
        s.switch_to_bytes_mode();
        s.append_bytes(b"<!DOCTYPE foo SYSTEM \"ext.dtd\">rest");
        let r = s.scan_doctype_bytes(0).unwrap();
        assert!(r);
        assert!(s.dtd_model.get_element_declaration("foo").is_some());
    }

    // ===== scan_bytes: full top-level dispatch loop =====
    //
    // These are the first genuinely end-to-end tests in this exploration —
    // a full document, or a full recursive entity expansion, driven start
    // to finish through scan_bytes() alone, exercising every byte-native
    // scanner built across this whole session together.

    fn characters_text(events: &[String]) -> String {
        events
            .iter()
            .filter_map(|e| {
                let rest = e.strip_prefix("characters(\"")?;
                let end = rest.find("\",")?;
                Some(rest[..end].to_string())
            })
            .collect()
    }

    #[test]
    fn scan_bytes_full_simple_document() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<root>hello</root>");
        s.scan_bytes().unwrap();
        assert_eq!(
            *events.borrow(),
            vec![
                "start_element(root)".to_string(),
                "end_attributes".to_string(),
                "characters(\"hello\",false,true)".to_string(),
                "end_element".to_string(),
            ]
        );
    }

    #[test]
    fn scan_bytes_full_document_with_attributes_comment_pi_cdata() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<root a=\"x&amp;y\"><!--c--><?pi d?><![CDATA[raw]]>tail</root>");
        s.scan_bytes().unwrap();
        let ev = events.borrow();
        assert_eq!(ev[0], "start_element(root)");
        assert!(ev.contains(&"start_attribute(a,CDATA,false,true)".to_string()));
        assert!(ev.contains(&"attr_value(\"x\",false)".to_string()));
        assert!(ev.contains(&"attr_value(\"&\",false)".to_string()));
        assert!(ev.contains(&"attr_value(\"y\",true)".to_string()));
        assert!(ev.contains(&"start_comment".to_string()));
        assert!(ev.contains(&"comment_data(\"c\",true)".to_string()));
        assert!(ev.contains(&"pi_target(pi)".to_string()));
        assert!(ev.contains(&"pi_data(\"d\",true)".to_string()));
        assert!(ev.contains(&"start_cdata".to_string()));
        assert!(ev.contains(&"characters(\"raw\",false,true)".to_string()));
        assert!(ev.contains(&"end_cdata".to_string()));
        assert!(ev.contains(&"characters(\"tail\",false,true)".to_string()));
        assert_eq!(ev.last().unwrap(), "end_element");
    }

    #[test]
    fn scan_bytes_expands_general_entity_in_content() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.general_entities
            .insert("foo".to_string(), Rc::from(['b', 'a', 'r']));
        s.switch_to_bytes_mode();
        s.append_bytes(b"<root>pre&foo;post</root>");
        s.scan_bytes().unwrap();
        let ev = events.borrow();
        assert!(ev.contains(&"start_entity(foo)".to_string()));
        assert!(ev.contains(&"end_entity(foo)".to_string()));
        let start_entity_idx = ev.iter().position(|e| e == "start_entity(foo)").unwrap();
        let end_entity_idx = ev.iter().position(|e| e == "end_entity(foo)").unwrap();
        assert!(start_entity_idx < end_entity_idx);
        assert_eq!(characters_text(&ev), "prebarpost");
        assert_eq!(ev.last().unwrap(), "end_element");
    }

    #[test]
    fn scan_bytes_expands_general_entity_with_nested_markup_in_content() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.general_entities.insert(
            "elem".to_string(),
            Rc::from("<child>x</child>".chars().collect::<Vec<char>>()),
        );
        s.switch_to_bytes_mode();
        s.append_bytes(b"<root>a&elem;b</root>");
        s.scan_bytes().unwrap();
        let ev = events.borrow();
        let start_entity_idx = ev.iter().position(|e| e == "start_entity(elem)").unwrap();
        let start_child_idx = ev
            .iter()
            .position(|e| e == "start_element(child)")
            .unwrap();
        let end_entity_idx = ev.iter().position(|e| e == "end_entity(elem)").unwrap();
        assert!(start_entity_idx < start_child_idx);
        assert!(start_child_idx < end_entity_idx);
        assert_eq!(characters_text(&ev), "axb");
        // Full document parsed to a clean close: <child> opened and closed
        // strictly within the entity's replacement text, and </root>
        // closed the root — no unbalanced element boundary leaked across
        // the entity-expansion recursion.
        assert!(s.element_stack.is_empty());
        assert_eq!(ev.last().unwrap(), "end_element");
    }

    #[test]
    fn scan_bytes_needs_more_across_full_document() {
        let mut app = TagRecordingHandler::default();
        let events = Rc::clone(&app.events);
        let mut s = make_scanner(&mut app, false);
        s.switch_to_bytes_mode();
        s.append_bytes(b"<root a=\"1");
        s.scan_bytes().unwrap();
        assert!(!events.borrow().contains(&"end_attributes".to_string()));

        s.append_bytes(b"\">hel");
        s.scan_bytes().unwrap();

        s.append_bytes(b"lo</root>");
        s.scan_bytes().unwrap();

        let ev = events.borrow();
        assert_eq!(ev[0], "start_element(root)");
        assert!(ev.contains(&"end_attributes".to_string()));
        assert_eq!(characters_text(&ev), "hello");
        assert_eq!(ev.last().unwrap(), "end_element");
    }

    #[test]
    fn scan_bytes_matches_char_path_on_full_document() {
        for input in [
            "<root>hello</root>",
            "<root a=\"x&amp;y\"><!--c--><?pi d?>text</root>",
        ] {
            let mut app_bytes = TagRecordingHandler::default();
            let bytes_events = Rc::clone(&app_bytes.events);
            let mut sb = make_scanner(&mut app_bytes, false);
            sb.switch_to_bytes_mode();
            sb.append_bytes(input.as_bytes());
            sb.scan_bytes().unwrap();

            let mut app_chars = TagRecordingHandler::default();
            let char_events = Rc::clone(&app_chars.events);
            let mut sc = make_scanner(&mut app_chars, false);
            sc.append(input);
            sc.scan().unwrap();

            assert_eq!(*bytes_events.borrow(), *char_events.borrow());
        }
    }
}
