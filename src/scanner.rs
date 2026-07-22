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

use crate::decoder;
use crate::dtd::{
    ContentModel, ContentModelValidator, ContentType, DtdModel, ElementDeclaration, Mode, NodeType,
    Occurrence,
};
use crate::entity::{EntityResolver, ExternalId};
use crate::error::{ParseError, ParseResult};
use crate::features::ScannerSettings;
use crate::handler::XmlHandler;
use crate::locator::DocumentLocator;
use crate::names::PackedName;

const INITIAL_CAPACITY: usize = 8192;

#[derive(Clone, Copy, PartialEq, Eq)]
enum KwResult {
    Match,
    NoMatch,
    NeedMore,
}

enum RefResult {
    NeedMore,
    Decoded(String),
    General(String),
}

/// External general entity identifiers: `(publicId, systemId, ndataName)`.
#[derive(Clone, Debug)]
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
    entities: HashMap<String, String>,
    external_names: HashMap<String, ExtEntity>,
    param_entities: HashMap<String, String>,
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
    document_started: bool,
    defer_document_start_until_encoding: bool,

    buf: Vec<char>,
    pos: usize,
    limit: usize,

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

    element_stack: Vec<String>,
    validator_stack: Option<Vec<ContentModelValidator>>,

    seen_attribute_names: Vec<String>,

    name_pool: PackedName,

    root_started: bool,
    root_ended: bool,
    doctype_seen: bool,
    doctype_name: Option<String>,

    in_doctype: bool,
    doctype_subset_closed: bool,
    doctype_name_pending: Option<String>,
    doctype_pending: Option<PendingDecls>,

    doctype_external_public_id: Option<String>,
    doctype_external_system_id: Option<String>,
    doctype_public_id: Option<String>,
    doctype_system_id: Option<String>,

    general_entities: HashMap<String, String>,
    external_entity_names: HashMap<String, ExtEntity>,
    parameter_entities: HashMap<String, String>,
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
    let u = c as u32;
    if c == ':' || c == '_' || c.is_ascii_uppercase() || c.is_ascii_lowercase() {
        return true;
    }
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
    if is_name_start_char(c) {
        return true;
    }
    let u = c as u32;
    c == '-'
        || c == '.'
        || c.is_ascii_digit()
        || u == 0xB7
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
            document_started: false,
            defer_document_start_until_encoding,
            buf: vec!['\u{0}'; INITIAL_CAPACITY],
            pos: 0,
            limit: 0,
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
            doctype_external_public_id: None,
            doctype_external_system_id: None,
            doctype_public_id: None,
            doctype_system_id: None,
            general_entities: HashMap::new(),
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

    /// Resets all streaming/parse state so the scanner can parse a fresh
    /// document with the same handler, resolver, and settings.
    pub fn reset(&mut self) {
        self.encoding = None;
        self.document_started = false;
        self.buf.clear();
        self.buf.resize(INITIAL_CAPACITY, '\u{0}');
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
        self.doctype_external_public_id = None;
        self.doctype_external_system_id = None;
        self.doctype_public_id = None;
        self.doctype_system_id = None;
        self.general_entities.clear();
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
        let needed = data.chars().count();
        if self.pos > 0 {
            let remaining = self.limit - self.pos;
            if remaining > 0 {
                self.buf.copy_within(self.pos..self.limit, 0);
            }
            self.limit = remaining;
            self.pos = 0;
        }
        if self.limit + needed > self.buf.len() {
            let mut newcap = self.buf.len().max(1) * 2;
            while newcap < self.limit + needed {
                newcap *= 2;
            }
            self.buf.resize(newcap, '\u{0}');
        }
        for (i, c) in data.chars().enumerate() {
            self.buf[self.limit + i] = c;
        }
        self.limit += needed;
    }

    fn slice(&self, start: usize, end: usize) -> String {
        self.buf[start..end].iter().collect()
    }

    // ===== Whole-DTD end-of-document checks =====

    fn check_entity_values_do_not_reference_unparsed_entities(&mut self) -> ParseResult<()> {
        let entries: Vec<(String, String)> = self
            .general_entities
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, value) in entries {
            let chars: Vec<char> = value.chars().collect();
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

    fn record_seen_attribute_name(&mut self, name: String) -> ParseResult<()> {
        if self.was_attribute_seen(&name) {
            return Err(self.fatal(&format!(
                "Well-formedness Constraint: Unique Att Spec. Attribute \"{name}\" already appeared on this element."
            )));
        }
        self.seen_attribute_names.push(name);
        Ok(())
    }

    fn was_attribute_seen(&self, name: &str) -> bool {
        self.seen_attribute_names.iter().any(|n| n == name)
    }

    fn check_entity_expansion_limit(&mut self) -> ParseResult<()> {
        self.entity_expansion_count += 1;
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

    fn check_name_start_char(&mut self, name_start: usize) -> ParseResult<()> {
        if !is_name_start_char(self.buf[name_start]) {
            return Err(self.fatal("Names must begin with a legal NameStartChar"));
        }
        Ok(())
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
        let s = self.slice(start, end_idx);
        if self.validation_enabled {
            self.record_text_for_validation(&s, is_ws)?;
        }
        self.handler.characters(&s, is_ws, end)
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
        if let Some(predef) = match_predefined(&self.buf, name_start, len) {
            self.pos = p + 1;
            return Ok(RefResult::Decoded(predef.to_string()));
        }
        let name: String = self.buf[name_start..p].iter().collect();
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
        let q_name = self.name_pool.intern_range(&self.buf, name_start, p - name_start);
        if !self.root_started {
            self.root_started = true;
            if self.validation_enabled {
                if let Some(dname) = self.doctype_name.clone() {
                    if dname != q_name {
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
                .intern_range(&self.buf, name_start, self.pos - name_start);

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
                .and_then(|attrs| attrs.iter().find(|(n, _)| *n == attr_name).map(|(_, d)| d));
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
            let check_xml_space = attr_name == "xml:space";
            self.normalizing_current_attribute =
                self.collapse_current_attr_value || self.validation_enabled || check_xml_space;
            if self.normalizing_current_attribute {
                self.normalize_builder.clear();
                if self.validation_enabled || check_xml_space {
                    self.current_attr_element_name = current_element_name.clone();
                    self.current_attr_name = attr_name.clone();
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

    fn is_attr_stop(&self, c: char, quote: char) -> bool {
        c == quote
            || c == '&'
            || c == '<'
            || c == '\t'
            || c == '\n'
            || c == '\r'
            || !self.is_legal_literal_char(c)
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
                    let s = self.slice(run_start, self.pos);
                    self.emit_attribute_value_content(&s, false)?;
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
                    let s = self.slice(run_start, self.pos);
                    self.emit_attribute_value_content(&s, true)?;
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
                let s = self.slice(run_start, amp_pos);
                self.emit_attribute_value_content(&s, false)?;
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
                    let s = self.slice(self.pos, p);
                    self.handler.comment_data(&s, false)?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf[p + 1] == '-' {
                if self.buf[p + 2] == '>' {
                    let s = self.slice(self.pos, p);
                    self.handler.comment_data(&s, true)?;
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
        let s = self.slice(start, end);
        // CDATA never matches the nonterminal S (Sun xmlconf empty / not-sa14):
        // even whitespace-only CDATA is character data for Element Valid, not
        // ignorable separator whitespace between children.
        if end > start && self.validation_enabled {
            self.record_text_for_validation(&s, false)?;
        }
        self.handler.characters(&s, false, is_end)
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
        let target = self.name_pool.intern_range(&self.buf, target_start, p - target_start);
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
                    let s = self.slice(self.pos, p);
                    self.handler.pi_data(&s, false)?;
                    self.pos = p;
                }
                return Ok(false);
            }
            if self.buf[p + 1] == '>' {
                let s = self.slice(self.pos, p);
                self.handler.pi_data(&s, true)?;
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
                        for rc in &replacement {
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
                    pending.param_entities.insert(name.clone(), sb.clone());
                    self.handler.internal_entity_decl(&format!("%{name}"), &sb)?;
                }
            } else if !pending.entities.contains_key(&name)
                && !pending.external_names.contains_key(&name)
                && !self.general_entities.contains_key(&name)
                && !self.external_entity_names.contains_key(&name)
            {
                pending.entities.insert(name.clone(), sb.clone());
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
                .intern_range(&self.buf, attr_name_start, p - attr_name_start);

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
        if self.settings.disallow_doctype_decl {
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
            self.doctype_pending = Some(PendingDecls::default());
            self.pos = p + 1;
            self.in_doctype = true;
            if !self.scan_doctype_subset()? {
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

    fn finish_doctype_external_subset(&mut self, root_name: &str) -> ParseResult<()> {
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
        self.check_entity_expansion_limit()?;
        Ok(true)
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
            replacement_chars = self.general_entities.get(name).unwrap().chars().collect();
        }

        self.entity_expansion_stack.push(name.to_string());
        let saved_buf = std::mem::replace(&mut self.buf, replacement_chars);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_content_run_open = self.content_run_open;
        let saved_allow_restricted = self.allow_restricted_char_in_content;
        let stack_depth_at_entry = self.element_stack.len();

        self.pos = 0;
        self.limit = self.buf.len();
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

        self.buf = saved_buf;
        self.pos = saved_pos;
        self.limit = saved_limit;
        self.content_run_open = saved_content_run_open;
        self.allow_restricted_char_in_content = saved_allow_restricted;
        self.entity_expansion_stack.pop();
        self.entity_stack_floors.pop();

        final_result
    }

    fn expand_general_entity_in_attribute_value(&mut self, name: &str) -> ParseResult<String> {
        if !self.check_entity_referenceable(name, false)? {
            return Ok(String::new());
        }
        let replacement = self.general_entities.get(name).cloned().unwrap_or_default();
        self.entity_expansion_stack.push(name.to_string());
        let rbuf: Vec<char> = replacement.chars().collect();
        let context = format!("entity \"{name}\"");
        let result = self.resolve_attribute_text(&rbuf, &context);
        self.entity_expansion_stack.pop();
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

        let saved_buf = std::mem::replace(&mut self.buf, chars);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        self.pos = 0;
        self.limit = self.buf.len();
        self.parsing_external_content = true;

        let result = self.parse_markup_decl_seq(false, false, &mut pending);

        let commit_result = if result.is_ok() {
            self.commit_external_subset(&mut pending)
        } else {
            Ok(())
        };

        self.buf = saved_buf;
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
        self.check_entity_expansion_limit()?;
        self.parameter_entity_expansion_stack.push(name.clone());

        let saved_buf = std::mem::replace(&mut self.buf, replacement_chars);
        let saved_pos = self.pos;
        let saved_limit = self.limit;
        let saved_parsing = self.parsing_external_content;
        let saved_base = self.base_system_id.clone();
        self.pos = 0;
        self.limit = self.buf.len();
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

        self.buf = saved_buf;
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
    ) -> ParseResult<Option<Vec<char>>> {
        let literal = pending
            .param_entities
            .get(name)
            .cloned()
            .or_else(|| self.parameter_entities.get(name).cloned());
        if let Some(literal) = literal {
            self.last_param_entity_was_external = false;
            return Ok(Some(literal.chars().collect()));
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
            return Ok(Some(Vec::new()));
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
        Ok(Some(self.strip_declaration(&fetched)?))
    }

    // ===== PE splicing inside declarations =====

    fn splice_into_buf(&mut self, start: usize, end: usize, replacement: &[char]) -> usize {
        let old_span = end - start;
        let new_span = replacement.len();
        let delta = new_span as i64 - old_span as i64;
        if delta > 0 {
            let needed = (self.limit as i64 + delta) as usize;
            if needed > self.buf.len() {
                let mut newcap = self.buf.len() * 2;
                while newcap < needed {
                    newcap *= 2;
                }
                self.buf.resize(newcap, '\u{0}');
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
        for (i, c) in replacement.iter().enumerate() {
            self.buf[start + i] = *c;
        }
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
        let mut replacement: Vec<char> = Vec::with_capacity(replacement_chars.len() + 2);
        replacement.push(' ');
        replacement.extend_from_slice(&replacement_chars);
        replacement.push(' ');
        let end = self.last_pe_reference_end;
        Ok(self.splice_into_buf(p, end, &replacement))
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
    ) -> ParseResult<Option<Vec<char>>> {
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
        self.check_entity_expansion_limit()?;
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

    // ===== Attribute defaults =====

    fn apply_attribute_defaults(&mut self, element_name: &str) -> ParseResult<()> {
        let declared: Option<Vec<(String, crate::dtd::AttDef)>> =
            self.dtd_model.get_attributes(element_name).cloned();
        let declared = match declared {
            None => return Ok(()),
            Some(d) => d,
        };
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
