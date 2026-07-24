// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Streaming XML serializer.
//!
//! Ported from Gonzalez `XMLWriter.java`. Writes XML to any [`std::io::Write`]
//! sink with optional pretty-print indentation, charset/BOM handling, XML 1.1
//! escaping, namespace declarations, and DTD output (including standalone
//! conversion).

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};

use encoding_rs::Encoding;

use crate::indent::IndentConfig;
use crate::namespace::XML_NAMESPACE_URI;

const DEFAULT_CAPACITY: usize = 4096;
const SEND_THRESHOLD_NUM: usize = 3;
const SEND_THRESHOLD_DEN: usize = 4;

const BOM_UTF16_BE: &[u8] = &[0xFE, 0xFF];
const BOM_UTF16_LE: &[u8] = &[0xFF, 0xFE];
const BOM_UTF32_BE: &[u8] = &[0x00, 0x00, 0xFE, 0xFF];
const BOM_UTF32_LE: &[u8] = &[0xFF, 0xFE, 0x00, 0x00];

/// Output character encoding for [`XmlWriter`].
///
/// UTF-16 and UTF-32 variants emit a BOM on the first write. `UTF-16` (without
/// endianness) maps to big-endian, matching Gonzalez.
#[derive(Clone, Copy, Debug)]
pub enum OutputCharset {
    Utf8,
    Utf16Be,
    Utf16Le,
    Utf32Be,
    Utf32Le,
    /// True ISO-8859-1 (byte N ↔ U+00N), not windows-1252.
    Iso8859_1,
    UsAscii,
    /// Any other encoding supported by `encoding_rs`.
    Encoding(&'static Encoding),
}

impl OutputCharset {
    /// Resolves a charset name the way Gonzalez `Charset.forName` / `setCharset`
    /// would for the encodings we care about.
    pub fn from_name(name: &str) -> Option<Self> {
        let upper = name.to_ascii_uppercase();
        match upper.as_str() {
            "UTF-8" | "UTF8" => Some(Self::Utf8),
            "UTF-16" | "UTF16" | "UTF-16BE" | "UTF16BE" => Some(Self::Utf16Be),
            "UTF-16LE" | "UTF16LE" => Some(Self::Utf16Le),
            "UTF-32" | "UTF32" | "UTF-32BE" | "UTF32BE" => Some(Self::Utf32Be),
            "UTF-32LE" | "UTF32LE" => Some(Self::Utf32Le),
            "ISO-8859-1" | "ISO8859-1" | "ISO_8859_1" | "LATIN1" | "L1" | "CSISOLATIN1"
            | "ISO-IR-100" => Some(Self::Iso8859_1),
            "US-ASCII" | "ASCII" | "ISO646-US" | "ISO_646.IRV:1991" | "ANSI_X3.4-1968"
            | "IBM367" | "CP367" => Some(Self::UsAscii),
            _ => Encoding::for_label(name.as_bytes()).map(Self::Encoding),
        }
    }

    fn pending_bom(self) -> Option<&'static [u8]> {
        match self {
            Self::Utf16Be => Some(BOM_UTF16_BE),
            Self::Utf16Le => Some(BOM_UTF16_LE),
            Self::Utf32Be => Some(BOM_UTF32_BE),
            Self::Utf32Le => Some(BOM_UTF32_LE),
            _ => None,
        }
    }

    fn is_utf8(self) -> bool {
        matches!(self, Self::Utf8)
    }
}

struct ElementInfo {
    q_name: String,
}

/// Streaming XML serializer.
///
/// Elements are opened with one of the `write_start_element` overloads. The
/// start tag remains open until any non-attribute event is received, allowing
/// attributes and namespace declarations to be added afterward. A
/// `write_end_element` with no intervening content produces the self-closing
/// `/>` form.
///
/// Configuration setters (`set_indent_config`, `set_charset`, `set_xml11`,
/// `set_standalone`) should be called before writing begins.
///
/// Not thread-safe. Does not close the underlying sink on [`Self::close`];
/// the caller is responsible for that.
pub struct XmlWriter<W: Write> {
    sink: W,
    buffer: Vec<u8>,
    send_threshold: usize,

    indent_config: Option<IndentConfig>,
    charset: OutputCharset,
    xml11: bool,
    standalone: bool,
    pending_bom: Option<&'static [u8]>,

    /// Pre-encoded ASCII bytes (0–127) for the current charset.
    encoded_ascii: Vec<Vec<u8>>,
    max_ascii_bytes: usize,

    element_stack: VecDeque<ElementInfo>,
    /// Namespace scopes: prefix → URI. Empty map is the shared empty scope.
    namespace_stack: VecDeque<HashMap<String, String>>,

    pending_start_tag: bool,
    has_content: bool,
    has_nested_elements: bool,
    at_document_start: bool,

    in_cdata: bool,
    in_dtd: bool,
    dtd_internal_subset_open: bool,
    in_external_subset: bool,
}

impl XmlWriter<Vec<u8>> {
    /// Creates an in-memory writer. Call [`Self::into_inner`] after flush to
    /// take the output bytes.
    pub fn new_vec() -> Self {
        Self::new(Vec::new())
    }
}

impl<W: Write> XmlWriter<W> {
    /// Creates a writer with the default 4 KiB buffer.
    pub fn new(sink: W) -> Self {
        Self::with_capacity(sink, DEFAULT_CAPACITY)
    }

    /// Creates a writer with indentation enabled.
    pub fn with_indent(sink: W, indent_config: IndentConfig) -> Self {
        let mut w = Self::new(sink);
        w.indent_config = Some(indent_config);
        w
    }

    /// Creates a writer with the specified buffer capacity.
    pub fn with_capacity(sink: W, buffer_capacity: usize) -> Self {
        let capacity = buffer_capacity.max(16);
        let mut w = Self {
            sink,
            buffer: Vec::with_capacity(capacity),
            send_threshold: (capacity * SEND_THRESHOLD_NUM) / SEND_THRESHOLD_DEN,
            indent_config: None,
            charset: OutputCharset::Utf8,
            xml11: false,
            standalone: false,
            pending_bom: None,
            encoded_ascii: Vec::new(),
            max_ascii_bytes: 1,
            element_stack: VecDeque::new(),
            namespace_stack: VecDeque::new(),
            pending_start_tag: false,
            has_content: false,
            has_nested_elements: false,
            at_document_start: true,
            in_cdata: false,
            in_dtd: false,
            dtd_internal_subset_open: false,
            in_external_subset: false,
        };
        w.namespace_stack.push_back(HashMap::new());
        w.init_encoded_ascii();
        w
    }

    /// Creates a writer with capacity and indentation.
    pub fn with_capacity_and_indent(
        sink: W,
        buffer_capacity: usize,
        indent_config: IndentConfig,
    ) -> Self {
        let mut w = Self::with_capacity(sink, buffer_capacity);
        w.indent_config = Some(indent_config);
        w
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Returns a mutable reference to the underlying sink.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.sink
    }

    /// Returns a reference to the underlying sink.
    pub fn get_ref(&self) -> &W {
        &self.sink
    }

    // ========== Configuration ==========

    /// Sets indentation, or `None` for compact output. Call before writing.
    pub fn set_indent_config(&mut self, indent_config: Option<IndentConfig>) {
        self.indent_config = indent_config;
    }

    /// Sets the output character encoding. Call before writing.
    pub fn set_charset(&mut self, charset: OutputCharset) {
        self.charset = charset;
        self.pending_bom = charset.pending_bom();
        self.init_encoded_ascii();
    }

    /// Sets the output encoding by IANA / Java charset name.
    ///
    /// Returns `false` if the name is not recognized.
    pub fn set_charset_name(&mut self, name: &str) -> bool {
        match OutputCharset::from_name(name) {
            Some(cs) => {
                self.set_charset(cs);
                true
            }
            None => false,
        }
    }

    /// Enables XML 1.1 escaping (CR, C1 controls, U+2028 as character refs).
    pub fn set_xml11(&mut self, xml11: bool) {
        self.xml11 = xml11;
    }

    /// When enabled, omits external DOCTYPE identifiers and inlines all DTD
    /// declarations (including the external subset) into the internal subset.
    pub fn set_standalone(&mut self, standalone: bool) {
        self.standalone = standalone;
    }

    // ========== Elements ==========

    /// Opens a start element with a local name (no namespace).
    pub fn write_start_element(&mut self, local_name: &str) -> io::Result<()> {
        self.close_pending_start_tag(false)?;

        if self.indent_config.is_some() && !self.at_document_start {
            self.write_indent()?;
        }
        self.at_document_start = false;

        self.write_raw_str("<")?;
        self.write_raw_str(local_name)?;

        self.namespace_stack.push_back(HashMap::new());
        self.element_stack.push_back(ElementInfo {
            q_name: local_name.to_string(),
        });

        self.pending_start_tag = true;
        self.has_content = false;
        self.has_nested_elements = false;

        self.send_if_needed()
    }

    /// Opens a start element, resolving a prefix from the current namespace
    /// context for `namespace_uri`.
    pub fn write_start_element_ns(&mut self, namespace_uri: &str, local_name: &str) -> io::Result<()> {
        self.close_pending_start_tag(false)?;

        if self.indent_config.is_some() && !self.at_document_start {
            self.write_indent()?;
        }
        self.at_document_start = false;

        let prefix = if !namespace_uri.is_empty() {
            self.get_prefix(namespace_uri)
        } else {
            None
        };

        let q_name = match prefix {
            Some(p) if !p.is_empty() => format!("{p}:{local_name}"),
            _ => local_name.to_string(),
        };

        self.write_raw_str("<")?;
        self.write_raw_str(&q_name)?;

        self.namespace_stack.push_back(HashMap::new());
        self.element_stack.push_back(ElementInfo { q_name });

        self.pending_start_tag = true;
        self.has_content = false;
        self.has_nested_elements = false;

        self.send_if_needed()
    }

    /// Opens a start element with an explicit prefix.
    ///
    /// Does **not** emit an `xmlns` declaration; call [`Self::write_namespace`]
    /// or [`Self::write_default_namespace`] explicitly if needed.
    pub fn write_start_element_prefixed(
        &mut self,
        prefix: &str,
        local_name: &str,
        _namespace_uri: &str,
    ) -> io::Result<()> {
        self.close_pending_start_tag(false)?;

        if self.indent_config.is_some() && !self.at_document_start {
            self.write_indent()?;
        }
        self.at_document_start = false;

        let q_name = if !prefix.is_empty() {
            format!("{prefix}:{local_name}")
        } else {
            local_name.to_string()
        };

        self.write_raw_str("<")?;
        self.write_raw_str(&q_name)?;

        self.namespace_stack.push_back(HashMap::new());
        self.element_stack.push_back(ElementInfo { q_name });

        self.pending_start_tag = true;
        self.has_content = false;
        self.has_nested_elements = false;

        self.send_if_needed()
    }

    /// Closes the current element (`/>` if empty, otherwise `</qName>`).
    pub fn write_end_element(&mut self) -> io::Result<()> {
        let element = self
            .element_stack
            .pop_back()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No open element to close"))?;
        self.namespace_stack.pop_back();

        if self.pending_start_tag && !self.has_content {
            self.write_raw_str("/>")?;
            self.pending_start_tag = false;
        } else {
            self.close_pending_start_tag(false)?;

            if self.indent_config.is_some() && self.has_nested_elements {
                self.write_indent()?;
            }

            self.write_raw_str("</")?;
            self.write_raw_str(&element.q_name)?;
            self.write_raw_str(">")?;
        }

        // Parent now has content and a nested element (matches Gonzalez).
        self.has_content = true;
        self.has_nested_elements = true;

        self.send_if_needed()
    }

    // ========== Attributes ==========

    /// Writes an attribute while a start tag is open.
    pub fn write_attribute(&mut self, local_name: &str, value: &str) -> io::Result<()> {
        if !self.pending_start_tag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_attribute() called outside of start element",
            ));
        }
        self.write_attribute_output(local_name, value)?;
        self.send_if_needed()
    }

    /// Writes a namespaced attribute, resolving the prefix from context.
    pub fn write_attribute_ns(
        &mut self,
        namespace_uri: &str,
        local_name: &str,
        value: &str,
    ) -> io::Result<()> {
        if !self.pending_start_tag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_attribute() called outside of start element",
            ));
        }

        let prefix = if !namespace_uri.is_empty() {
            self.get_prefix(namespace_uri)
        } else {
            None
        };

        let q_name = match prefix {
            Some(p) if !p.is_empty() => format!("{p}:{local_name}"),
            _ => local_name.to_string(),
        };

        self.write_attribute_output(&q_name, value)?;
        self.send_if_needed()
    }

    /// Writes a namespaced attribute with an explicit prefix.
    pub fn write_attribute_prefixed(
        &mut self,
        prefix: &str,
        local_name: &str,
        _namespace_uri: &str,
        value: &str,
    ) -> io::Result<()> {
        if !self.pending_start_tag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_attribute() called outside of start element",
            ));
        }

        let q_name = if !prefix.is_empty() {
            format!("{prefix}:{local_name}")
        } else {
            local_name.to_string()
        };

        self.write_attribute_output(&q_name, value)?;
        self.send_if_needed()
    }

    // ========== Namespaces ==========

    /// Writes `xmlns:prefix="uri"` (or default namespace if `prefix` is empty).
    /// Redundant declarations are suppressed.
    pub fn write_namespace(&mut self, prefix: &str, namespace_uri: &str) -> io::Result<()> {
        if !self.pending_start_tag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_namespace() called outside of start element",
            ));
        }
        if prefix.is_empty() {
            return self.write_default_namespace(namespace_uri);
        }
        self.write_namespace_declaration(prefix, namespace_uri)?;
        self.mutable_namespace_scope()
            .insert(prefix.to_string(), namespace_uri.to_string());
        Ok(())
    }

    /// Writes `xmlns="uri"`. Redundant declarations are suppressed.
    pub fn write_default_namespace(&mut self, namespace_uri: &str) -> io::Result<()> {
        if !self.pending_start_tag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_default_namespace() called outside of start element",
            ));
        }
        self.write_namespace_declaration("", namespace_uri)?;
        self.mutable_namespace_scope()
            .insert(String::new(), namespace_uri.to_string());
        Ok(())
    }

    // ========== Characters / markup ==========

    /// Writes character content (escaped unless inside CDATA).
    pub fn write_characters(&mut self, text: &str) -> io::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        self.close_pending_start_tag(true)?;
        if self.in_cdata {
            self.validate_cdata_content(text)?;
            self.write_raw_str(text)?;
        } else {
            self.write_escaped_characters(text)?;
        }
        self.send_if_needed()
    }

    /// Opens a CDATA section. Content written until [`Self::write_end_cdata`]
    /// is not XML-escaped.
    pub fn write_start_cdata(&mut self) -> io::Result<()> {
        self.close_pending_start_tag(true)?;
        self.in_cdata = true;
        self.write_raw_str("<![CDATA[")?;
        self.send_if_needed()
    }

    /// Closes a CDATA section.
    pub fn write_end_cdata(&mut self) -> io::Result<()> {
        self.in_cdata = false;
        self.write_raw_str("]]>")?;
        self.send_if_needed()
    }

    /// Writes a complete CDATA section.
    #[deprecated(note = "use write_start_cdata / write_characters / write_end_cdata")]
    pub fn write_cdata(&mut self, data: &str) -> io::Result<()> {
        self.write_start_cdata()?;
        self.write_characters(data)?;
        self.write_end_cdata()
    }

    /// Writes an XML comment. Double hyphens and a trailing hyphen are
    /// sanitized to keep the output well-formed.
    pub fn write_comment(&mut self, text: &str) -> io::Result<()> {
        if self.in_dtd && !self.should_write_declaration() {
            return Ok(());
        }

        self.close_pending_start_tag(true)?;

        if self.in_dtd {
            self.open_internal_subset_if_needed()?;
        }

        if self.indent_config.is_some() && !self.at_document_start && !self.in_dtd {
            self.write_indent()?;
        }
        self.at_document_start = false;

        self.write_raw_str("<!--")?;
        self.write_comment_content(text)?;
        self.write_raw_str("-->")?;

        if self.in_dtd {
            self.write_raw_str("\n")?;
        }

        self.send_if_needed()
    }

    /// Writes a processing instruction with no data.
    pub fn write_processing_instruction(&mut self, target: &str) -> io::Result<()> {
        self.write_processing_instruction_data(target, None)
    }

    /// Writes a processing instruction with optional data.
    pub fn write_processing_instruction_data(
        &mut self,
        target: &str,
        data: Option<&str>,
    ) -> io::Result<()> {
        self.close_pending_start_tag(true)?;

        if self.indent_config.is_some() && !self.at_document_start {
            self.write_indent()?;
        }
        self.at_document_start = false;

        self.write_raw_str("<?")?;
        self.write_raw_str(target)?;
        if let Some(d) = data {
            if !d.is_empty() {
                self.write_raw_str(" ")?;
                self.write_pi_data(d)?;
            }
        }
        self.write_raw_str("?>")?;

        self.send_if_needed()
    }

    /// Writes an entity reference (`&name;`).
    pub fn write_entity_ref(&mut self, name: &str) -> io::Result<()> {
        self.close_pending_start_tag(true)?;
        self.write_raw_str("&")?;
        self.write_raw_str(name)?;
        self.write_raw_str(";")?;
        self.send_if_needed()
    }

    /// Writes raw content without XML escaping (XSLT disable-output-escaping).
    ///
    /// **Warning:** can produce output that is not well-formed XML.
    pub fn write_raw(&mut self, text: &str) -> io::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        self.close_pending_start_tag(true)?;
        self.write_raw_str(text)?;
        self.send_if_needed()
    }

    // ========== DTD ==========

    /// Writes the start of a DOCTYPE declaration.
    pub fn write_start_dtd(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> io::Result<()> {
        self.in_dtd = true;
        self.dtd_internal_subset_open = false;
        self.in_external_subset = false;

        self.write_raw_str("<!DOCTYPE ")?;
        self.write_raw_str(name)?;

        if !self.standalone {
            if let Some(pub_id) = public_id {
                self.write_raw_str(" PUBLIC \"")?;
                self.write_escaped_id(pub_id)?;
                self.write_raw_str("\" \"")?;
                if let Some(sys_id) = system_id {
                    self.write_escaped_id(sys_id)?;
                }
                self.write_raw_str("\"")?;
            } else if let Some(sys_id) = system_id {
                self.write_raw_str(" SYSTEM \"")?;
                self.write_escaped_id(sys_id)?;
                self.write_raw_str("\"")?;
            }
        }

        self.send_if_needed()
    }

    /// Writes the end of a DOCTYPE declaration.
    pub fn write_end_dtd(&mut self) -> io::Result<()> {
        if self.dtd_internal_subset_open {
            self.write_raw_str("]>")?;
        } else {
            self.write_raw_str(">")?;
        }
        if self.indent_config.is_some() {
            self.write_raw_str("\n")?;
        }
        self.in_dtd = false;
        self.dtd_internal_subset_open = false;
        self.in_external_subset = false;
        self.send_if_needed()
    }

    /// Writes an element declaration in the DTD internal subset.
    pub fn write_element_decl(&mut self, name: &str, model: &str) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;
        self.write_raw_str("  <!ELEMENT ")?;
        self.write_raw_str(name)?;
        self.write_raw_str(" ")?;
        self.write_raw_str(model)?;
        self.write_raw_str(">\n")?;
        self.send_if_needed()
    }

    /// Writes an attribute declaration in the DTD internal subset.
    pub fn write_attribute_decl(
        &mut self,
        e_name: &str,
        a_name: &str,
        ty: &str,
        mode: Option<&str>,
        value: Option<&str>,
    ) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;

        self.write_raw_str("  <!ATTLIST ")?;
        self.write_raw_str(e_name)?;
        self.write_raw_str(" ")?;
        self.write_raw_str(a_name)?;
        self.write_raw_str(" ")?;
        self.write_raw_str(ty)?;
        if let Some(m) = mode {
            if !m.is_empty() {
                self.write_raw_str(" ")?;
                self.write_raw_str(m)?;
            }
        }
        if let Some(v) = value {
            self.write_raw_str(" \"")?;
            self.write_escaped_attribute_value(v)?;
            self.write_raw_str("\"")?;
        }
        self.write_raw_str(">\n")?;
        self.send_if_needed()
    }

    /// Writes an internal entity declaration. Prefix the name with `%` for a
    /// parameter entity.
    pub fn write_internal_entity_decl(&mut self, name: &str, value: &str) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;

        if let Some(rest) = name.strip_prefix('%') {
            self.write_raw_str("  <!ENTITY % ")?;
            self.write_raw_str(rest)?;
        } else {
            self.write_raw_str("  <!ENTITY ")?;
            self.write_raw_str(name)?;
        }
        self.write_raw_str(" \"")?;
        self.write_escaped_entity_value(value)?;
        self.write_raw_str("\">\n")?;
        self.send_if_needed()
    }

    /// Writes an external entity declaration. Prefix the name with `%` for a
    /// parameter entity.
    pub fn write_external_entity_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: &str,
    ) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;

        if let Some(rest) = name.strip_prefix('%') {
            self.write_raw_str("  <!ENTITY % ")?;
            self.write_raw_str(rest)?;
        } else {
            self.write_raw_str("  <!ENTITY ")?;
            self.write_raw_str(name)?;
        }
        if let Some(pub_id) = public_id {
            self.write_raw_str(" PUBLIC \"")?;
            self.write_escaped_id(pub_id)?;
            self.write_raw_str("\" \"")?;
            self.write_escaped_id(system_id)?;
            self.write_raw_str("\"")?;
        } else {
            self.write_raw_str(" SYSTEM \"")?;
            self.write_escaped_id(system_id)?;
            self.write_raw_str("\"")?;
        }
        self.write_raw_str(">\n")?;
        self.send_if_needed()
    }

    /// Writes a notation declaration.
    pub fn write_notation_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;

        self.write_raw_str("  <!NOTATION ")?;
        self.write_raw_str(name)?;
        if let Some(pub_id) = public_id {
            self.write_raw_str(" PUBLIC \"")?;
            self.write_escaped_id(pub_id)?;
            self.write_raw_str("\"")?;
            if let Some(sys_id) = system_id {
                self.write_raw_str(" \"")?;
                self.write_escaped_id(sys_id)?;
                self.write_raw_str("\"")?;
            }
        } else if let Some(sys_id) = system_id {
            self.write_raw_str(" SYSTEM \"")?;
            self.write_escaped_id(sys_id)?;
            self.write_raw_str("\"")?;
        }
        self.write_raw_str(">\n")?;
        self.send_if_needed()
    }

    /// Writes an unparsed entity declaration.
    pub fn write_unparsed_entity_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: &str,
        notation_name: &str,
    ) -> io::Result<()> {
        if !self.should_write_declaration() {
            return Ok(());
        }
        self.open_internal_subset_if_needed()?;

        self.write_raw_str("  <!ENTITY ")?;
        self.write_raw_str(name)?;
        if let Some(pub_id) = public_id {
            self.write_raw_str(" PUBLIC \"")?;
            self.write_escaped_id(pub_id)?;
            self.write_raw_str("\" \"")?;
            self.write_escaped_id(system_id)?;
            self.write_raw_str("\"")?;
        } else {
            self.write_raw_str(" SYSTEM \"")?;
            self.write_escaped_id(system_id)?;
            self.write_raw_str("\"")?;
        }
        self.write_raw_str(" NDATA ")?;
        self.write_raw_str(notation_name)?;
        self.write_raw_str(">\n")?;
        self.send_if_needed()
    }

    /// Marks subsequent DTD declarations as belonging to the external subset.
    pub fn start_external_subset(&mut self) {
        self.in_external_subset = true;
    }

    /// Ends the external DTD subset region.
    pub fn end_external_subset(&mut self) {
        self.in_external_subset = false;
    }

    // ========== Lifecycle ==========

    /// Flushes any buffered data to the sink.
    pub fn flush(&mut self) -> io::Result<()> {
        self.close_pending_start_tag(false)?;
        self.send()
    }

    /// Flushes the writer. Does **not** close the underlying sink.
    pub fn close(&mut self) -> io::Result<()> {
        self.flush()
    }

    // ========== Namespace lookup ==========

    /// Returns the prefix bound to `namespace_uri`, or `None`.
    pub fn get_prefix(&self, namespace_uri: &str) -> Option<String> {
        if namespace_uri.is_empty() {
            return None;
        }
        if namespace_uri == XML_NAMESPACE_URI {
            return Some("xml".to_string());
        }
        for scope in self.namespace_stack.iter().rev() {
            for (prefix, uri) in scope {
                if uri == namespace_uri {
                    return Some(prefix.clone());
                }
            }
        }
        None
    }

    /// Returns the namespace URI bound to `prefix`, or `None`.
    pub fn get_namespace_uri(&self, prefix: &str) -> Option<String> {
        if prefix == "xml" {
            return Some(XML_NAMESPACE_URI.to_string());
        }
        for scope in self.namespace_stack.iter().rev() {
            if let Some(uri) = scope.get(prefix) {
                return Some(uri.clone());
            }
        }
        None
    }

    /// All in-scope namespace bindings (inner scopes shadow outer). The
    /// implicit `xml` binding is not included.
    pub fn get_all_namespace_bindings(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();
        // Gonzalez iterates from top of stack (inner first); ArrayDeque
        // iterator goes from head (first pushed = outer) to tail.
        // In Java: `for (Map scope : namespaceStack)` — ArrayDeque iterates
        // from head (oldest/outer) to tail (newest/inner). And it only puts
        // if !result.containsKey — so outer wins? Wait:
        // ```
        // for (Map.Entry entry : scope.entrySet()) {
        //     if (!result.containsKey(entry.getKey())) {
        //         result.put(...);
        //     }
        // }
        // ```
        // If iterating outer-first, first put wins = outer. But typically
        // inner should shadow. Looking again at Java ArrayDeque iteration:
        // elements are returned from first to last (head to tail). Push is
        // at head for ArrayDeque.push()! So push puts at front, and
        // iteration goes head→tail = newest→oldest. So inner first, and
        // !containsKey means first (inner) wins. Good.
        //
        // Our VecDeque: push_back, iterate .iter().rev() for newest first.
        for scope in self.namespace_stack.iter().rev() {
            for (prefix, uri) in scope {
                result.entry(prefix.clone()).or_insert_with(|| uri.clone());
            }
        }
        result
    }

    // ========== Internals ==========

    fn should_write_declaration(&self) -> bool {
        if !self.in_dtd {
            return false;
        }
        if self.standalone {
            return true;
        }
        !self.in_external_subset
    }

    fn open_internal_subset_if_needed(&mut self) -> io::Result<()> {
        if !self.dtd_internal_subset_open {
            self.write_raw_str(" [\n")?;
            self.dtd_internal_subset_open = true;
        }
        Ok(())
    }

    fn mutable_namespace_scope(&mut self) -> &mut HashMap<String, String> {
        self.namespace_stack
            .back_mut()
            .expect("namespace stack always non-empty")
    }

    fn get_current_default_namespace(&self) -> Option<&str> {
        for scope in self.namespace_stack.iter().rev() {
            if let Some(uri) = scope.get("") {
                return Some(uri.as_str());
            }
        }
        None
    }

    fn get_namespace_uri_for_prefix(&self, prefix: &str) -> Option<&str> {
        for scope in self.namespace_stack.iter().rev() {
            if let Some(uri) = scope.get(prefix) {
                return Some(uri.as_str());
            }
        }
        None
    }

    fn write_namespace_declaration(&mut self, prefix: &str, uri: &str) -> io::Result<()> {
        if prefix.is_empty() {
            let current_default = self.get_current_default_namespace();
            if uri.is_empty() {
                if current_default.map(|u| u.is_empty()).unwrap_or(true) {
                    return Ok(());
                }
            } else if current_default == Some(uri) {
                return Ok(());
            }
            self.write_raw_str(" xmlns=\"")?;
        } else {
            if let Some(existing) = self.get_namespace_uri_for_prefix(prefix) {
                if existing == uri {
                    return Ok(());
                }
            }
            self.write_raw_str(" xmlns:")?;
            self.write_raw_str(prefix)?;
            self.write_raw_str("=\"")?;
        }
        self.write_escaped_namespace_uri(uri)?;
        self.write_raw_str("\"")
    }

    fn write_attribute_output(&mut self, q_name: &str, value: &str) -> io::Result<()> {
        self.write_raw_str(" ")?;
        self.write_raw_str(q_name)?;
        self.write_raw_str("=\"")?;
        self.write_escaped_attribute_value(value)?;
        self.write_raw_str("\"")
    }

    fn close_pending_start_tag(&mut self, mark_content: bool) -> io::Result<()> {
        if self.pending_start_tag {
            self.write_raw_str(">")?;
            self.pending_start_tag = false;
        }
        if mark_content {
            self.has_content = true;
        }
        Ok(())
    }

    fn write_indent(&mut self) -> io::Result<()> {
        let config = self.indent_config.expect("indent checked by caller");
        let depth = self.element_stack.len();
        let indent_size = config.indent_count() * depth;
        let nl = self.encoded_ascii[b'\n' as usize].clone();
        let indent_bytes = self.encoded_ascii[config.indent_char() as u8 as usize].clone();
        self.ensure_capacity(nl.len() + indent_size * indent_bytes.len());
        self.buffer.extend_from_slice(&nl);
        for _ in 0..indent_size {
            self.buffer.extend_from_slice(&indent_bytes);
        }
        Ok(())
    }

    fn init_encoded_ascii(&mut self) {
        self.encoded_ascii = (0u8..128)
            .map(|i| self.encode_ascii_char(i as char))
            .collect();
        self.max_ascii_bytes = self.encoded_ascii[b'<' as usize].len();
    }

    fn encode_ascii_char(&self, c: char) -> Vec<u8> {
        debug_assert!(c as u32 <= 0x7F);
        let mut out = Vec::new();
        self.encode_code_point_into(c as u32, &mut out);
        out
    }

    fn encode_code_point_into(&self, code_point: u32, out: &mut Vec<u8>) {
        match self.charset {
            OutputCharset::Utf8 => {
                let Some(ch) = char::from_u32(code_point) else {
                    return;
                };
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            OutputCharset::Utf16Be => {
                if code_point <= 0xFFFF {
                    out.extend_from_slice(&(code_point as u16).to_be_bytes());
                } else {
                    let cp = code_point - 0x10000;
                    let high = (0xD800 + (cp >> 10)) as u16;
                    let low = (0xDC00 + (cp & 0x3FF)) as u16;
                    out.extend_from_slice(&high.to_be_bytes());
                    out.extend_from_slice(&low.to_be_bytes());
                }
            }
            OutputCharset::Utf16Le => {
                if code_point <= 0xFFFF {
                    out.extend_from_slice(&(code_point as u16).to_le_bytes());
                } else {
                    let cp = code_point - 0x10000;
                    let high = (0xD800 + (cp >> 10)) as u16;
                    let low = (0xDC00 + (cp & 0x3FF)) as u16;
                    out.extend_from_slice(&high.to_le_bytes());
                    out.extend_from_slice(&low.to_le_bytes());
                }
            }
            OutputCharset::Utf32Be => {
                out.extend_from_slice(&code_point.to_be_bytes());
            }
            OutputCharset::Utf32Le => {
                out.extend_from_slice(&code_point.to_le_bytes());
            }
            OutputCharset::Iso8859_1 => {
                if code_point <= 0xFF {
                    out.push(code_point as u8);
                }
            }
            OutputCharset::UsAscii => {
                if code_point <= 0x7F {
                    out.push(code_point as u8);
                }
            }
            OutputCharset::Encoding(enc) => {
                let Some(ch) = char::from_u32(code_point) else {
                    return;
                };
                let s = ch.to_string();
                let (encoded, _, had_unmappable) = enc.encode(&s);
                if !had_unmappable {
                    out.extend_from_slice(&encoded);
                }
            }
        }
    }

    fn emit_bom_if_needed(&mut self) {
        if let Some(bom) = self.pending_bom.take() {
            self.ensure_capacity(bom.len());
            self.buffer.extend_from_slice(bom);
        }
    }

    fn write_raw_str(&mut self, s: &str) -> io::Result<()> {
        self.emit_bom_if_needed();
        if s.is_empty() {
            return Ok(());
        }
        if self.charset.is_utf8() && s.is_ascii() {
            self.ensure_capacity(s.len());
            self.buffer.extend_from_slice(s.as_bytes());
            return Ok(());
        }
        let mut encoded = Vec::new();
        for ch in s.chars() {
            self.encode_code_point_into(ch as u32, &mut encoded);
        }
        self.ensure_capacity(encoded.len());
        self.buffer.extend_from_slice(&encoded);
        Ok(())
    }

    fn validate_cdata_content(&self, text: &str) -> io::Result<()> {
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        for i in 0..len {
            let c = chars[i];
            if c == ']' && i + 2 < len && chars[i + 1] == ']' && chars[i + 2] == '>' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CDATA section must not contain \"]]>\"",
                ));
            }
            if c == '\0' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CDATA section must not contain the null character (U+0000)",
                ));
            }
            let cp = c as u32;
            if cp < 0x20 && c != '\t' && c != '\n' && c != '\r' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "CDATA section must not contain control character (U+{:X})",
                        cp
                    ),
                ));
            }
            if self.xml11 && (0x7F..=0x9F).contains(&cp) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "CDATA section must not contain C1 control character (U+{:02X})",
                        cp
                    ),
                ));
            }
        }
        Ok(())
    }

    fn write_comment_content(&mut self, text: &str) -> io::Result<()> {
        let chars: Vec<char> = text.chars().collect();
        let end = chars.len();
        let mut seg_start = 0usize;
        let mut i = 0usize;
        while i < end {
            if chars[i] == '-' && i + 1 < end && chars[i + 1] == '-' {
                let segment: String = chars[seg_start..=i].iter().collect();
                self.write_raw_str(&segment)?;
                self.write_raw_str(" ")?;
                seg_start = i + 1;
            }
            i += 1;
        }
        let segment: String = chars[seg_start..end].iter().collect();
        self.write_raw_str(&segment)?;
        if end > 0 && chars[end - 1] == '-' {
            self.write_raw_str(" ")?;
        }
        Ok(())
    }

    fn write_pi_data(&mut self, data: &str) -> io::Result<()> {
        let bytes = data.as_bytes();
        let len = bytes.len();
        let mut seg_start = 0usize;
        let mut i = 0usize;
        while i + 1 < len {
            if bytes[i] == b'?' && bytes[i + 1] == b'>' {
                self.write_raw_str(&data[seg_start..=i])?;
                self.write_raw_str(" ")?;
                seg_start = i + 1;
            }
            i += 1;
        }
        self.write_raw_str(&data[seg_start..])
    }

    fn write_escaped_id(&mut self, id: &str) -> io::Result<()> {
        let mut seg_start = 0usize;
        for (i, ch) in id.char_indices() {
            if ch == '"' {
                self.write_raw_str(&id[seg_start..i])?;
                self.write_raw_str("&quot;")?;
                seg_start = i + ch.len_utf8();
            }
        }
        self.write_raw_str(&id[seg_start..])
    }

    fn write_escaped_characters(&mut self, s: &str) -> io::Result<()> {
        for ch in s.chars() {
            self.write_escaped_code_point(ch as u32)?;
        }
        Ok(())
    }

    fn write_escaped_code_point(&mut self, code_point: u32) -> io::Result<()> {
        match code_point {
            0x3C => self.write_raw_str("&lt;"),
            0x3E => self.write_raw_str("&gt;"),
            0x26 => self.write_raw_str("&amp;"),
            cp if cp < 0x20 && cp != 0x09 && cp != 0x0A && (cp != 0x0D || self.xml11) => {
                self.write_character_reference(cp)
            }
            cp if cp < 0x80 => {
                let ascii = self.encoded_ascii[cp as usize].clone();
                self.ensure_capacity(ascii.len());
                self.buffer.extend_from_slice(&ascii);
                Ok(())
            }
            cp if self.xml11 && (0x7F..=0x9F).contains(&cp) => self.write_character_reference(cp),
            0x2028 if self.xml11 => self.write_character_reference(0x2028),
            cp => self.write_encoded_code_point(cp),
        }
    }

    fn write_escaped_attribute_value(&mut self, s: &str) -> io::Result<()> {
        for ch in s.chars() {
            let code_point = ch as u32;
            match code_point {
                0x3C => self.write_raw_str("&lt;")?,
                0x3E => self.write_raw_str("&gt;")?,
                0x26 => self.write_raw_str("&amp;")?,
                0x22 => self.write_raw_str("&quot;")?,
                0x09 | 0x0A | 0x0D => self.write_decimal_character_reference(code_point)?,
                cp if cp < 0x20 => self.write_character_reference(cp)?,
                cp if cp < 0x80 => {
                    let ascii = self.encoded_ascii[cp as usize].clone();
                    self.ensure_capacity(ascii.len());
                    self.buffer.extend_from_slice(&ascii);
                }
                cp if self.xml11 && (0x7F..=0x9F).contains(&cp) => {
                    self.write_character_reference(cp)?
                }
                0x2028 if self.xml11 => self.write_character_reference(0x2028)?,
                cp => self.write_encoded_code_point(cp)?,
            }
        }
        Ok(())
    }

    fn write_escaped_entity_value(&mut self, s: &str) -> io::Result<()> {
        for ch in s.chars() {
            let code_point = ch as u32;
            match code_point {
                0x26 => self.write_raw_str("&amp;")?,
                0x25 => self.write_raw_str("&#37;")?,
                0x22 => self.write_raw_str("&quot;")?,
                cp if cp < 0x20 && cp != 0x09 && cp != 0x0A && cp != 0x0D => {
                    self.write_character_reference(cp)?
                }
                cp if cp < 0x80 => {
                    let ascii = self.encoded_ascii[cp as usize].clone();
                    self.ensure_capacity(ascii.len());
                    self.buffer.extend_from_slice(&ascii);
                }
                cp => self.write_encoded_code_point(cp)?,
            }
        }
        Ok(())
    }

    fn write_escaped_namespace_uri(&mut self, s: &str) -> io::Result<()> {
        for ch in s.chars() {
            let code_point = ch as u32;
            match code_point {
                0x3C => self.write_raw_str("&lt;")?,
                0x3E => self.write_raw_str("&gt;")?,
                0x26 => self.write_raw_str("&amp;")?,
                0x22 => self.write_raw_str("&quot;")?,
                cp if cp < 0x20 && cp != 0x09 && cp != 0x0A && cp != 0x0D => {
                    self.write_character_reference(cp)?
                }
                cp if cp < 0x80 => {
                    let ascii = self.encoded_ascii[cp as usize].clone();
                    self.ensure_capacity(ascii.len());
                    self.buffer.extend_from_slice(&ascii);
                }
                cp if self.xml11 => self.write_hex_character_reference(cp)?,
                cp => self.write_encoded_code_point(cp)?,
            }
        }
        Ok(())
    }

    fn write_encoded_code_point(&mut self, code_point: u32) -> io::Result<()> {
        match self.charset {
            OutputCharset::Utf8 => {
                self.ensure_capacity(4);
                self.write_utf8_code_point(code_point);
                Ok(())
            }
            OutputCharset::Iso8859_1 => {
                if code_point <= 0xFF {
                    self.ensure_capacity(1);
                    self.buffer.push(code_point as u8);
                    Ok(())
                } else {
                    self.write_character_reference(code_point)
                }
            }
            OutputCharset::UsAscii => self.write_character_reference(code_point),
            OutputCharset::Utf16Be
            | OutputCharset::Utf16Le
            | OutputCharset::Utf32Be
            | OutputCharset::Utf32Le => {
                let mut tmp = Vec::new();
                self.encode_code_point_into(code_point, &mut tmp);
                self.ensure_capacity(tmp.len());
                self.buffer.extend_from_slice(&tmp);
                Ok(())
            }
            OutputCharset::Encoding(enc) => {
                let Some(ch) = char::from_u32(code_point) else {
                    return self.write_character_reference(code_point);
                };
                let s = ch.to_string();
                let (encoded, _, had_unmappable) = enc.encode(&s);
                if had_unmappable {
                    self.write_character_reference(code_point)
                } else {
                    self.ensure_capacity(encoded.len());
                    self.buffer.extend_from_slice(&encoded);
                    Ok(())
                }
            }
        }
    }

    fn write_character_reference(&mut self, code_point: u32) -> io::Result<()> {
        self.write_decimal_character_reference(code_point)
    }

    fn write_decimal_character_reference(&mut self, code_point: u32) -> io::Result<()> {
        self.write_raw_str(&format!("&#{code_point};"))
    }

    fn write_hex_character_reference(&mut self, code_point: u32) -> io::Result<()> {
        self.write_raw_str(&format!("&#x{code_point:X};"))
    }

    fn write_utf8_code_point(&mut self, code_point: u32) {
        if code_point < 0x80 {
            self.buffer.push(code_point as u8);
        } else if code_point < 0x800 {
            self.buffer.push((0xC0 | (code_point >> 6)) as u8);
            self.buffer.push((0x80 | (code_point & 0x3F)) as u8);
        } else if code_point < 0x10000 {
            self.buffer.push((0xE0 | (code_point >> 12)) as u8);
            self.buffer
                .push((0x80 | ((code_point >> 6) & 0x3F)) as u8);
            self.buffer.push((0x80 | (code_point & 0x3F)) as u8);
        } else {
            self.buffer.push((0xF0 | (code_point >> 18)) as u8);
            self.buffer
                .push((0x80 | ((code_point >> 12) & 0x3F)) as u8);
            self.buffer
                .push((0x80 | ((code_point >> 6) & 0x3F)) as u8);
            self.buffer.push((0x80 | (code_point & 0x3F)) as u8);
        }
    }

    fn ensure_capacity(&mut self, needed: usize) {
        self.buffer.reserve(needed);
    }

    fn send_if_needed(&mut self) -> io::Result<()> {
        if self.buffer.len() >= self.send_threshold {
            self.send()?;
        }
        Ok(())
    }

    fn send(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.sink.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }
}
