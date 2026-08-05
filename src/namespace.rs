// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Namespace processing.
//!
//! Ported from Gonzalez `NamespaceFilter.java` and `NamespaceScopeTracker.java`.
//!
//! [`Scanner`](crate::scanner::Scanner) always reports `xmlns`/`xmlns:prefix`
//! as plain attributes (namespace-unaware behaviour). A namespace-aware
//! consumer places a [`NamespaceFilter`] in front of it to translate those
//! into [`XmlHandler::namespace`] events, applying the Namespace Constraints.

use std::collections::HashMap;
use std::rc::Rc;

use crate::error::ParseResult;
use crate::handler::XmlHandler;
use crate::locator::Locator;
use crate::names::InternedStringPool;

/// XML namespace URI (pre-bound to the `xml` prefix).
pub const XML_NAMESPACE_URI: &str = "http://www.w3.org/XML/1998/namespace";
/// XMLNS namespace URI (pre-bound to the `xmlns` prefix).
pub const XMLNS_NAMESPACE_URI: &str = "http://www.w3.org/2000/xmlns/";

// ===== NamespaceScopeTracker =====

#[derive(Default)]
struct Scope {
    bindings: HashMap<String, Rc<str>>,
    declaration_count: usize,
}

/// Manages prefix-to-URI mappings with per-element scoping.
///
/// Ported from `NamespaceScopeTracker.java` (the binding/scope machinery;
/// `processName`/QName pooling is not needed by the Rust pipeline).
pub struct NamespaceScopeTracker {
    scopes: Vec<Scope>,
    scope_depth: isize,
    active_bindings: HashMap<String, Rc<str>>,
    intern_pool: Option<InternedStringPool>,
}

impl Default for NamespaceScopeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceScopeTracker {
    pub fn new() -> Self {
        let mut t = Self {
            scopes: Vec::new(),
            scope_depth: -1,
            active_bindings: HashMap::new(),
            // On by default: every declare_prefix call goes through this,
            // and once InternedStringPool returns Rc<str> a hit is a
            // refcount bump — there's no document shape where this is
            // worse than the uninterned fallback, only ones where it's a
            // real win (any URI redeclared more than once).
            intern_pool: Some(InternedStringPool::new()),
        };
        t.push_context();
        t.declare_prefix("xml", XML_NAMESPACE_URI);
        t.declare_prefix("xmlns", XMLNS_NAMESPACE_URI);
        t
    }

    pub fn set_intern_pool(&mut self, pool: InternedStringPool) {
        self.intern_pool = Some(pool);
    }

    pub fn push_context(&mut self) {
        self.scope_depth += 1;
        let depth = self.scope_depth as usize;
        if depth < self.scopes.len() {
            let scope = &mut self.scopes[depth];
            if scope.declaration_count > 0 {
                scope.bindings.clear();
                scope.declaration_count = 0;
            }
        } else {
            self.scopes.push(Scope::default());
        }
    }

    pub fn pop_context(&mut self) {
        if self.scope_depth < 0 {
            panic!("Cannot pop root namespace context");
        }
        let depth = self.scope_depth as usize;
        if self.scopes[depth].declaration_count > 0 {
            let prefixes: Vec<String> = self.scopes[depth].bindings.keys().cloned().collect();
            for prefix in prefixes {
                let outer = self.find_binding_in_outer_scopes(&prefix, self.scope_depth - 1);
                match outer {
                    Some(uri) => {
                        self.active_bindings.insert(prefix, uri);
                    }
                    None => {
                        self.active_bindings.remove(&prefix);
                    }
                }
            }
        }
        self.scope_depth -= 1;
    }

    pub fn declare_prefix(&mut self, prefix: &str, uri: &str) -> bool {
        let uri: Rc<str> = match &mut self.intern_pool {
            Some(pool) => pool.intern(uri),
            None => Rc::from(uri),
        };
        let depth = self.scope_depth as usize;
        let scope = &mut self.scopes[depth];
        if scope.bindings.get(prefix) == Some(&uri) {
            return false;
        }
        scope.bindings.insert(prefix.to_string(), Rc::clone(&uri));
        scope.declaration_count += 1;
        self.active_bindings.insert(prefix.to_string(), uri);
        true
    }

    /// Returns the URI bound to `prefix`, or `None` if unbound (an empty URI
    /// counts as unbound per XML Namespaces 1.1).
    pub fn get_uri(&self, prefix: &str) -> Option<&str> {
        match self.active_bindings.get(prefix) {
            Some(uri) if !uri.is_empty() => Some(uri.as_ref()),
            _ => None,
        }
    }

    pub fn reset(&mut self) {
        self.scopes.clear();
        self.active_bindings.clear();
        self.scope_depth = -1;
        self.push_context();
        self.declare_prefix("xml", XML_NAMESPACE_URI);
        self.declare_prefix("xmlns", XMLNS_NAMESPACE_URI);
    }

    fn find_binding_in_outer_scopes(&self, prefix: &str, max_depth: isize) -> Option<Rc<str>> {
        let mut i = max_depth;
        while i >= 0 {
            if let Some(uri) = self.scopes[i as usize].bindings.get(prefix) {
                return Some(Rc::clone(uri));
            }
            i -= 1;
        }
        None
    }
}

// ===== NamespaceFilter =====

/// [`XmlHandler`] filter that reroutes `xmlns`/`xmlns:prefix` attributes to
/// [`XmlHandler::namespace`] on a delegate, passing all other events through.
///
/// Also performs Namespace Constraint validation: QName syntax, prefix binding,
/// expanded-name uniqueness for attributes, and prefix unbinding rules.
///
/// Ported from `NamespaceFilter.java` with integrated SAXAdapter-style NSC.
pub struct NamespaceFilter<'a> {
    delegate: &'a mut dyn XmlHandler,
    xml11: bool,
    namespace_prefixes: bool,
    #[allow(dead_code)]
    xmlns_uris: bool,
    current_attr_name: String,
    current_attr_type: String,
    current_attr_declared: bool,
    current_attr_specified: bool,
    current_is_namespace_decl: bool,
    value_first_chunk: bool,
    value_builder: String,
    tracker: NamespaceScopeTracker,
    element_qname: String,
    /// Raw qNames of non-xmlns attributes on the current element, for deferred
    /// prefix-binding and expanded-name duplicate checks at end_attributes.
    pending_attr_qnames: Vec<String>,
}

impl<'a> NamespaceFilter<'a> {
    pub fn new(delegate: &'a mut dyn XmlHandler, xml11: bool) -> Self {
        Self {
            delegate,
            xml11,
            namespace_prefixes: false,
            xmlns_uris: false,
            current_attr_name: String::new(),
            current_attr_type: String::new(),
            current_attr_declared: false,
            current_attr_specified: false,
            current_is_namespace_decl: false,
            value_first_chunk: false,
            value_builder: String::new(),
            tracker: NamespaceScopeTracker::new(),
            element_qname: String::new(),
            pending_attr_qnames: Vec::new(),
        }
    }

    pub fn set_namespace_prefixes(&mut self, value: bool) {
        self.namespace_prefixes = value;
    }

    pub fn set_xmlns_uris(&mut self, value: bool) {
        self.xmlns_uris = value;
    }

    fn validate_qname(&mut self, name: &str) -> ParseResult<()> {
        if name.is_empty() {
            return self.delegate.fatal_error("Empty name is not a valid QName");
        }
        let colon_pos = name.find(':');
        match colon_pos {
            None => {
                if !is_ncname(name) {
                    return self.delegate.fatal_error(&format!(
                        "NSC: \"{name}\" is not a valid NCName"
                    ));
                }
            }
            Some(pos) => {
                let prefix = &name[..pos];
                let local = &name[pos + 1..];
                if prefix.is_empty() || local.is_empty() {
                    return self.delegate.fatal_error(&format!(
                        "NSC: \"{name}\" is not a valid QName (empty prefix or local part)"
                    ));
                }
                if local.contains(':') {
                    return self.delegate.fatal_error(&format!(
                        "NSC: \"{name}\" is not a valid QName (multiple colons)"
                    ));
                }
                if !is_ncname(prefix) {
                    return self.delegate.fatal_error(&format!(
                        "NSC: prefix \"{prefix}\" in \"{name}\" is not a valid NCName"
                    ));
                }
                if !is_ncname(local) {
                    return self.delegate.fatal_error(&format!(
                        "NSC: local part \"{local}\" in \"{name}\" is not a valid NCName"
                    ));
                }
            }
        }
        Ok(())
    }

    fn split_qname(name: &str) -> (&str, &str) {
        match name.find(':') {
            Some(pos) => (&name[..pos], &name[pos + 1..]),
            None => ("", name),
        }
    }

    fn declare_namespace(&mut self, attr_name: &str, uri: &str) -> ParseResult<()> {
        let prefix: String;
        if attr_name == "xmlns" {
            if uri == XML_NAMESPACE_URI {
                return self
                    .delegate
                    .fatal_error("Cannot bind default namespace to reserved XML namespace URI");
            }
            if uri == XMLNS_NAMESPACE_URI {
                return self
                    .delegate
                    .fatal_error("Cannot bind default namespace to reserved xmlns namespace URI");
            }
            self.validate_namespace_uri(uri)?;
            prefix = String::new();
        } else {
            prefix = attr_name[6..].to_string(); // skip "xmlns:"
            if prefix.is_empty() {
                return self
                    .delegate
                    .fatal_error("Namespace prefix must not be empty after xmlns:");
            }
            if uri.is_empty() && !self.xml11 {
                return self.delegate.fatal_error(&format!(
                    "Prefix unbinding (xmlns:{prefix}=\"\") is only allowed in XML 1.1"
                ));
            }
            if prefix == "xml" && uri != XML_NAMESPACE_URI {
                return self.delegate.fatal_error(&format!(
                    "Cannot bind 'xml' prefix to namespace other than {XML_NAMESPACE_URI}"
                ));
            }
            if prefix == "xmlns" {
                return self.delegate.fatal_error("Cannot declare 'xmlns' prefix");
            }
            if uri == XML_NAMESPACE_URI && prefix != "xml" {
                return self.delegate.fatal_error(&format!(
                    "Cannot bind prefix '{prefix}' to reserved XML namespace URI"
                ));
            }
            if uri == XMLNS_NAMESPACE_URI {
                return self.delegate.fatal_error(&format!(
                    "Cannot bind prefix '{prefix}' to reserved xmlns namespace URI"
                ));
            }
            self.validate_namespace_uri(uri)?;
        }
        self.tracker.declare_prefix(&prefix, uri);
        self.delegate.namespace(&prefix, uri)?;
        if self.namespace_prefixes {
            self.delegate.start_attribute(
                attr_name,
                &self.current_attr_type,
                self.current_attr_declared,
                self.current_attr_specified,
            )?;
            self.delegate.attribute_value_content(uri, true)?;
        }
        Ok(())
    }

    fn validate_namespace_uri(&mut self, uri: &str) -> ParseResult<()> {
        if uri.is_empty() {
            return Ok(());
        }
        if !self.xml11 && !is_ascii_only(uri) {
            self.delegate.error(&format!(
                "Namespace name '{uri}' is an IRI, not a URI (Namespaces in XML 1.0 \u{00a7}2)"
            ))?;
        }
        if !is_absolute_uri(uri) {
            self.delegate.error(&format!(
                "Namespace name '{uri}' is not an absolute URI (Namespaces in XML 1.0 \u{00a7}2, deprecated)"
            ))?;
        }
        Ok(())
    }
}

fn is_ncname_start_char(c: char) -> bool {
    if c == ':' {
        return false;
    }
    let u = c as u32;
    c == '_'
        || c.is_ascii_uppercase()
        || c.is_ascii_lowercase()
        || (0xC0..=0xD6).contains(&u)
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

fn is_ncname_char(c: char) -> bool {
    if is_ncname_start_char(c) {
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

fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        None => false,
        Some(c) if !is_ncname_start_char(c) => false,
        _ => chars.all(is_ncname_char),
    }
}

fn is_absolute_uri(uri: &str) -> bool {
    let bytes = uri.as_bytes();
    let colon = match uri.find(':') {
        Some(i) => i,
        None => return false,
    };
    if colon == 0 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for &c in &bytes[1..colon] {
        if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.') {
            return false;
        }
    }
    true
}

fn is_ascii_only(s: &str) -> bool {
    s.bytes().all(|b| b <= 0x7F)
}

impl XmlHandler for NamespaceFilter<'_> {
    fn set_locator(&mut self, locator: &dyn Locator) {
        self.delegate.set_locator(locator);
    }

    fn set_xml11(&mut self, xml11: bool) {
        self.xml11 = xml11;
        self.delegate.set_xml11(xml11);
    }

    fn start_document(&mut self) -> ParseResult<()> {
        self.delegate.start_document()
    }

    fn end_document(&mut self) -> ParseResult<()> {
        self.delegate.end_document()
    }

    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        self.tracker.push_context();
        self.element_qname.clear();
        self.element_qname.push_str(q_name);
        self.pending_attr_qnames.clear();
        self.validate_qname(q_name)?;
        self.delegate.start_element(q_name)
    }

    fn namespace(&mut self, _prefix: &str, _uri: &str) -> ParseResult<()> {
        self.delegate.fatal_error(
            "namespace() received by NamespaceFilter - upstream should only emit plain attributes",
        )
    }

    fn start_attribute(
        &mut self,
        name: &str,
        ty: &str,
        declared: bool,
        specified: bool,
    ) -> ParseResult<()> {
        self.current_is_namespace_decl = name == "xmlns" || name.starts_with("xmlns:");
        if self.current_is_namespace_decl {
            // Only the xmlns-declaration path reads these back (in
            // attribute_value_content / declare_namespace) — the common
            // case below passes name/ty straight through without storing
            // them, so allocating copies here would be pure waste.
            self.current_attr_name.clear();
            self.current_attr_name.push_str(name);
            self.current_attr_type.clear();
            self.current_attr_type.push_str(ty);
            self.current_attr_declared = declared;
            self.current_attr_specified = specified;
            self.value_first_chunk = true;
            Ok(())
        } else {
            self.validate_qname(name)?;
            if name.contains(':') {
                self.pending_attr_qnames.push(name.to_string());
            }
            self.delegate.start_attribute(name, ty, declared, specified)
        }
    }

    fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
        if !self.current_is_namespace_decl {
            return self.delegate.attribute_value_content(value, end);
        }
        if self.value_first_chunk && end {
            let name = std::mem::take(&mut self.current_attr_name);
            let r = self.declare_namespace(&name, value);
            self.current_attr_name = name;
            return r;
        }
        if self.value_first_chunk {
            self.value_builder.clear();
            self.value_first_chunk = false;
        }
        self.value_builder.push_str(value);
        if end {
            let name = std::mem::take(&mut self.current_attr_name);
            let val = std::mem::take(&mut self.value_builder);
            let r = self.declare_namespace(&name, &val);
            self.current_attr_name = name;
            self.value_builder = val;
            return r;
        }
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        let elem = std::mem::take(&mut self.element_qname);
        let (prefix, _local) = Self::split_qname(&elem);
        if !prefix.is_empty() && self.tracker.get_uri(prefix).is_none() {
            let r = self.delegate.fatal_error(&format!(
                "NSC: Element prefix \"{prefix}\" is not bound to a namespace URI"
            ));
            self.element_qname = elem;
            return r;
        }
        self.element_qname = elem;

        let attrs = std::mem::take(&mut self.pending_attr_qnames);
        // Borrowed straight from `attrs`/`self.tracker` — this is a
        // per-element scratch list, never read after this loop, so there's
        // nothing to gain by copying into owned Strings.
        let mut expanded: Vec<(&str, &str)> = Vec::with_capacity(attrs.len());
        for qn in attrs.iter() {
            let colon = match qn.find(':') {
                Some(c) => c,
                None => continue,
            };
            let prefix = &qn[..colon];
            let local = &qn[colon + 1..];
            match self.tracker.get_uri(prefix) {
                None => {
                    let msg = format!(
                        "NSC: Attribute prefix \"{prefix}\" is not bound to a namespace URI"
                    );
                    self.pending_attr_qnames = attrs;
                    return self.delegate.fatal_error(&msg);
                }
                Some(uri) => {
                    if expanded.iter().any(|(u, l)| *u == uri && *l == local) {
                        let msg = format!(
                            "NSC: Duplicate attribute by expanded name ({{{uri}}}{local}) — \
                             attributes must be unique by namespace URI + local name"
                        );
                        self.pending_attr_qnames = attrs;
                        return self.delegate.fatal_error(&msg);
                    }
                    expanded.push((uri, local));
                }
            }
        }
        self.pending_attr_qnames = attrs;
        self.delegate.end_attributes()
    }

    fn characters(&mut self, text: &str, ignorable: bool, end: bool) -> ParseResult<()> {
        self.delegate.characters(text, ignorable, end)
    }

    fn end_element(&mut self) -> ParseResult<()> {
        self.tracker.pop_context();
        self.delegate.end_element()
    }

    fn start_comment(&mut self) -> ParseResult<()> {
        self.delegate.start_comment()
    }

    fn comment_data(&mut self, text: &str, end: bool) -> ParseResult<()> {
        self.delegate.comment_data(text, end)
    }

    fn start_cdata(&mut self) -> ParseResult<()> {
        self.delegate.start_cdata()
    }

    fn end_cdata(&mut self) -> ParseResult<()> {
        self.delegate.end_cdata()
    }

    fn start_dtd(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> ParseResult<()> {
        self.delegate.start_dtd(name, public_id, system_id)
    }

    fn end_dtd(&mut self) -> ParseResult<()> {
        self.delegate.end_dtd()
    }

    fn start_entity(&mut self, name: &str) -> ParseResult<()> {
        self.delegate.start_entity(name)
    }

    fn end_entity(&mut self, name: &str) -> ParseResult<()> {
        self.delegate.end_entity(name)
    }

    fn notation_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> ParseResult<()> {
        self.delegate.notation_decl(name, public_id, system_id)
    }

    fn unparsed_entity_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
        notation_name: &str,
    ) -> ParseResult<()> {
        self.delegate
            .unparsed_entity_decl(name, public_id, system_id, notation_name)
    }

    fn element_decl(&mut self, name: &str, model: &str) -> ParseResult<()> {
        self.delegate.element_decl(name, model)
    }

    fn attribute_decl(
        &mut self,
        e_name: &str,
        a_name: &str,
        ty: &str,
        mode: &str,
        value: Option<&str>,
    ) -> ParseResult<()> {
        self.delegate.attribute_decl(e_name, a_name, ty, mode, value)
    }

    fn internal_entity_decl(&mut self, name: &str, value: &str) -> ParseResult<()> {
        self.delegate.internal_entity_decl(name, value)
    }

    fn external_entity_decl(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: &str,
    ) -> ParseResult<()> {
        self.delegate.external_entity_decl(name, public_id, system_id)
    }

    fn skipped_entity(&mut self, name: &str) -> ParseResult<()> {
        self.delegate.skipped_entity(name)
    }

    fn pi_target(&mut self, target: &str) -> ParseResult<()> {
        self.delegate.pi_target(target)
    }

    fn pi_data(&mut self, data: &str, end: bool) -> ParseResult<()> {
        self.delegate.pi_data(data, end)
    }

    fn save_buffers(&mut self) -> ParseResult<()> {
        self.delegate.save_buffers()
    }

    fn fatal_error(&mut self, message: &str) -> ParseResult<()> {
        self.delegate.fatal_error(message)
    }

    fn error(&mut self, message: &str) -> ParseResult<()> {
        self.delegate.error(message)
    }
}
