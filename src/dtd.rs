//! DTD model: element declarations, attribute declarations, content models,
//! and streaming content-model validation.
//!
//! Ported from Gonzalez `DTDModel.java`, `ElementDeclaration.java`, and
//! `ContentModelValidator.java`.

use std::collections::HashMap;
use std::fmt;

/// Content model types (`<!ELEMENT>` kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Empty,
    Any,
    Mixed,
    Element,
}

impl ContentType {
    /// Matches Java `ContentType.name()`.
    pub fn name(self) -> &'static str {
        match self {
            ContentType::Empty => "EMPTY",
            ContentType::Any => "ANY",
            ContentType::Mixed => "MIXED",
            ContentType::Element => "ELEMENT",
        }
    }
}

/// Node types in the content model tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Pcdata,
    Element,
    Sequence,
    Choice,
}

/// Occurrence indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occurrence {
    Once,
    Optional,
    ZeroOrMore,
    OneOrMore,
}

/// A node in the content model tree.
#[derive(Debug, Clone)]
pub struct ContentModel {
    pub node_type: NodeType,
    pub element_name: Option<String>,
    pub occurrence: Occurrence,
    pub children: Option<Vec<ContentModel>>,
}

impl ContentModel {
    pub fn leaf(node_type: NodeType, element_name: Option<String>, occurrence: Occurrence) -> Self {
        Self {
            node_type,
            element_name,
            occurrence,
            children: None,
        }
    }

    pub fn group(node_type: NodeType, children: Vec<ContentModel>, occurrence: Occurrence) -> Self {
        Self {
            node_type,
            element_name: None,
            occurrence,
            children: Some(children),
        }
    }
}

impl fmt::Display for ContentModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.node_type {
            NodeType::Pcdata => write!(f, "#PCDATA")?,
            NodeType::Element => write!(f, "{}", self.element_name.as_deref().unwrap_or(""))?,
            NodeType::Sequence | NodeType::Choice => {
                write!(f, "(")?;
                if let Some(children) = &self.children {
                    for (i, child) in children.iter().enumerate() {
                        if i > 0 {
                            if self.node_type == NodeType::Sequence {
                                write!(f, ", ")?;
                            } else {
                                write!(f, " | ")?;
                            }
                        }
                        write!(f, "{child}")?;
                    }
                }
                write!(f, ")")?;
            }
        }
        match self.occurrence {
            Occurrence::Optional => write!(f, "?")?,
            Occurrence::ZeroOrMore => write!(f, "*")?,
            Occurrence::OneOrMore => write!(f, "+")?,
            Occurrence::Once => {}
        }
        Ok(())
    }
}

/// A parsed `<!ELEMENT>` declaration.
#[derive(Debug, Clone)]
pub struct ElementDeclaration {
    pub name: String,
    pub content_type: ContentType,
    pub content_model: Option<ContentModel>,
    pub from_external_subset: bool,
}

impl ElementDeclaration {
    pub fn new(name: String, content_type: ContentType) -> Self {
        Self {
            name,
            content_type,
            content_model: None,
            from_external_subset: false,
        }
    }
}

/// `#REQUIRED`/`#IMPLIED`/`#FIXED`/plain-default distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    None,
    Required,
    Implied,
    Fixed,
}

/// A parsed attribute declaration (one entry of an `<!ATTLIST>`).
#[derive(Debug, Clone)]
pub struct AttDef {
    pub attr_type: String,
    pub mode: Mode,
    pub default_value: Option<String>,
    pub enumeration: Option<Vec<String>>,
    pub declared_externally: bool,
}

impl AttDef {
    pub fn is_cdata(&self) -> bool {
        self.attr_type == "CDATA"
    }
}

/// Ordered attribute list for a single element (declaration order preserved).
type AttList = Vec<(String, AttDef)>;

/// DTD model: element content models/types and attribute declarations.
#[derive(Debug, Default)]
pub struct DtdModel {
    elements: HashMap<String, ElementDeclaration>,
    attlists: HashMap<String, AttList>,
    /// Insertion order of element names in `attlists`, for stable iteration.
    attlist_order: Vec<String>,
}

impl DtdModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// First declaration wins.
    pub fn declare_element(&mut self, element: &str, decl: ElementDeclaration) -> bool {
        if self.elements.contains_key(element) {
            return false;
        }
        self.elements.insert(element.to_string(), decl);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub fn declare_attribute(
        &mut self,
        element: &str,
        attr_name: &str,
        attr_type: &str,
        mode: Mode,
        raw_default: Option<String>,
        enumeration: Option<Vec<String>>,
        declared_externally: bool,
    ) -> bool {
        if !self.attlists.contains_key(element) {
            self.attlists.insert(element.to_string(), Vec::new());
            self.attlist_order.push(element.to_string());
        }
        let attrs = self.attlists.get_mut(element).unwrap();
        if attrs.iter().any(|(n, _)| n == attr_name) {
            return false;
        }
        attrs.push((
            attr_name.to_string(),
            AttDef {
                attr_type: attr_type.to_string(),
                mode,
                default_value: raw_default,
                enumeration,
                declared_externally,
            },
        ));
        true
    }

    pub fn get_content_type(&self, element: &str) -> Option<ContentType> {
        if self.elements.is_empty() {
            return None;
        }
        self.elements.get(element).map(|d| d.content_type)
    }

    pub fn get_element_declaration(&self, element: &str) -> Option<&ElementDeclaration> {
        if self.elements.is_empty() {
            return None;
        }
        self.elements.get(element)
    }

    pub fn get_attributes(&self, element: &str) -> Option<&AttList> {
        if self.attlists.is_empty() {
            return None;
        }
        self.attlists.get(element)
    }

    pub fn get_att_def(&self, element: &str, attr_name: &str) -> Option<&AttDef> {
        self.get_attributes(element)
            .and_then(|attrs| attrs.iter().find(|(n, _)| n == attr_name).map(|(_, d)| d))
    }

    pub fn has_attribute_of_type(&self, element: &str, attr_type: &str, exclude_name: &str) -> bool {
        match self.attlists.get(element) {
            None => false,
            Some(attrs) => attrs
                .iter()
                .any(|(n, d)| n != exclude_name && d.attr_type == attr_type),
        }
    }

    pub fn has_any_defaults(&self) -> bool {
        self.attlists
            .values()
            .any(|attrs| attrs.iter().any(|(_, d)| d.default_value.is_some()))
    }

    /// Element names with ATTLIST declarations, in insertion order.
    pub fn attlist_element_names(&self) -> &[String] {
        &self.attlist_order
    }

    /// Snapshot of every ATTLIST default value needing entity resolution:
    /// `(element, attr, raw_default)`.
    pub fn collect_default_raws(&self) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for element in &self.attlist_order {
            if let Some(attrs) = self.attlists.get(element) {
                for (attr, def) in attrs {
                    if let Some(raw) = &def.default_value {
                        out.push((element.clone(), attr.clone(), raw.clone()));
                    }
                }
            }
        }
        out
    }

    /// Cloned snapshot of every declared attribute: `(element, attr, def)`,
    /// in element declaration order. Used for whole-DTD validity checks that
    /// call the handler while iterating.
    pub fn attlists_snapshot(&self) -> Vec<(String, String, AttDef)> {
        let mut out = Vec::new();
        for element in &self.attlist_order {
            if let Some(attrs) = self.attlists.get(element) {
                for (attr, def) in attrs {
                    out.push((element.clone(), attr.clone(), def.clone()));
                }
            }
        }
        out
    }

    pub fn set_default_value(&mut self, element: &str, attr_name: &str, value: String) {
        if let Some(attrs) = self.attlists.get_mut(element) {
            if let Some((_, def)) = attrs.iter_mut().find(|(n, _)| n == attr_name) {
                def.default_value = Some(value);
            }
        }
    }
}

// ===== Content model validation =====

struct MatchResult {
    matched: bool,
    position: usize,
    error: Option<String>,
}

impl MatchResult {
    fn success(position: usize) -> Self {
        Self {
            matched: true,
            position,
            error: None,
        }
    }

    fn failure(position: usize, error: impl Into<String>) -> Self {
        Self {
            matched: false,
            position,
            error: Some(error.into()),
        }
    }
}

/// Validates element content against a DTD-declared content model.
///
/// Ported from `ContentModelValidator.java`.
pub struct ContentModelValidator {
    decl: ElementDeclaration,
    children: Vec<String>,
    #[allow(dead_code)]
    has_text_content: bool,
}

impl ContentModelValidator {
    pub fn new(decl: ElementDeclaration) -> Self {
        Self {
            decl,
            children: Vec::new(),
            has_text_content: false,
        }
    }

    /// Returns an error message if validation fails, `None` if valid.
    pub fn add_text_content(&mut self, _text: &str, is_whitespace_only: bool) -> Option<String> {
        if is_whitespace_only {
            return None;
        }
        self.has_text_content = true;
        match self.decl.content_type {
            ContentType::Empty => Some(format!(
                "Element '{}' declared EMPTY but has text content",
                self.decl.name
            )),
            ContentType::Element => Some(format!(
                "Element '{}' has element-only content but contains text",
                self.decl.name
            )),
            ContentType::Any | ContentType::Mixed => None,
        }
    }

    pub fn add_child_element(&mut self, child_name: &str) -> Option<String> {
        self.children.push(child_name.to_string());
        match self.decl.content_type {
            ContentType::Empty => Some(format!(
                "Element '{}' declared EMPTY but has child element '{}'",
                self.decl.name, child_name
            )),
            ContentType::Any => None,
            ContentType::Mixed => self.validate_mixed_content(child_name),
            ContentType::Element => None,
        }
    }

    pub fn validate(&self) -> Option<String> {
        match self.decl.content_type {
            ContentType::Empty | ContentType::Any | ContentType::Mixed => None,
            ContentType::Element => self.validate_element_content(),
        }
    }

    fn validate_mixed_content(&self, child_name: &str) -> Option<String> {
        let model = self.decl.content_model.as_ref()?;
        let children = model.children.as_ref()?;
        for child in children {
            if child.node_type == NodeType::Element
                && child.element_name.as_deref() == Some(child_name)
            {
                return None;
            }
        }
        let mut allowed = String::new();
        for child in children {
            if child.node_type == NodeType::Element {
                if !allowed.is_empty() {
                    allowed.push_str(", ");
                }
                allowed.push_str(child.element_name.as_deref().unwrap_or(""));
            }
        }
        Some(format!(
            "Element '{}' not allowed in content of '{}'. Allowed: {}",
            child_name, self.decl.name, allowed
        ))
    }

    fn validate_element_content(&self) -> Option<String> {
        let model = match &self.decl.content_model {
            None => {
                if !self.children.is_empty() {
                    return Some(format!(
                        "Element '{}' should have no children",
                        self.decl.name
                    ));
                }
                return None;
            }
            Some(m) => m,
        };
        let result = self.match_content_model(model, 0);
        if !result.matched {
            return Some(format!(
                "Content of element '{}' does not match content model. {}",
                self.decl.name,
                result.error.unwrap_or_default()
            ));
        }
        if result.position < self.children.len() {
            let mut unexpected = String::new();
            for name in &self.children[result.position..] {
                if !unexpected.is_empty() {
                    unexpected.push_str(", ");
                }
                unexpected.push_str(name);
            }
            return Some(format!(
                "Unexpected elements in '{}': {}",
                self.decl.name, unexpected
            ));
        }
        None
    }

    fn match_content_model(&self, model: &ContentModel, start: usize) -> MatchResult {
        match model.node_type {
            NodeType::Element => self.match_element(model, start),
            NodeType::Sequence => self.match_sequence(model, start),
            NodeType::Choice => self.match_choice(model, start),
            NodeType::Pcdata => {
                MatchResult::failure(start, "#PCDATA not allowed in element content")
            }
        }
    }

    fn match_element(&self, model: &ContentModel, start: usize) -> MatchResult {
        let expected = model.element_name.as_deref().unwrap_or("");
        if start >= self.children.len() {
            if model.occurrence == Occurrence::Once || model.occurrence == Occurrence::OneOrMore {
                return MatchResult::failure(start, format!("Expected '{expected}'"));
            }
            return MatchResult::success(start);
        }
        let child_name = &self.children[start];
        if expected == child_name {
            let mut position = start + 1;
            match model.occurrence {
                Occurrence::Once | Occurrence::Optional => MatchResult::success(position),
                Occurrence::OneOrMore | Occurrence::ZeroOrMore => {
                    while position < self.children.len() && self.children[position] == expected {
                        position += 1;
                    }
                    MatchResult::success(position)
                }
            }
        } else if model.occurrence == Occurrence::Optional
            || model.occurrence == Occurrence::ZeroOrMore
        {
            MatchResult::success(start)
        } else {
            MatchResult::failure(
                start,
                format!("Expected '{expected}', found '{child_name}'"),
            )
        }
    }

    fn match_sequence(&self, model: &ContentModel, start: usize) -> MatchResult {
        let children = match &model.children {
            None => return MatchResult::success(start),
            Some(c) if c.is_empty() => return MatchResult::success(start),
            Some(c) => c,
        };
        let mut position = start;
        let mut sequence_matches = 0usize;
        loop {
            let sequence_start = position;
            let mut all_children_matched = true;
            for child in children {
                let result = self.match_content_model(child, position);
                if !result.matched {
                    all_children_matched = false;
                    if sequence_matches == 0 {
                        if model.occurrence == Occurrence::Optional
                            || model.occurrence == Occurrence::ZeroOrMore
                        {
                            return MatchResult::success(start);
                        }
                        return result;
                    }
                    break;
                }
                position = result.position;
            }
            if all_children_matched {
                sequence_matches += 1;
            }
            if position == sequence_start {
                break;
            }
            if model.occurrence != Occurrence::ZeroOrMore
                && model.occurrence != Occurrence::OneOrMore
            {
                break;
            }
            if position >= self.children.len() {
                break;
            }
        }
        if sequence_matches == 0
            && (model.occurrence == Occurrence::Once || model.occurrence == Occurrence::OneOrMore)
        {
            return MatchResult::failure(start, "Required sequence not found");
        }
        MatchResult::success(position)
    }

    fn match_choice(&self, model: &ContentModel, start: usize) -> MatchResult {
        let children = match &model.children {
            None => return MatchResult::success(start),
            Some(c) if c.is_empty() => return MatchResult::success(start),
            Some(c) => c,
        };
        let mut position = start;
        let mut choice_matches = 0usize;
        loop {
            let mut matched_any = false;
            let mut best_position = position;
            for child in children {
                let result = self.match_content_model(child, position);
                if result.matched && result.position > position {
                    matched_any = true;
                    best_position = best_position.max(result.position);
                }
            }
            if !matched_any {
                break;
            }
            position = best_position;
            choice_matches += 1;
            if model.occurrence != Occurrence::ZeroOrMore
                && model.occurrence != Occurrence::OneOrMore
            {
                break;
            }
            if position >= self.children.len() {
                break;
            }
        }
        if choice_matches == 0
            && (model.occurrence == Occurrence::Once || model.occurrence == Occurrence::OneOrMore)
        {
            return MatchResult::failure(start, "No valid choice found in content model");
        }
        MatchResult::success(position)
    }
}
