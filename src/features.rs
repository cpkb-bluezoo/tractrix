//! SAX-like feature and property names / defaults.

use crate::error::FeatureError;

pub const FEATURE_NAMESPACES: &str = "http://xml.org/sax/features/namespaces";
pub const FEATURE_NAMESPACE_PREFIXES: &str = "http://xml.org/sax/features/namespace-prefixes";
pub const FEATURE_VALIDATION: &str = "http://xml.org/sax/features/validation";
pub const FEATURE_EXTERNAL_GENERAL_ENTITIES: &str =
    "http://xml.org/sax/features/external-general-entities";
pub const FEATURE_EXTERNAL_PARAMETER_ENTITIES: &str =
    "http://xml.org/sax/features/external-parameter-entities";
pub const FEATURE_DISALLOW_DOCTYPE_DECL: &str =
    "http://apache.org/xml/features/disallow-doctype-decl";
pub const FEATURE_RESOLVE_DTD_URIS: &str = "http://xml.org/sax/features/resolve-dtd-uris";
pub const FEATURE_STRING_INTERNING: &str = "http://xml.org/sax/features/string-interning";
pub const FEATURE_XMLNS_URIS: &str = "http://xml.org/sax/features/xmlns-uris";
pub const FEATURE_IS_STANDALONE: &str = "http://xml.org/sax/features/is-standalone";
pub const FEATURE_XML_1_1: &str = "http://xml.org/sax/features/xml-1.1";
pub const FEATURE_SECURE_PROCESSING: &str =
    "http://javax.xml.XMLConstants/feature/secure-processing";
pub const FEATURE_UNICODE_NORMALIZATION: &str =
    "http://xml.org/sax/features/unicode-normalization-checking";
pub const FEATURE_LEXICAL_HANDLER: &str = "http://xml.org/sax/features/lexical-handler";
pub const FEATURE_PARAMETER_ENTITIES: &str = "http://xml.org/sax/features/parameter-entities";
pub const FEATURE_USE_ATTRIBUTES2: &str = "http://xml.org/sax/features/use-attributes2";
pub const FEATURE_USE_LOCATOR2: &str = "http://xml.org/sax/features/use-locator2";
pub const FEATURE_USE_ENTITY_RESOLVER2: &str =
    "http://xml.org/sax/features/use-entity-resolver2";

pub const PROPERTY_ACCESS_EXTERNAL_DTD: &str =
    "http://javax.xml.XMLConstants/property/accessExternalDTD";
pub const PROPERTY_ENTITY_EXPANSION_LIMIT: &str =
    "http://www.nongnu.org/gonzalez/properties/entity-expansion-limit";

pub const DEFAULT_EXPANSION_LIMIT: i32 = 64000;

/// Property values accepted by [`crate::Parser::set_property`].
#[derive(Debug, Clone)]
pub enum PropertyValue {
    String(String),
    Integer(i32),
}

/// Mutable feature/property store matching Gonzalez `Parser` defaults.
#[derive(Debug, Clone)]
pub struct FeatureSet {
    pub namespaces: bool,
    pub namespace_prefixes: bool,
    pub validation: bool,
    pub external_general_entities: bool,
    pub external_parameter_entities: bool,
    pub disallow_doctype_decl: bool,
    pub resolve_dtd_uris: bool,
    pub string_interning: bool,
    pub xmlns_uris: bool,
    pub is_standalone: bool,
    pub access_external_dtd: String,
    pub entity_expansion_limit: i32,
    pub parsing_started: bool,
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self {
            namespaces: true,
            namespace_prefixes: false,
            validation: false,
            external_general_entities: false,
            external_parameter_entities: false,
            disallow_doctype_decl: false,
            resolve_dtd_uris: true,
            string_interning: true,
            xmlns_uris: false,
            is_standalone: false,
            access_external_dtd: String::new(),
            entity_expansion_limit: DEFAULT_EXPANSION_LIMIT,
            parsing_started: false,
        }
    }
}

impl FeatureSet {
    pub fn get_feature(&self, name: &str) -> Result<bool, FeatureError> {
        match name {
            FEATURE_NAMESPACES => Ok(self.namespaces),
            FEATURE_NAMESPACE_PREFIXES => Ok(self.namespace_prefixes),
            FEATURE_VALIDATION => Ok(self.validation),
            FEATURE_EXTERNAL_GENERAL_ENTITIES => Ok(self.external_general_entities),
            FEATURE_EXTERNAL_PARAMETER_ENTITIES => Ok(self.external_parameter_entities),
            FEATURE_DISALLOW_DOCTYPE_DECL => Ok(self.disallow_doctype_decl),
            FEATURE_RESOLVE_DTD_URIS => Ok(self.resolve_dtd_uris),
            FEATURE_STRING_INTERNING => Ok(self.string_interning),
            FEATURE_XMLNS_URIS => Ok(self.xmlns_uris),
            FEATURE_IS_STANDALONE => Ok(self.is_standalone),
            FEATURE_XML_1_1 => Ok(true),
            FEATURE_LEXICAL_HANDLER
            | FEATURE_PARAMETER_ENTITIES
            | FEATURE_USE_ATTRIBUTES2
            | FEATURE_USE_LOCATOR2
            | FEATURE_USE_ENTITY_RESOLVER2 => Ok(true),
            FEATURE_SECURE_PROCESSING => Ok(!self.external_general_entities
                && !self.external_parameter_entities),
            FEATURE_UNICODE_NORMALIZATION => Ok(false),
            _ => Err(FeatureError::unrecognized(name)),
        }
    }

    pub fn set_feature(&mut self, name: &str, value: bool) -> Result<(), FeatureError> {
        if self.parsing_started {
            match name {
                FEATURE_NAMESPACES | FEATURE_VALIDATION => {
                    return Err(FeatureError::unsupported(name));
                }
                _ => {}
            }
        }
        match name {
            FEATURE_NAMESPACES => self.namespaces = value,
            FEATURE_NAMESPACE_PREFIXES => self.namespace_prefixes = value,
            FEATURE_VALIDATION => self.validation = value,
            FEATURE_EXTERNAL_GENERAL_ENTITIES => self.external_general_entities = value,
            FEATURE_EXTERNAL_PARAMETER_ENTITIES => self.external_parameter_entities = value,
            FEATURE_DISALLOW_DOCTYPE_DECL => self.disallow_doctype_decl = value,
            FEATURE_RESOLVE_DTD_URIS => self.resolve_dtd_uris = value,
            FEATURE_STRING_INTERNING => self.string_interning = value,
            FEATURE_XMLNS_URIS => self.xmlns_uris = value,
            FEATURE_SECURE_PROCESSING => {
                if value {
                    self.external_general_entities = false;
                    self.external_parameter_entities = false;
                    self.access_external_dtd.clear();
                } else {
                    self.external_general_entities = true;
                    self.external_parameter_entities = true;
                    self.access_external_dtd = "all".to_string();
                }
            }
            FEATURE_UNICODE_NORMALIZATION => {
                if value {
                    return Err(FeatureError::unsupported(name));
                }
            }
            FEATURE_IS_STANDALONE
            | FEATURE_XML_1_1
            | FEATURE_LEXICAL_HANDLER
            | FEATURE_PARAMETER_ENTITIES
            | FEATURE_USE_ATTRIBUTES2
            | FEATURE_USE_LOCATOR2
            | FEATURE_USE_ENTITY_RESOLVER2 => {
                return Err(FeatureError::unsupported(name));
            }
            _ => return Err(FeatureError::unrecognized(name)),
        }
        Ok(())
    }

    pub fn get_property(&self, name: &str) -> Result<PropertyValue, FeatureError> {
        match name {
            PROPERTY_ACCESS_EXTERNAL_DTD => {
                Ok(PropertyValue::String(self.access_external_dtd.clone()))
            }
            PROPERTY_ENTITY_EXPANSION_LIMIT => {
                Ok(PropertyValue::Integer(self.entity_expansion_limit))
            }
            _ => Err(FeatureError::unrecognized(name)),
        }
    }

    pub fn set_property(&mut self, name: &str, value: PropertyValue) -> Result<(), FeatureError> {
        match name {
            PROPERTY_ACCESS_EXTERNAL_DTD => match value {
                PropertyValue::String(s) => self.access_external_dtd = s,
                _ => return Err(FeatureError::unsupported(name)),
            },
            PROPERTY_ENTITY_EXPANSION_LIMIT => match value {
                PropertyValue::Integer(n) => self.entity_expansion_limit = n,
                PropertyValue::String(s) => {
                    self.entity_expansion_limit = s
                        .parse()
                        .map_err(|_| FeatureError::unsupported(name))?;
                }
            },
            _ => return Err(FeatureError::unrecognized(name)),
        }
        Ok(())
    }

    pub fn scanner_settings(&self) -> ScannerSettings {
        ScannerSettings {
            external_general_entities: self.external_general_entities,
            external_parameter_entities: self.external_parameter_entities,
            disallow_doctype_decl: self.disallow_doctype_decl,
            resolve_dtd_uris: self.resolve_dtd_uris,
            access_external_dtd: self.access_external_dtd.clone(),
            entity_expansion_limit: self.entity_expansion_limit,
        }
    }
}

/// Immutable security snapshot for Scanner construction.
#[derive(Debug, Clone)]
pub struct ScannerSettings {
    pub external_general_entities: bool,
    pub external_parameter_entities: bool,
    pub disallow_doctype_decl: bool,
    pub resolve_dtd_uris: bool,
    pub access_external_dtd: String,
    pub entity_expansion_limit: i32,
}

impl ScannerSettings {
    /// Permissive defaults for direct/test construction.
    pub fn permissive() -> Self {
        Self {
            external_general_entities: true,
            external_parameter_entities: true,
            disallow_doctype_decl: false,
            resolve_dtd_uris: true,
            access_external_dtd: "all".to_string(),
            entity_expansion_limit: i32::MAX,
        }
    }
}
