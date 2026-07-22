//! Parse errors for Tractrix.

use std::fmt;

/// Result type for parse operations that may fail fatally.
pub type ParseResult<T> = Result<T, ParseError>;

/// Fatal parse error (well-formedness failure or I/O/config failure).
///
/// Recoverable validation errors are reported via [`crate::XmlHandler::error`]
/// and do not stop parsing.
#[derive(Debug, Clone)]
pub struct ParseError {
    message: String,
    pub line: i32,
    pub column: i32,
    pub system_id: Option<String>,
    pub public_id: Option<String>,
}

impl ParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            line: -1,
            column: -1,
            system_id: None,
            public_id: None,
        }
    }

    pub fn with_location(mut self, line: i32, column: i32) -> Self {
        self.line = line;
        self.column = column;
        self
    }

    pub fn with_ids(mut self, public_id: Option<String>, system_id: Option<String>) -> Self {
        self.public_id = public_id;
        self.system_id = system_id;
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if self.line >= 0 {
            write!(f, " (line {}, column {})", self.line, self.column)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

/// Feature/property configuration error (unrecognized or unsupported).
#[derive(Debug, Clone)]
pub struct FeatureError {
    message: String,
}

impl FeatureError {
    pub fn unrecognized(name: &str) -> Self {
        Self {
            message: format!("Feature/property not recognized: {name}"),
        }
    }

    pub fn unsupported(name: &str) -> Self {
        Self {
            message: format!("Feature/property not supported: {name}"),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FeatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FeatureError {}
