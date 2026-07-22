//! Document location reporting.

/// Locator for reporting parse position to handlers.
pub trait Locator {
    fn public_id(&self) -> Option<&str>;
    fn system_id(&self) -> Option<&str>;
    fn line_number(&self) -> i32;
    fn column_number(&self) -> i32;
}

/// Mutable locator owned by the scanner/parser.
#[derive(Debug, Clone, Default)]
pub struct DocumentLocator {
    pub public_id: Option<String>,
    pub system_id: Option<String>,
    pub line: i32,
    pub column: i32,
}

impl Locator for DocumentLocator {
    fn public_id(&self) -> Option<&str> {
        self.public_id.as_deref()
    }

    fn system_id(&self) -> Option<&str> {
        self.system_id.as_deref()
    }

    fn line_number(&self) -> i32 {
        self.line
    }

    fn column_number(&self) -> i32 {
        self.column
    }
}
