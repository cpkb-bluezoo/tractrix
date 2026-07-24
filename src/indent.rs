// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Indentation configuration for XML output.
//!
//! Ported from Gonzalez `IndentConfig.java`.

use std::fmt;

/// Configuration for XML output indentation.
///
/// Specifies the character to use for indentation (space or tab) and how many
/// times to repeat it per indentation level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IndentConfig {
    indent_char: char,
    indent_count: usize,
}

impl IndentConfig {
    /// Creates an indent configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `indent_char` is not space or tab, or if `indent_count`
    /// is zero.
    pub fn new(indent_char: char, indent_count: usize) -> Result<Self, &'static str> {
        if indent_char != ' ' && indent_char != '\t' {
            return Err("Indent character must be space or tab");
        }
        if indent_count == 0 {
            return Err("Indent count must be positive");
        }
        Ok(Self {
            indent_char,
            indent_count,
        })
    }

    /// Returns the character to use for indentation (`' '` or `'\t'`).
    pub fn indent_char(self) -> char {
        self.indent_char
    }

    /// Returns how many times to repeat the indent character per level.
    pub fn indent_count(self) -> usize {
        self.indent_count
    }

    /// Single tab per level.
    pub fn tabs() -> Self {
        Self {
            indent_char: '\t',
            indent_count: 1,
        }
    }

    /// Two spaces per level.
    pub fn spaces2() -> Self {
        Self {
            indent_char: ' ',
            indent_count: 2,
        }
    }

    /// Four spaces per level.
    pub fn spaces4() -> Self {
        Self {
            indent_char: ' ',
            indent_count: 4,
        }
    }

    /// The specified number of spaces per level.
    ///
    /// # Panics
    ///
    /// Panics if `count` is zero.
    pub fn spaces(count: usize) -> Self {
        Self::new(' ', count).expect("indent count must be positive")
    }
}

impl fmt::Display for IndentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.indent_char == '\t' {
            write!(f, "IndentConfig(tab x {})", self.indent_count)
        } else {
            write!(f, "IndentConfig({} spaces)", self.indent_count)
        }
    }
}
