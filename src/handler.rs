//! Native XML event handler (Gonzalez `XMLHandler`).

use crate::error::{ParseError, ParseResult};
use crate::locator::Locator;

/// Streaming structural event vocabulary emitted by the Scanner.
///
/// Matches Gonzalez `XMLHandler`: raw qNames, streamed attribute values /
/// text / PI data / comments with an explicit `end` flag, optional
/// namespace events from a namespace-aware filter stage.
pub trait XmlHandler {
    fn set_locator(&mut self, _locator: &dyn Locator) {}

    fn set_xml11(&mut self, _xml11: bool) {}

    fn start_document(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn end_document(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn start_element(&mut self, _q_name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn namespace(&mut self, _prefix: &str, _uri: &str) -> ParseResult<()> {
        Ok(())
    }

    fn start_attribute(
        &mut self,
        name: &str,
        ty: &str,
        declared: bool,
        specified: bool,
    ) -> ParseResult<()> {
        let _ = (name, ty, declared, specified);
        Ok(())
    }

    fn attribute_value_content(&mut self, _value: &str, _end: bool) -> ParseResult<()> {
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn characters(&mut self, _text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn start_comment(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn comment_data(&mut self, _text: &str, _end: bool) -> ParseResult<()> {
        Ok(())
    }

    fn start_cdata(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn end_cdata(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn start_dtd(
        &mut self,
        _name: &str,
        _public_id: Option<&str>,
        _system_id: Option<&str>,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn end_dtd(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn start_entity(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn end_entity(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn notation_decl(
        &mut self,
        _name: &str,
        _public_id: Option<&str>,
        _system_id: Option<&str>,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn unparsed_entity_decl(
        &mut self,
        _name: &str,
        _public_id: Option<&str>,
        _system_id: Option<&str>,
        _notation_name: &str,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn element_decl(&mut self, _name: &str, _model: &str) -> ParseResult<()> {
        Ok(())
    }

    fn attribute_decl(
        &mut self,
        _e_name: &str,
        _a_name: &str,
        _ty: &str,
        _mode: &str,
        _value: Option<&str>,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn internal_entity_decl(&mut self, _name: &str, _value: &str) -> ParseResult<()> {
        Ok(())
    }

    fn external_entity_decl(
        &mut self,
        _name: &str,
        _public_id: Option<&str>,
        _system_id: &str,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn skipped_entity(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn pi_target(&mut self, _target: &str) -> ParseResult<()> {
        Ok(())
    }

    fn pi_data(&mut self, _data: &str, _end: bool) -> ParseResult<()> {
        Ok(())
    }

    fn save_buffers(&mut self) -> ParseResult<()> {
        Ok(())
    }

    /// Reports a fatal error. Returning `Err` stops parsing.
    fn fatal_error(&mut self, message: &str) -> ParseResult<()> {
        Err(ParseError::new(message))
    }

    /// Recoverable error (typically a validity constraint violation).
    fn error(&mut self, _message: &str) -> ParseResult<()> {
        Ok(())
    }
}

/// No-op handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultHandler;

impl XmlHandler for DefaultHandler {}
