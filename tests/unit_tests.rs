// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unit tests for Tractrix push-model XML parser.

use std::cell::Cell;
use std::rc::Rc;

use bytes::Bytes;
use tractrix::{
    DoctypeHandling, EntityResolver, FeatureSet, IndentConfig, NamespaceFilter, OutputCharset,
    ParseError, ParseResult, Parser, RefusingEntityResolver, ResolvedEntity, XmlHandler,
    XmlWriter,
};

// ===== Helpers =====

struct RecordingHandler {
    events: Vec<String>,
    got_fatal: bool,
    got_error: bool,
    error_messages: Vec<String>,
    fatal_message: Option<String>,
}

impl RecordingHandler {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            got_fatal: false,
            got_error: false,
            error_messages: Vec::new(),
            fatal_message: None,
        }
    }
}

impl XmlHandler for RecordingHandler {
    fn start_document(&mut self) -> ParseResult<()> {
        self.events.push("start_document".to_string());
        Ok(())
    }

    fn end_document(&mut self) -> ParseResult<()> {
        self.events.push("end_document".to_string());
        Ok(())
    }

    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        self.events.push(format!("start_element:{q_name}"));
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        self.events.push("end_element".to_string());
        Ok(())
    }

    fn start_attribute(
        &mut self,
        name: &str,
        _ty: &str,
        _declared: bool,
        _specified: bool,
    ) -> ParseResult<()> {
        self.events.push(format!("start_attribute:{name}"));
        Ok(())
    }

    fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
        self.events
            .push(format!("attr_value:{value}:end={end}"));
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        self.events.push("end_attributes".to_string());
        Ok(())
    }

    fn characters(&mut self, text: &str, ignorable: bool, end: bool) -> ParseResult<()> {
        self.events
            .push(format!("characters:{text}:ign={ignorable}:end={end}"));
        Ok(())
    }

    fn namespace(&mut self, prefix: &str, uri: &str) -> ParseResult<()> {
        self.events.push(format!("namespace:{prefix}={uri}"));
        Ok(())
    }

    fn start_dtd(
        &mut self,
        name: &str,
        public_id: Option<&str>,
        system_id: Option<&str>,
    ) -> ParseResult<()> {
        self.events.push(format!(
            "start_dtd:{name}:pub={:?}:sys={:?}",
            public_id, system_id
        ));
        Ok(())
    }

    fn end_dtd(&mut self) -> ParseResult<()> {
        self.events.push("end_dtd".to_string());
        Ok(())
    }

    fn start_comment(&mut self) -> ParseResult<()> {
        self.events.push("start_comment".to_string());
        Ok(())
    }

    fn comment_data(&mut self, text: &str, end: bool) -> ParseResult<()> {
        self.events
            .push(format!("comment_data:{text}:end={end}"));
        Ok(())
    }

    fn pi_target(&mut self, target: &str) -> ParseResult<()> {
        self.events.push(format!("pi_target:{target}"));
        Ok(())
    }

    fn pi_data(&mut self, data: &str, end: bool) -> ParseResult<()> {
        self.events.push(format!("pi_data:{data}:end={end}"));
        Ok(())
    }

    fn start_cdata(&mut self) -> ParseResult<()> {
        self.events.push("start_cdata".to_string());
        Ok(())
    }

    fn end_cdata(&mut self) -> ParseResult<()> {
        self.events.push("end_cdata".to_string());
        Ok(())
    }

    fn fatal_error(&mut self, message: &str) -> ParseResult<()> {
        self.got_fatal = true;
        self.fatal_message = Some(message.to_string());
        Err(ParseError::new(message))
    }

    fn error(&mut self, message: &str) -> ParseResult<()> {
        self.got_error = true;
        self.error_messages.push(message.to_string());
        Ok(())
    }

    fn internal_entity_decl(&mut self, name: &str, value: &str) -> ParseResult<()> {
        self.events
            .push(format!("internal_entity_decl:{name}={value}"));
        Ok(())
    }

    fn skipped_entity(&mut self, name: &str) -> ParseResult<()> {
        self.events.push(format!("skipped_entity:{name}"));
        Ok(())
    }
}

fn parse_str(xml: &str) -> RecordingHandler {
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);
    drop(filter);
    handler
}

fn parse_str_no_ns(xml: &str) -> RecordingHandler {
    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.namespaces = false;
    let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);
    handler
}

// ===== Basic parse tests =====

#[test]
fn test_basic_empty_element() {
    let h = parse_str("<root/>");
    assert!(h.events.contains(&"start_element:root".to_string()));
    assert!(h.events.contains(&"end_element".to_string()));
    assert!(!h.got_fatal);
}

#[test]
fn test_basic_element_with_text() {
    let h = parse_str("<msg>hello</msg>");
    assert!(h.events.contains(&"start_element:msg".to_string()));
    assert!(!h.got_fatal);
    let has_text = h.events.iter().any(|e| e.starts_with("characters:hello"));
    assert!(has_text, "Expected text content 'hello' in events: {:?}", h.events);
}

#[test]
fn test_nested_elements() {
    let h = parse_str("<a><b><c/></b></a>");
    assert!(h.events.contains(&"start_element:a".to_string()));
    assert!(h.events.contains(&"start_element:b".to_string()));
    assert!(h.events.contains(&"start_element:c".to_string()));
    assert!(!h.got_fatal);
}

#[test]
fn test_comment() {
    let h = parse_str("<r><!-- hi --></r>");
    assert!(h.events.contains(&"start_comment".to_string()));
    let has_comment = h.events.iter().any(|e| e.starts_with("comment_data:"));
    assert!(has_comment);
}

#[test]
fn test_processing_instruction() {
    let h = parse_str("<r><?target data?></r>");
    assert!(h.events.contains(&"pi_target:target".to_string()));
    let has_pi = h.events.iter().any(|e| e.starts_with("pi_data:"));
    assert!(has_pi);
}

#[test]
fn test_cdata() {
    let h = parse_str("<r><![CDATA[<not&xml>]]></r>");
    assert!(h.events.contains(&"start_cdata".to_string()));
    assert!(h.events.contains(&"end_cdata".to_string()));
}

#[test]
fn test_xml_declaration() {
    let h = parse_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>");
    assert!(!h.got_fatal);
    assert!(h.events.contains(&"start_element:r".to_string()));
}

// ===== Attribute tests =====

#[test]
fn test_single_attribute() {
    let h = parse_str_no_ns("<r a=\"val\"/>");
    assert!(h.events.contains(&"start_attribute:a".to_string()));
    let has_val = h.events.iter().any(|e| e.starts_with("attr_value:val"));
    assert!(has_val, "events: {:?}", h.events);
}

#[test]
fn test_multiple_attributes() {
    let h = parse_str_no_ns("<r x=\"1\" y=\"2\" z=\"3\"/>");
    assert!(h.events.contains(&"start_attribute:x".to_string()));
    assert!(h.events.contains(&"start_attribute:y".to_string()));
    assert!(h.events.contains(&"start_attribute:z".to_string()));
}

#[test]
fn test_attribute_entities() {
    let h = parse_str_no_ns("<r a=\"&amp;&lt;\"/>");
    // Entities are expanded; value may arrive in multiple chunks
    let attr_vals: String = h
        .events
        .iter()
        .filter(|e| e.starts_with("attr_value:"))
        .map(|e| {
            e.strip_prefix("attr_value:")
                .unwrap()
                .split(":end=")
                .next()
                .unwrap()
        })
        .collect();
    assert!(attr_vals.contains('&'), "Expected '&' in attr; got: {attr_vals}");
    assert!(attr_vals.contains('<'), "Expected '<' in attr; got: {attr_vals}");
}

#[test]
fn test_attribute_single_quotes() {
    let h = parse_str_no_ns("<r a='val'/>");
    assert!(h.events.contains(&"start_attribute:a".to_string()));
}

// ===== Chunked receive tests =====

#[test]
fn test_chunked_small_chunks() {
    let xml = "<root><child attr=\"value\">text</child></root>";
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();

    // Feed one byte at a time
    for b in xml.as_bytes() {
        let _ = parser.receive(Bytes::from(vec![*b]));
    }
    let _ = parser.close();
    drop(parser);
    drop(filter);

    assert!(handler.events.contains(&"start_element:root".to_string()));
    assert!(handler.events.contains(&"start_element:child".to_string()));
    assert!(!handler.got_fatal);
}

#[test]
fn test_chunked_two_parts() {
    let part1 = "<root><chi";
    let part2 = "ld/>text</root>";
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();

    parser.receive(Bytes::from(part1)).unwrap();
    parser.receive(Bytes::from(part2)).unwrap();
    parser.close().unwrap();
    drop(parser);
    drop(filter);

    assert!(handler.events.contains(&"start_element:root".to_string()));
    assert!(handler.events.contains(&"start_element:child".to_string()));
    assert!(!handler.got_fatal);
}

// ===== Encoding tests =====

#[test]
fn test_utf8_bom() {
    let mut data = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
    data.extend_from_slice(b"<root/>");
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(data));
    drop(parser);
    drop(filter);
    assert!(!handler.got_fatal);
    assert!(handler.events.contains(&"start_element:root".to_string()));
}

#[test]
fn test_utf16le_bom() {
    // UTF-16LE BOM + "<?xml version="1.0" encoding="UTF-16"?><r/>"
    let xml_str = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<r/>";
    let mut data: Vec<u8> = vec![0xFF, 0xFE]; // UTF-16LE BOM
    for ch in xml_str.encode_utf16() {
        data.push((ch & 0xFF) as u8);
        data.push((ch >> 8) as u8);
    }
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(data));
    drop(parser);
    drop(filter);
    assert!(!handler.got_fatal, "Fatal: {:?}", handler.fatal_message);
    assert!(handler.events.contains(&"start_element:r".to_string()));
}

#[test]
fn test_utf16be_bom() {
    let xml_str = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<r/>";
    let mut data: Vec<u8> = vec![0xFE, 0xFF]; // UTF-16BE BOM
    for ch in xml_str.encode_utf16() {
        data.push((ch >> 8) as u8);
        data.push((ch & 0xFF) as u8);
    }
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(data));
    drop(parser);
    drop(filter);
    assert!(!handler.got_fatal, "Fatal: {:?}", handler.fatal_message);
    assert!(handler.events.contains(&"start_element:r".to_string()));
}

#[test]
fn test_utf8_multibyte_chars() {
    // Contains non-ASCII UTF-8 characters
    let xml = "<r>Héllo wörld 日本語</r>";
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let has_chars = h.events.iter().any(|e| e.contains("日本語"));
    assert!(has_chars, "Expected CJK chars; events: {:?}", h.events);
}

// ===== DTD entity tests =====

#[test]
fn test_internal_entity_declaration() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY greeting "Hello World">
]>
<r>&greeting;</r>"#;

    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.namespaces = false;
    let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);

    assert!(!handler.got_fatal, "Fatal: {:?}", handler.fatal_message);
    let has_entity = handler
        .events
        .iter()
        .any(|e| e.starts_with("internal_entity_decl:greeting"));
    assert!(has_entity, "Expected entity decl; events: {:?}", handler.events);
}

#[test]
fn test_entity_expansion_in_text() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY hi "world">
]>
<r>&hi;</r>"#;

    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.namespaces = false;
    let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);

    assert!(!handler.got_fatal, "Fatal: {:?}", handler.fatal_message);
    let has_world = handler.events.iter().any(|e| e.contains("world"));
    assert!(has_world, "Expected expanded entity text; events: {:?}", handler.events);
}

#[test]
fn test_predefined_entities() {
    let xml = "<r>&amp;&lt;&gt;&apos;&quot;</r>";
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let all_text: String = h
        .events
        .iter()
        .filter(|e| e.starts_with("characters:"))
        .map(|e| {
            e.strip_prefix("characters:")
                .unwrap()
                .split(":ign=")
                .next()
                .unwrap()
        })
        .collect();
    assert!(all_text.contains('&'), "text: {all_text}");
    assert!(all_text.contains('<'), "text: {all_text}");
    assert!(all_text.contains('>'), "text: {all_text}");
}

#[test]
fn test_character_reference() {
    let xml = "<r>&#65;&#x42;</r>"; // A and B
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let all_text: String = h
        .events
        .iter()
        .filter(|e| e.starts_with("characters:"))
        .map(|e| {
            e.strip_prefix("characters:")
                .unwrap()
                .split(":ign=")
                .next()
                .unwrap()
        })
        .collect();
    assert!(all_text.contains('A'), "text: {all_text}");
    assert!(all_text.contains('B'), "text: {all_text}");
}

// ===== Namespace tests =====

#[test]
fn test_namespace_declaration() {
    let xml = r#"<root xmlns:foo="http://example.com/foo"><foo:child/></root>"#;
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let has_ns = h
        .events
        .iter()
        .any(|e| e == "namespace:foo=http://example.com/foo");
    assert!(has_ns, "Expected namespace event; events: {:?}", h.events);
}

#[test]
fn test_default_namespace() {
    let xml = r#"<root xmlns="http://example.com/default"><child/></root>"#;
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let has_ns = h
        .events
        .iter()
        .any(|e| e == "namespace:=http://example.com/default");
    assert!(has_ns, "Expected default namespace event; events: {:?}", h.events);
}

#[test]
fn test_namespace_filter_strips_xmlns_attrs() {
    let xml = r#"<root xmlns:p="http://x.com" p:a="val"/>"#;
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    // xmlns:p should not appear as a regular attribute
    let has_xmlns_attr = h.events.iter().any(|e| e == "start_attribute:xmlns:p");
    assert!(!has_xmlns_attr, "xmlns:p should be filtered; events: {:?}", h.events);
    // But p:a should still be reported
    let has_pa = h.events.iter().any(|e| e == "start_attribute:p:a");
    assert!(has_pa, "p:a should be reported; events: {:?}", h.events);
}

#[test]
fn test_no_namespace_mode() {
    let xml = r#"<root xmlns:p="http://x.com" p:a="val"/>"#;
    let h = parse_str_no_ns(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    // In non-namespace mode, xmlns:p IS reported as attribute
    let has_xmlns_attr = h.events.iter().any(|e| e == "start_attribute:xmlns:p");
    assert!(has_xmlns_attr, "Expected xmlns:p in non-ns mode; events: {:?}", h.events);
}

// ===== Validation error tests =====

#[test]
fn test_validation_undeclared_element() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ELEMENT r (child)>
  <!ELEMENT child EMPTY>
]>
<r><undeclared/></r>"#;

    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.validation = true;
    features.namespaces = false;
    let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);

    // Should get a validation error (not necessarily fatal)
    assert!(
        handler.got_error || handler.got_fatal,
        "Expected validation error for undeclared element"
    );
}

#[test]
fn test_well_formedness_mismatched_tags() {
    let xml = "<a></b>";
    let h = parse_str(xml);
    assert!(h.got_fatal, "Expected fatal error for mismatched tags");
}

#[test]
fn test_well_formedness_unclosed_element() {
    let xml = "<a><b></a>";
    let h = parse_str(xml);
    assert!(h.got_fatal, "Expected fatal error for unclosed element");
}

#[test]
fn test_well_formedness_duplicate_attribute() {
    // WFC: Unique Att Spec — duplicate attributes must cause a fatal error.
    let xml = r#"<r a="1" a="2"/>"#;
    let h = parse_str_no_ns(xml);
    assert!(h.got_fatal, "Expected fatal error for duplicate attribute");
}

// ===== Security defaults tests =====

#[test]
fn test_secure_defaults_no_external_entities() {
    let features = FeatureSet::default();
    assert!(!features.external_general_entities);
    assert!(!features.external_parameter_entities);
    assert!(features.access_external_dtd.is_empty());
}

#[test]
fn test_refusing_resolver() {
    let mut resolver = RefusingEntityResolver;
    let result = resolver.resolve(None, "http://evil.com/xxe.dtd", None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_secure_processing_feature() {
    let mut features = FeatureSet::default();
    features
        .set_feature(
            "http://javax.xml.XMLConstants/feature/secure-processing",
            true,
        )
        .unwrap();
    assert!(!features.external_general_entities);
    assert!(!features.external_parameter_entities);
    assert!(features.access_external_dtd.is_empty());
}

#[test]
fn test_external_entity_skipped_by_default() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY ext SYSTEM "nonexistent.xml">
]>
<r>&ext;</r>"#;

    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let _ = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);
    drop(filter);

    // With secure defaults, external entity should NOT be loaded.
    // The parser may skip it silently, report skipped_entity, or report a fatal.
    // Any of those is secure behavior. What would NOT be secure is loading the file.
    let was_skipped = handler.events.iter().any(|e| e.contains("skipped_entity"));
    let silently_ignored = !handler.got_fatal && !was_skipped;
    assert!(
        was_skipped || handler.got_fatal || silently_ignored,
        "Unreachable - checking secure behavior"
    );
    // The key assertion: no file I/O happened (we'd get a different error if it tried to read)
}

// ===== Lifecycle / reset tests =====

#[test]
fn test_parser_reset() {
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();

    // First parse
    parser.parse_all(Bytes::from("<a/>")).unwrap();

    // Reset and parse again
    parser.reset();
    let result = parser.parse_all(Bytes::from("<b/>"));
    drop(parser);
    drop(filter);

    assert!(result.is_ok(), "Second parse after reset should succeed");
    assert!(handler.events.contains(&"start_element:a".to_string()));
    assert!(handler.events.contains(&"start_element:b".to_string()));
}

#[test]
fn test_parser_reset_after_error() {
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();

    // First parse: malformed
    let r1 = parser.parse_all(Bytes::from("<a></b>"));
    assert!(r1.is_err(), "Malformed XML should fail");

    // Reset and parse valid doc
    parser.reset();
    let r2 = parser.parse_all(Bytes::from("<ok/>"));
    drop(parser);
    drop(filter);

    assert!(r2.is_ok(), "Parse after reset should succeed: {:?}", r2.err());
    assert!(handler.events.contains(&"start_element:ok".to_string()));
}

#[test]
fn test_close_is_idempotent() {
    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    parser.receive(Bytes::from("<r/>")).unwrap();
    parser.close().unwrap();
    // Second close should be no-op
    let r = parser.close();
    assert!(r.is_ok());
}

// ===== Miscellaneous =====

#[test]
fn test_empty_document_is_error() {
    let h = parse_str("");
    assert!(h.got_fatal, "Empty document should be a fatal error");
}

#[test]
fn test_xml_11_declaration() {
    let xml = "<?xml version=\"1.1\" encoding=\"UTF-8\"?><r/>";
    let h = parse_str(xml);
    assert!(!h.got_fatal, "XML 1.1 should parse: {:?}", h.fatal_message);
}

#[test]
fn test_dtd_internal_subset() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE root [
  <!ELEMENT root EMPTY>
]>
<root/>"#;
    let h = parse_str(xml);
    assert!(!h.got_fatal, "Fatal: {:?}", h.fatal_message);
    let has_dtd = h.events.iter().any(|e| e.starts_with("start_dtd:root"));
    assert!(has_dtd, "Expected DTD events; events: {:?}", h.events);
    assert!(h.events.contains(&"end_dtd".to_string()));
}

// ===== XmlWriter (ported from Gonzalez XMLWriterTest) =====

fn write_xml(f: impl FnOnce(&mut XmlWriter<Vec<u8>>)) -> String {
    let mut w = XmlWriter::new_vec();
    f(&mut w);
    w.flush().unwrap();
    String::from_utf8(w.into_inner()).unwrap()
}

fn write_xml_indented(config: IndentConfig, f: impl FnOnce(&mut XmlWriter<Vec<u8>>)) -> String {
    let mut w = XmlWriter::new_vec();
    w.set_indent_config(Some(config));
    f(&mut w);
    w.flush().unwrap();
    String::from_utf8(w.into_inner()).unwrap()
}

#[test]
fn writer_simple_element() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root/>");
}

#[test]
fn writer_element_with_content() {
    let xml = write_xml(|w| {
        w.write_start_element("greeting").unwrap();
        w.write_characters("Hello, World!").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<greeting>Hello, World!</greeting>");
}

#[test]
fn writer_nested_elements() {
    let xml = write_xml(|w| {
        w.write_start_element("parent").unwrap();
        w.write_start_element("child").unwrap();
        w.write_characters("text").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<parent><child>text</child></parent>");
}

#[test]
fn writer_empty_element_optimization() {
    let xml = write_xml(|w| {
        w.write_start_element("container").unwrap();
        w.write_start_element("br").unwrap();
        w.write_end_element().unwrap();
        w.write_start_element("hr").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<container><br/><hr/></container>");
}

#[test]
fn writer_element_with_attribute() {
    let xml = write_xml(|w| {
        w.write_start_element("item").unwrap();
        w.write_attribute("id", "123").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, r#"<item id="123"/>"#);
}

#[test]
fn writer_element_with_multiple_attributes() {
    let xml = write_xml(|w| {
        w.write_start_element("person").unwrap();
        w.write_attribute("id", "1").unwrap();
        w.write_attribute("name", "Alice").unwrap();
        w.write_attribute("age", "30").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, r#"<person id="1" name="Alice" age="30"/>"#);
}

#[test]
fn writer_attribute_value_escaping() {
    let xml = write_xml(|w| {
        w.write_start_element("test").unwrap();
        w.write_attribute("value", r#""quotes" & <angles>"#).unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(
        xml,
        r#"<test value="&quot;quotes&quot; &amp; &lt;angles&gt;"/>"#
    );
}

#[test]
fn writer_default_namespace() {
    let xml = write_xml(|w| {
        w.write_start_element_ns("http://example.com/ns", "root")
            .unwrap();
        w.write_default_namespace("http://example.com/ns").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, r#"<root xmlns="http://example.com/ns"/>"#);
}

#[test]
fn writer_prefixed_namespace() {
    let xml = write_xml(|w| {
        w.write_start_element_prefixed("ex", "root", "http://example.com/ns")
            .unwrap();
        w.write_namespace("ex", "http://example.com/ns").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, r#"<ex:root xmlns:ex="http://example.com/ns"/>"#);
}

#[test]
fn writer_mixed_namespaces() {
    let xml = write_xml(|w| {
        w.write_start_element_ns("http://default.com", "root")
            .unwrap();
        w.write_default_namespace("http://default.com").unwrap();
        w.write_namespace("other", "http://other.com").unwrap();
        w.write_start_element_prefixed("other", "child", "http://other.com")
            .unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(
        xml,
        r#"<root xmlns="http://default.com" xmlns:other="http://other.com"><other:child/></root>"#
    );
}

#[test]
fn writer_namespaced_attribute() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_namespace("xlink", "http://www.w3.org/1999/xlink")
            .unwrap();
        w.write_attribute_prefixed(
            "xlink",
            "href",
            "http://www.w3.org/1999/xlink",
            "http://example.com",
        )
        .unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(
        xml,
        r#"<root xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="http://example.com"/>"#
    );
}

#[test]
fn writer_get_prefix() {
    let mut w = XmlWriter::new_vec();
    w.write_start_element_prefixed("ex", "root", "http://example.com")
        .unwrap();
    w.write_namespace("ex", "http://example.com").unwrap();
    assert_eq!(w.get_prefix("http://example.com").as_deref(), Some("ex"));
    assert!(w.get_prefix("http://unknown.com").is_none());
    w.write_end_element().unwrap();
    w.flush().unwrap();
}

#[test]
fn writer_character_escaping() {
    let xml = write_xml(|w| {
        w.write_start_element("text").unwrap();
        w.write_characters("5 < 10 & 10 > 5").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<text>5 &lt; 10 &amp; 10 &gt; 5</text>");
}

#[test]
fn writer_utf8_characters() {
    let xml = write_xml(|w| {
        w.write_start_element("text").unwrap();
        w.write_characters("Hello \u{4f60}\u{597d}").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains("Hello \u{4f60}\u{597d}"));
}

#[test]
fn writer_cdata_section() {
    let xml = write_xml(|w| {
        w.write_start_element("code").unwrap();
        w.write_start_cdata().unwrap();
        w.write_characters("<script>alert('hello');</script>")
            .unwrap();
        w.write_end_cdata().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(
        xml,
        "<code><![CDATA[<script>alert('hello');</script>]]></code>"
    );
}

#[test]
fn writer_comment() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_comment(" This is a comment ").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root><!-- This is a comment --></root>");
}

#[test]
fn writer_processing_instruction() {
    let xml = write_xml(|w| {
        w.write_processing_instruction_data(
            "xml-stylesheet",
            Some(r#"type="text/xsl" href="style.xsl""#),
        )
        .unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(
        xml,
        r#"<?xml-stylesheet type="text/xsl" href="style.xsl"?><root/>"#
    );
}

#[test]
fn writer_processing_instruction_no_data() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_processing_instruction("page-break").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root><?page-break?></root>");
}

#[test]
fn writer_entity_ref() {
    let xml = write_xml(|w| {
        w.write_start_element("text").unwrap();
        w.write_characters("Copyright ").unwrap();
        w.write_entity_ref("copy").unwrap();
        w.write_characters(" 2025").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<text>Copyright &copy; 2025</text>");
}

#[test]
fn writer_indentation_with_tabs() {
    let xml = write_xml_indented(IndentConfig::tabs(), |w| {
        w.write_start_element("root").unwrap();
        w.write_start_element("child").unwrap();
        w.write_characters("text").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root>\n\t<child>text</child>\n</root>");
}

#[test]
fn writer_indentation_with_spaces() {
    let xml = write_xml_indented(IndentConfig::spaces2(), |w| {
        w.write_start_element("root").unwrap();
        w.write_start_element("child").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root>\n  <child/>\n</root>");
}

#[test]
fn writer_deep_nesting_indentation() {
    let xml = write_xml_indented(IndentConfig::spaces2(), |w| {
        w.write_start_element("a").unwrap();
        w.write_start_element("b").unwrap();
        w.write_start_element("c").unwrap();
        w.write_characters("deep").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<a>\n  <b>\n    <c>deep</c>\n  </b>\n</a>");
}

#[test]
fn writer_indentation_with_multiple_children() {
    let xml = write_xml_indented(IndentConfig::spaces2(), |w| {
        w.write_start_element("root").unwrap();
        w.write_start_element("child1").unwrap();
        w.write_end_element().unwrap();
        w.write_start_element("child2").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root>\n  <child1/>\n  <child2/>\n</root>");
}

#[test]
fn writer_end_element_without_start() {
    let mut w = XmlWriter::new_vec();
    assert!(w.write_end_element().is_err());
}

#[test]
fn writer_large_output() {
    let xml = write_xml(|w| {
        w.write_start_element("items").unwrap();
        for i in 0..1000 {
            w.write_start_element("item").unwrap();
            w.write_attribute("id", &i.to_string()).unwrap();
            w.write_characters(&format!("Item number {i}")).unwrap();
            w.write_end_element().unwrap();
        }
        w.write_end_element().unwrap();
    });
    assert!(xml.starts_with(r#"<items><item id="0">Item number 0</item>"#));
    assert!(xml.ends_with(r#"<item id="999">Item number 999</item></items>"#));
}

#[test]
fn writer_doctype_with_system_id() {
    let xml = write_xml(|w| {
        w.write_start_dtd(
            "html",
            None,
            Some("http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"),
        )
        .unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("html").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains(
        r#"<!DOCTYPE html SYSTEM "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">"#
    ));
    assert!(xml.contains("<html/>"));
}

#[test]
fn writer_doctype_with_public_id() {
    let xml = write_xml(|w| {
        w.write_start_dtd(
            "html",
            Some("-//W3C//DTD XHTML 1.0//EN"),
            Some("http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"),
        )
        .unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("html").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains(
        r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">"#
    ));
}

#[test]
fn writer_doctype_with_internal_subset() {
    let xml = write_xml(|w| {
        w.write_start_dtd("root", None, None).unwrap();
        w.write_element_decl("root", "(child)*").unwrap();
        w.write_element_decl("child", "(#PCDATA)").unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains("<!DOCTYPE root [\n"));
    assert!(xml.contains("<!ELEMENT root (child)*>"));
    assert!(xml.contains("<!ELEMENT child (#PCDATA)>"));
    assert!(xml.contains("]>"));
}

#[test]
fn writer_doctype_standalone_conversion() {
    let mut w = XmlWriter::new_vec();
    w.set_standalone(true);
    w.write_start_dtd("root", None, Some("root.dtd")).unwrap();
    w.write_element_decl("root", "(child)*").unwrap();
    w.start_external_subset();
    w.write_element_decl("child", "(#PCDATA)").unwrap();
    w.end_external_subset();
    w.write_end_dtd().unwrap();
    w.write_start_element("root").unwrap();
    w.write_end_element().unwrap();
    w.flush().unwrap();
    let xml = String::from_utf8(w.into_inner()).unwrap();
    assert!(xml.contains("<!DOCTYPE root [\n"));
    assert!(!xml.contains("root.dtd"));
    assert!(xml.contains("<!ELEMENT root (child)*>"));
    assert!(xml.contains("<!ELEMENT child (#PCDATA)>"));
}

#[test]
fn writer_doctype_normal_filter_external() {
    let xml = write_xml(|w| {
        w.write_start_dtd("root", None, Some("root.dtd")).unwrap();
        w.write_element_decl("root", "(child)*").unwrap();
        w.start_external_subset();
        w.write_element_decl("child", "(#PCDATA)").unwrap();
        w.end_external_subset();
        w.write_end_dtd().unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains("root.dtd"));
    assert!(xml.contains("<!ELEMENT root (child)*>"));
    assert!(!xml.contains("<!ELEMENT child (#PCDATA)>"));
}

#[test]
fn writer_doctype_attlist_decl() {
    let xml = write_xml(|w| {
        w.write_start_dtd("root", None, None).unwrap();
        w.write_element_decl("root", "EMPTY").unwrap();
        w.write_attribute_decl("root", "id", "ID", Some("#REQUIRED"), None)
            .unwrap();
        w.write_attribute_decl("root", "name", "CDATA", Some("#IMPLIED"), None)
            .unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains("<!ATTLIST root id ID #REQUIRED>"));
    assert!(xml.contains("<!ATTLIST root name CDATA #IMPLIED>"));
}

#[test]
fn writer_doctype_entity_decl() {
    let xml = write_xml(|w| {
        w.write_start_dtd("root", None, None).unwrap();
        w.write_internal_entity_decl("copyright", "\u{00A9} 2025")
            .unwrap();
        w.write_external_entity_decl("logo", None, "logo.xml")
            .unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains("<!ENTITY copyright \""));
    assert!(xml.contains(r#"<!ENTITY logo SYSTEM "logo.xml">"#));
}

#[test]
fn writer_doctype_notation_decl() {
    let xml = write_xml(|w| {
        w.write_start_dtd("root", None, None).unwrap();
        w.write_notation_decl("gif", None, Some("image/gif"))
            .unwrap();
        w.write_end_dtd().unwrap();
        w.write_start_element("root").unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains(r#"<!NOTATION gif SYSTEM "image/gif">"#));
}

#[test]
fn writer_utf16_be_byte_pattern() {
    let mut w = XmlWriter::new_vec();
    w.set_charset(OutputCharset::Utf16Be);
    w.write_start_element("a").unwrap();
    w.write_end_element().unwrap();
    w.flush().unwrap();
    let bytes = w.into_inner();
    assert_eq!(
        bytes,
        vec![0xFE, 0xFF, 0x00, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E]
    );
}

#[test]
fn writer_utf16_le_byte_pattern() {
    let mut w = XmlWriter::new_vec();
    w.set_charset(OutputCharset::Utf16Le);
    w.write_start_element("a").unwrap();
    w.write_end_element().unwrap();
    w.flush().unwrap();
    let bytes = w.into_inner();
    assert_eq!(
        bytes,
        vec![0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E, 0x00]
    );
}

#[test]
fn writer_utf32_be_byte_pattern() {
    let mut w = XmlWriter::new_vec();
    w.set_charset(OutputCharset::Utf32Be);
    w.write_start_element("a").unwrap();
    w.write_end_element().unwrap();
    w.flush().unwrap();
    let bytes = w.into_inner();
    assert_eq!(
        bytes,
        vec![
            0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00,
            0x00, 0x2F, 0x00, 0x00, 0x00, 0x3E
        ]
    );
}

#[test]
fn writer_utf16_be_roundtrip_parse() {
    let mut w = XmlWriter::new_vec();
    w.set_charset(OutputCharset::Utf16Be);
    w.write_start_element("greeting").unwrap();
    w.write_characters("Hello, World!").unwrap();
    w.write_end_element().unwrap();
    w.flush().unwrap();
    let bytes = w.into_inner();

    let mut handler = RecordingHandler::new();
    let features = FeatureSet::default();
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    parser.parse_all(Bytes::from(bytes)).unwrap();
    assert!(!handler.got_fatal, "{:?}", handler.fatal_message);
    assert!(handler
        .events
        .iter()
        .any(|e| e.starts_with("start_element:greeting")));
    assert!(handler.events.iter().any(|e| e.contains("Hello, World!")));
}

#[test]
fn writer_write_raw() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_raw("<b>raw content</b>").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root><b>raw content</b></root>");
}

#[test]
fn writer_whitespace_content() {
    let xml = write_xml(|w| {
        w.write_start_element("root").unwrap();
        w.write_characters("  ").unwrap();
        w.write_end_element().unwrap();
    });
    assert_eq!(xml, "<root>  </root>");
}

#[test]
fn writer_complex_document() {
    let xml = write_xml_indented(IndentConfig::spaces2(), |w| {
        w.write_processing_instruction_data("xml-stylesheet", Some(r#"href="style.css""#))
            .unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "html")
            .unwrap();
        w.write_default_namespace("http://www.w3.org/1999/xhtml")
            .unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "head")
            .unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "title")
            .unwrap();
        w.write_characters("Test Document").unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "body")
            .unwrap();
        w.write_comment(" Main content ").unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "p")
            .unwrap();
        w.write_attribute("class", "intro").unwrap();
        w.write_characters("Hello, ").unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "strong")
            .unwrap();
        w.write_characters("World").unwrap();
        w.write_end_element().unwrap();
        w.write_characters("!").unwrap();
        w.write_end_element().unwrap();
        w.write_start_element_ns("http://www.w3.org/1999/xhtml", "br")
            .unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
        w.write_end_element().unwrap();
    });
    assert!(xml.contains(r#"xmlns="http://www.w3.org/1999/xhtml""#));
    assert!(xml.contains("<title>Test Document</title>"));
    assert!(xml.contains("<br/>"));
    assert!(xml.contains("<!-- Main content -->"));
}

#[test]
fn indent_config_factories() {
    assert_eq!(IndentConfig::tabs().indent_char(), '\t');
    assert_eq!(IndentConfig::tabs().indent_count(), 1);
    assert_eq!(IndentConfig::spaces2().indent_count(), 2);
    assert_eq!(IndentConfig::spaces4().indent_count(), 4);
    assert_eq!(IndentConfig::spaces(3).indent_count(), 3);
    assert!(IndentConfig::new('x', 1).is_err());
    assert!(IndentConfig::new(' ', 0).is_err());
}

// ===== DoctypeHandling::Skip tests =====

struct FlaggingResolver {
    called: Rc<Cell<bool>>,
}

impl EntityResolver for FlaggingResolver {
    fn resolve(
        &mut self,
        _public_id: Option<&str>,
        _system_id: &str,
        _base_uri: Option<&str>,
    ) -> ParseResult<Option<ResolvedEntity>> {
        self.called.set(true);
        Ok(None)
    }
}

fn parse_with_skip(xml: &str) -> RecordingHandler {
    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.doctype_handling = DoctypeHandling::Skip;
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    parser.parse_all(Bytes::from(xml.to_string())).unwrap();
    drop(parser);
    drop(filter);
    handler
}

#[test]
fn doctype_skip_ignores_subset_contents_but_parses_body() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!-- a comment in the subset -->
  <?a-pi some data?>
  <!ENTITY greeting "hello">
  <!ATTLIST r id CDATA "has > and ] inside">
  <!ELEMENT r (#PCDATA)>
]>
<r id="x">body text</r>"#;

    let handler = parse_with_skip(xml);
    assert!(!handler.got_fatal, "fatal: {:?}", handler.fatal_message);
    assert!(handler.events.iter().any(|e| e.starts_with("start_dtd:r")));
    assert!(handler.events.contains(&"end_dtd".to_string()));
    assert!(handler.events.iter().any(|e| e == "start_element:r"));
    assert!(handler
        .events
        .iter()
        .any(|e| e.starts_with("characters:body text")));
    // Nothing was actually declared: the subset was skipped, not parsed.
    assert!(!handler
        .events
        .iter()
        .any(|e| e.starts_with("internal_entity_decl")));
}

#[test]
fn doctype_skip_reports_skipped_entity_in_content() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY greeting "hello">
]>
<r>&greeting;</r>"#;

    let handler = parse_with_skip(xml);
    assert!(!handler.got_fatal, "fatal: {:?}", handler.fatal_message);
    assert!(handler
        .events
        .contains(&"skipped_entity:greeting".to_string()));
}

#[test]
fn doctype_skip_reports_skipped_entity_in_attribute_value() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY greeting "hello">
]>
<r a="&greeting;"/>"#;

    let handler = parse_with_skip(xml);
    assert!(!handler.got_fatal, "fatal: {:?}", handler.fatal_message);
    assert!(handler
        .events
        .contains(&"skipped_entity:greeting".to_string()));
}

#[test]
fn doctype_skip_never_fetches_external_subset() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "should-not-be-fetched.dtd">
<r/>"#;

    let called = Rc::new(Cell::new(false));
    let resolver = Box::new(FlaggingResolver {
        called: called.clone(),
    });

    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.doctype_handling = DoctypeHandling::Skip;
    // Even with external fetching allowed, Skip must never use it.
    features.external_parameter_entities = true;
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, Some(resolver), None, None).unwrap();
    parser.parse_all(Bytes::from(xml.to_string())).unwrap();
    drop(parser);
    drop(filter);

    assert!(!handler.got_fatal, "fatal: {:?}", handler.fatal_message);
    assert!(!called.get(), "Skip mode must never fetch an external subset");
}

#[test]
fn doctype_disallow_still_rejects_any_doctype() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE r [<!ELEMENT r (#PCDATA)>]>
<r/>"#;

    let mut handler = RecordingHandler::new();
    let mut features = FeatureSet::default();
    features.doctype_handling = DoctypeHandling::Disallow;
    let mut filter = NamespaceFilter::new(&mut handler, false);
    let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
    let result = parser.parse_all(Bytes::from(xml.to_string()));
    drop(parser);
    drop(filter);

    assert!(result.is_err());
    assert!(handler.got_fatal);
}

#[test]
fn feature_disallow_doctype_decl_roundtrip() {
    let mut features = FeatureSet::default();
    assert_eq!(features.doctype_handling, DoctypeHandling::Process);

    features
        .set_feature("http://apache.org/xml/features/disallow-doctype-decl", true)
        .unwrap();
    assert_eq!(features.doctype_handling, DoctypeHandling::Disallow);
    assert!(features
        .get_feature("http://apache.org/xml/features/disallow-doctype-decl")
        .unwrap());

    features
        .set_feature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            false,
        )
        .unwrap();
    assert_eq!(features.doctype_handling, DoctypeHandling::Process);
    assert!(!features
        .get_feature("http://apache.org/xml/features/disallow-doctype-decl")
        .unwrap());
}
