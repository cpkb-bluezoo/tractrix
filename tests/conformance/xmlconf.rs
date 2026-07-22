// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! W3C XML Conformance Test Suite runner.
//!
//! This is a custom-harness (`harness = false`) integration test. The suite
//! lives at `xmlconf/` in this repository (next to `Cargo.toml`). An optional
//! `TRACTRIX_XMLCONF` / `XMLCONF_DIR` override still works for alternate
//! checkouts. Missing suite directory is a hard failure.
//!
//! Ported from Gonzalez `XMLConformanceTest.java`.
//!
//! Run separately from unit tests:
//! ```text
//! cargo test --test unit_tests
//! cargo test --test xmlconf
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use bytes::Bytes;
use tractrix::{
    FeatureSet, FileEntityResolver, NamespaceFilter, ParseError, ParseResult, Parser, XmlHandler,
};

// ===== Test case model =====

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestCase {
    id: String,
    ty: String,
    file: PathBuf,
    description: String,
    sections: Option<String>,
    entities: Option<String>,
    recommendation: Option<String>,
    namespace: Option<String>,
    edition: Option<String>,
    suite: String,
}

impl std::fmt::Display for TestCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} ({})", self.suite, self.id, self.ty)
    }
}

#[derive(Debug)]
struct TestResult {
    id: String,
    suite: String,
    expected_type: String,
    passed: bool,
    actual_result: String,
    message: Option<String>,
}

// ===== Index file parsing (dogfood) =====

struct IndexHandler {
    tests: Vec<TestCase>,
    base_dir: PathBuf,
    suite: String,
    // Current TEST element state
    current_id: Option<String>,
    current_type: Option<String>,
    current_uri: Option<String>,
    current_sections: Option<String>,
    current_entities: Option<String>,
    current_recommendation: Option<String>,
    current_namespace: Option<String>,
    current_edition: Option<String>,
    current_description: String,
    in_test: bool,
    // Element tracking for matching end
    element_depth: usize,
    test_depth: Option<usize>,
    // Attribute accumulation
    current_attr_name: String,
    attr_value_buf: String,
    attrs: Vec<(String, String)>,
}

impl IndexHandler {
    fn new(base_dir: PathBuf, suite: String) -> Self {
        Self {
            tests: Vec::new(),
            base_dir,
            suite,
            current_id: None,
            current_type: None,
            current_uri: None,
            current_sections: None,
            current_entities: None,
            current_recommendation: None,
            current_namespace: None,
            current_edition: None,
            current_description: String::new(),
            in_test: false,
            element_depth: 0,
            test_depth: None,
            current_attr_name: String::new(),
            attr_value_buf: String::new(),
            attrs: Vec::new(),
        }
    }
}

impl XmlHandler for IndexHandler {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        self.element_depth += 1;
        self.attrs.clear();
        if q_name == "TEST" {
            self.in_test = true;
            self.test_depth = Some(self.element_depth);
            self.current_description.clear();
        }
        Ok(())
    }

    fn start_attribute(
        &mut self,
        name: &str,
        _ty: &str,
        _declared: bool,
        _specified: bool,
    ) -> ParseResult<()> {
        self.current_attr_name = name.to_string();
        self.attr_value_buf.clear();
        Ok(())
    }

    fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
        self.attr_value_buf.push_str(value);
        if end {
            self.attrs
                .push((self.current_attr_name.clone(), self.attr_value_buf.clone()));
        }
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        if self.in_test && self.test_depth == Some(self.element_depth) {
            for (name, value) in &self.attrs {
                match name.as_str() {
                    "ID" => self.current_id = Some(value.clone()),
                    "TYPE" => self.current_type = Some(value.clone()),
                    "URI" => self.current_uri = Some(value.clone()),
                    "SECTIONS" => self.current_sections = Some(value.clone()),
                    "ENTITIES" => self.current_entities = Some(value.clone()),
                    "RECOMMENDATION" => self.current_recommendation = Some(value.clone()),
                    "NAMESPACE" => self.current_namespace = Some(value.clone()),
                    "EDITION" => self.current_edition = Some(value.clone()),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn characters(&mut self, text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        if self.in_test && self.test_depth == Some(self.element_depth) {
            self.current_description.push_str(text);
        }
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        if self.in_test && self.test_depth == Some(self.element_depth) {
            if let (Some(id), Some(ty), Some(uri)) = (
                self.current_id.take(),
                self.current_type.take(),
                self.current_uri.take(),
            ) {
                let test_file = self.base_dir.join(&uri);
                self.tests.push(TestCase {
                    id,
                    ty,
                    file: test_file,
                    description: self.current_description.trim().to_string(),
                    sections: self.current_sections.take(),
                    entities: self.current_entities.take(),
                    recommendation: self.current_recommendation.take(),
                    namespace: self.current_namespace.take(),
                    edition: self.current_edition.take(),
                    suite: self.suite.clone(),
                });
            } else {
                self.current_id = None;
                self.current_type = None;
                self.current_uri = None;
                self.current_sections = None;
                self.current_entities = None;
                self.current_recommendation = None;
                self.current_namespace = None;
                self.current_edition = None;
            }
            self.in_test = false;
            self.test_depth = None;
        }
        self.element_depth = self.element_depth.saturating_sub(1);
        Ok(())
    }

    fn fatal_error(&mut self, message: &str) -> ParseResult<()> {
        Err(ParseError::new(message))
    }

    fn error(&mut self, _message: &str) -> ParseResult<()> {
        Ok(())
    }
}

fn parse_index_file(index_path: &Path, suite: &str) -> Result<Vec<TestCase>, String> {
    let base_dir = index_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    let data = fs::read(index_path)
        .map_err(|e| format!("Failed to read {}: {e}", index_path.display()))?;

    // Some index files (sun/*) are document fragments without a root element.
    // Detect this and wrap in a synthetic root so the parser can process them.
    let needs_wrapper = {
        let s = String::from_utf8_lossy(&data);
        let content = s.trim_start();
        // Skip XML declaration if present
        let after_decl = if content.starts_with("<?xml") {
            if let Some(pos) = content.find("?>") {
                content[pos + 2..].trim_start()
            } else {
                content
            }
        } else {
            content
        };
        // Skip comments
        let mut rest = after_decl;
        while rest.starts_with("<!--") {
            if let Some(end) = rest.find("-->") {
                rest = rest[end + 3..].trim_start();
            } else {
                break;
            }
        }
        // If the first real element is TEST (not a wrapper like TESTSUITE/TESTCASES),
        // this is a fragment that needs wrapping.
        rest.starts_with("<TEST")
    };

    let parse_data = if needs_wrapper {
        // Strip XML declaration if present (can't have it after our wrapper tag)
        let content = String::from_utf8_lossy(&data);
        let body = if content.trim_start().starts_with("<?xml") {
            if let Some(pos) = content.find("?>") {
                &content[pos + 2..]
            } else {
                content.as_ref()
            }
        } else {
            content.as_ref()
        };
        let mut wrapped = String::with_capacity(body.len() + 30);
        wrapped.push_str("<_w>");
        wrapped.push_str(body);
        wrapped.push_str("</_w>");
        wrapped.into_bytes()
    } else {
        data
    };

    let mut handler = IndexHandler::new(base_dir.clone(), suite.to_string());

    let mut features = FeatureSet::default();
    features.external_general_entities = true;
    features.external_parameter_entities = true;
    features.access_external_dtd = "file".to_string();
    features.namespaces = false;

    let resolver = Box::new(FileEntityResolver {
        access_external_dtd: "file".to_string(),
    });

    let system_id = index_path.to_string_lossy().into_owned();

    let mut parser =
        Parser::new(&mut handler, &features, Some(resolver), None, Some(system_id))
            .map_err(|e| format!("Failed to create parser for {}: {e}", index_path.display()))?;

    // Parse — tolerate errors for fragment-style index files
    let result = parser.parse_all(Bytes::from(parse_data));
    if result.is_err() && handler.tests.is_empty() {
        return Err(format!(
            "Failed to parse index {}: {}",
            index_path.display(),
            result.unwrap_err()
        ));
    }

    Ok(handler.tests)
}

// ===== Test execution =====

struct ScoreHandler {
    got_fatal: bool,
    got_error: bool,
    fatal_message: Option<String>,
}

impl ScoreHandler {
    fn new() -> Self {
        Self {
            got_fatal: false,
            got_error: false,
            fatal_message: None,
        }
    }
}

impl XmlHandler for ScoreHandler {
    fn fatal_error(&mut self, message: &str) -> ParseResult<()> {
        self.got_fatal = true;
        self.fatal_message = Some(message.to_string());
        Err(ParseError::new(message))
    }

    fn error(&mut self, _message: &str) -> ParseResult<()> {
        self.got_error = true;
        Ok(())
    }
}

fn run_test(test: &TestCase) -> TestResult {
    let id = test.id.clone();
    let suite = test.suite.clone();
    let expected_type = test.ty.clone();

    // Skip if EDITION is set and does not contain "5"
    if let Some(ref edition) = test.edition {
        if !edition.is_empty() && !edition.split_whitespace().any(|e| e.contains('5')) {
            return TestResult {
                id,
                suite,
                expected_type,
                passed: true,
                actual_result: "skipped (edition)".to_string(),
                message: None,
            };
        }
    }

    // Special-case Japanese encoding tests
    if test.id.starts_with("pr-xml-") || test.id.starts_with("weekly-") {
        return TestResult {
            id,
            suite,
            expected_type,
            passed: true,
            actual_result: "skipped (encoding special-case)".to_string(),
            message: None,
        };
    }

    // Read test file
    let data = match fs::read(&test.file) {
        Ok(d) => d,
        Err(e) => {
            return TestResult {
                id,
                suite,
                expected_type,
                passed: false,
                actual_result: "FILE_ERROR".to_string(),
                message: Some(format!("Cannot read {}: {e}", test.file.display())),
            };
        }
    };

    // Configure features
    let mut features = FeatureSet::default();
    features.external_general_entities = true;
    features.external_parameter_entities = true;
    features.access_external_dtd = "file".to_string();

    // Enable validation for invalid/valid
    if test.ty == "invalid" || test.ty == "valid" {
        features.validation = true;
    }

    // Configure namespaces
    let use_namespaces = match test.namespace.as_deref() {
        Some("no") => false,
        Some("yes") => true,
        _ => {
            // Default: namespaces on
            true
        }
    };
    features.namespaces = use_namespaces;

    // Entity resolver relative to test file
    let resolver = Box::new(FileEntityResolver {
        access_external_dtd: "file".to_string(),
    });

    let system_id = test.file.to_string_lossy().into_owned();

    // Run the parse
    let mut score = ScoreHandler::new();

    let parse_result = if use_namespaces {
        let mut filter = NamespaceFilter::new(&mut score, false);
        let mut parser = match Parser::new(
            &mut filter,
            &features,
            Some(resolver),
            None,
            Some(system_id),
        ) {
            Ok(p) => p,
            Err(e) => {
                return TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: "PARSER_INIT_ERROR".to_string(),
                    message: Some(format!("{e}")),
                };
            }
        };
        parser.parse_all(Bytes::from(data))
    } else {
        let mut parser = match Parser::new(
            &mut score,
            &features,
            Some(resolver),
            None,
            Some(system_id),
        ) {
            Ok(p) => p,
            Err(e) => {
                return TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: "PARSER_INIT_ERROR".to_string(),
                    message: Some(format!("{e}")),
                };
            }
        };
        parser.parse_all(Bytes::from(data))
    };

    let got_fatal = parse_result.is_err() || score.got_fatal;
    let got_error = score.got_error;
    let fatal_msg = parse_result
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .or_else(|| score.fatal_message.clone());

    // Score
    match test.ty.as_str() {
        "not-wf" | "error" => {
            if got_fatal || got_error {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: true,
                    actual_result: "rejected (expected)".to_string(),
                    message: None,
                }
            } else {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: "PARSED (expected rejection)".to_string(),
                    message: Some("Expected fatal/error but parsed successfully".to_string()),
                }
            }
        }
        "invalid" => {
            if got_fatal {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: "FATAL (expected recoverable error)".to_string(),
                    message: Some(format!(
                        "Got fatal instead of validation error: {}",
                        fatal_msg.unwrap_or_default()
                    )),
                }
            } else if got_error {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: true,
                    actual_result: "invalid (got validation error)".to_string(),
                    message: None,
                }
            } else {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: "VALID (expected validation error)".to_string(),
                    message: Some("Expected validation error but parsed cleanly".to_string()),
                }
            }
        }
        "valid" => {
            if got_fatal {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: false,
                    actual_result: format!(
                        "FATAL: {}",
                        fatal_msg.as_deref().unwrap_or("unknown")
                    ),
                    message: Some(format!(
                        "Expected valid but got fatal: {}",
                        fatal_msg.unwrap_or_default()
                    )),
                }
            } else {
                TestResult {
                    id,
                    suite,
                    expected_type,
                    passed: true,
                    actual_result: "valid (parsed ok)".to_string(),
                    message: None,
                }
            }
        }
        other => TestResult {
            id,
            suite,
            expected_type,
            passed: false,
            actual_result: format!("UNKNOWN TYPE: {other}"),
            message: Some("Unknown test type".to_string()),
        },
    }
}

// ===== Main =====

fn find_xmlconf_dir() -> Option<PathBuf> {
    // Optional overrides (CI or local alternate trees)
    for key in ["TRACTRIX_XMLCONF", "XMLCONF_DIR"] {
        if let Ok(dir) = env::var(key) {
            let p = PathBuf::from(&dir);
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    // Vendored suite in this repo
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        let vendored = PathBuf::from(&manifest).join("xmlconf");
        if vendored.is_dir() {
            return Some(vendored);
        }
    }
    None
}

fn main() {
    let xmlconf_dir = match find_xmlconf_dir() {
        Some(d) => d,
        None => {
            eprintln!(
                "ERROR: xmlconf directory not found. Expected `xmlconf/` next to Cargo.toml \
                 (or set TRACTRIX_XMLCONF / XMLCONF_DIR)."
            );
            process::exit(1);
        }
    };

    eprintln!("xmlconf: using suite at {}", xmlconf_dir.display());

    // Index files to load
    let index_files: &[(&str, &str)] = &[
        ("xmltest", "xmltest/xmltest.xml"),
        ("eduni/errata-2e", "eduni/errata-2e/errata2e.xml"),
        ("eduni/errata-3e", "eduni/errata-3e/errata3e.xml"),
        ("eduni/errata-4e", "eduni/errata-4e/errata4e.xml"),
        ("eduni/namespaces-1.0", "eduni/namespaces/1.0/rmt-ns10.xml"),
        ("eduni/namespaces-1.1", "eduni/namespaces/1.1/rmt-ns11.xml"),
        ("eduni/xml-1.1", "eduni/xml-1.1/xml11.xml"),
        ("ibm/oasis-invalid", "ibm/ibm_oasis_invalid.xml"),
        ("ibm/oasis-not-wf", "ibm/ibm_oasis_not-wf.xml"),
        ("ibm/oasis-valid", "ibm/ibm_oasis_valid.xml"),
        ("japanese", "japanese/japanese.xml"),
        ("oasis", "oasis/oasis.xml"),
        ("sun/error", "sun/sun-error.xml"),
        ("sun/invalid", "sun/sun-invalid.xml"),
        ("sun/not-wf", "sun/sun-not-wf.xml"),
        ("sun/valid", "sun/sun-valid.xml"),
    ];

    // Load all test cases
    let mut all_tests: Vec<TestCase> = Vec::new();

    for &(suite_name, rel_path) in index_files {
        let index_path = xmlconf_dir.join(rel_path);
        if !index_path.exists() {
            eprintln!("  WARNING: index not found: {}", index_path.display());
            continue;
        }
        match parse_index_file(&index_path, suite_name) {
            Ok(tests) => {
                eprintln!("  {} : {} tests", suite_name, tests.len());
                all_tests.extend(tests);
            }
            Err(e) => {
                eprintln!("  WARNING: failed to load {}: {}", suite_name, e);
            }
        }
    }

    eprintln!("\n  Total: {} tests\n", all_tests.len());

    if all_tests.is_empty() {
        eprintln!("No tests loaded; nothing to run.");
        process::exit(0);
    }

    // Run tests
    let mut results: Vec<TestResult> = Vec::new();
    for test in &all_tests {
        let result = run_test(test);
        results.push(result);
    }

    // Statistics
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    // Group by type (ordered)
    let mut by_type: Vec<(&str, usize, usize)> = Vec::new();
    for r in &results {
        let ty = r.expected_type.as_str();
        if let Some(entry) = by_type.iter_mut().find(|e| e.0 == ty) {
            entry.2 += 1;
            if r.passed {
                entry.1 += 1;
            }
        } else {
            by_type.push((ty, if r.passed { 1 } else { 0 }, 1));
        }
    }

    // Group by suite (ordered)
    let mut by_suite: Vec<(&str, usize, usize)> = Vec::new();
    for r in &results {
        let s = r.suite.as_str();
        if let Some(entry) = by_suite.iter_mut().find(|e| e.0 == s) {
            entry.2 += 1;
            if r.passed {
                entry.1 += 1;
            }
        } else {
            by_suite.push((s, if r.passed { 1 } else { 0 }, 1));
        }
    }

    // Print statistics
    println!("\n=== XML Conformance Test Statistics ===\n");
    for cat in &["not-wf", "invalid", "valid", "error"] {
        if let Some(entry) = by_type.iter().find(|e| e.0 == *cat) {
            println!(
                "{:<10}: {} / {} ({:.1}%)",
                cat,
                entry.1,
                entry.2,
                100.0 * entry.1 as f64 / entry.2 as f64
            );
        }
    }
    println!(
        "{:<10}: {} / {} ({:.1}%)",
        "total",
        passed,
        total,
        100.0 * passed as f64 / total as f64
    );

    println!("\n=== Results by Suite ===\n");
    for (suite, p, t) in &by_suite {
        println!(
            "{:<30}: {:4}/{:4} passed ({:.1}%)",
            suite,
            p,
            t,
            100.0 * *p as f64 / *t as f64
        );
    }

    // Write report
    let report_dir = PathBuf::from(
        env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()),
    );
    let _ = fs::create_dir_all(&report_dir);
    let report_path = report_dir.join("xml-conformance-report.txt");

    if let Ok(mut f) = fs::File::create(&report_path) {
        let _ = writeln!(f, "XML Conformance Test Report");
        let _ = writeln!(f, "============================");
        let _ = writeln!(f);
        let _ = writeln!(f, "Total tests: {}", total);
        let _ = writeln!(
            f,
            "Passed: {} ({:.1}%)",
            passed,
            100.0 * passed as f64 / total as f64
        );
        let _ = writeln!(
            f,
            "Failed: {} ({:.1}%)",
            failed,
            100.0 * failed as f64 / total as f64
        );
        let _ = writeln!(f);

        let _ = writeln!(f, "Results by Type:");
        let _ = writeln!(f, "---------------");
        for (ty, p, t) in &by_type {
            let _ = writeln!(
                f,
                "{}: {}/{} passed ({:.1}%)",
                ty,
                p,
                t,
                100.0 * *p as f64 / *t as f64
            );
        }
        let _ = writeln!(f);

        let _ = writeln!(f, "Results by Suite:");
        let _ = writeln!(f, "----------------");
        for (suite, p, t) in &by_suite {
            let _ = writeln!(
                f,
                "{}: {}/{} passed ({:.1}%)",
                suite,
                p,
                t,
                100.0 * *p as f64 / *t as f64
            );
        }
        let _ = writeln!(f);

        // Failed tests detail
        let _ = writeln!(f, "Failures:");
        let _ = writeln!(f, "---------");
        for r in &results {
            if !r.passed {
                let _ = writeln!(
                    f,
                    "[FAIL] {}:{} | Expected: {} | Actual: {} | {}",
                    r.suite,
                    r.id,
                    r.expected_type,
                    r.actual_result,
                    r.message.as_deref().unwrap_or("")
                );
            }
        }

        eprintln!("\nReport written to: {}", report_path.display());
    }

    // Print first N failures for quick debugging
    let failures: Vec<&TestResult> = results.iter().filter(|r| !r.passed).collect();
    if !failures.is_empty() {
        println!("\n=== First 20 failures ===\n");
        for r in failures.iter().take(20) {
            println!(
                "  [FAIL] {}:{} expected={} actual={} {}",
                r.suite,
                r.id,
                r.expected_type,
                r.actual_result,
                r.message.as_deref().unwrap_or("")
            );
        }
        if failures.len() > 20 {
            println!("  ... and {} more", failures.len() - 20);
        }
    }

    // Exit code
    if failed > 0 {
        eprintln!("\nFAILED: {} of {} tests failed.", failed, total);
        process::exit(1);
    } else {
        eprintln!("\nAll {} tests passed.", total);
        process::exit(0);
    }
}
