//! Throughput benchmark for tractrix itself, driven the same way the
//! README's push example shows: `Parser::receive(Bytes)` in a loop.
//!
//! Three configs, matching the feature-parity matrix (see benchmarks/README.md):
//!   - "ns":     namespaces on, validation off, DOCTYPE processed — compared against Expat
//!   - "ns+dtd": namespaces on, validation on, DOCTYPE processed   — compared against libxml2
//!   - "skip":   namespaces on, DOCTYPE contents skipped entirely  — compared against quick-xml,
//!               which never processes a DTD's contents at all (see `DoctypeHandling::Skip`)
//!
//! For "ns+dtd", external DTD/entity resolution is enabled (mirroring
//! `tests/conformance/xmlconf.rs`'s valid/invalid handling) with the
//! document's own path as the system ID, so sibling relative DTDs in the
//! corpus resolve — the same fix applied to the libxml2 harness.
//!
//! This binary doubles as the well-formedness/validity oracle used by
//! scripts/assemble_corpus.sh: run it over a candidate file list with
//! iterations=1 and read which files show up in the "errors" array.
//!
//! Usage: bench_tractrix <file-list> <chunk-size-bytes> <iterations> <ns|ns+dtd|skip>

use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

use bytes::Bytes;
use tractrix::{
    DoctypeHandling, EntityResolver, FeatureSet, FileEntityResolver, NamespaceFilter, ParseResult,
    Parser, XmlHandler,
};

/// A no-op sink like `DefaultHandler`, except it remembers whether
/// `error()` fired. `error()` reports recoverable validity-constraint
/// violations (SAX/Xerces convention: non-fatal, the application decides
/// what to do with them) — `DefaultHandler` correctly no-ops it, but that
/// means a plain `DefaultHandler`-based harness can never tell a validity
/// error from a clean parse. This is what makes the ns+dtd config (and the
/// oracle usage in assemble_corpus.sh) actually notice validation failures
/// instead of silently reporting every validating parse as successful.
struct RecordingHandler {
    error: Option<String>,
}

impl XmlHandler for RecordingHandler {
    fn error(&mut self, message: &str) -> ParseResult<()> {
        if self.error.is_none() {
            self.error = Some(message.to_string());
        }
        Ok(())
    }
}

struct Doc {
    path: String,
    data: Bytes,
}

fn load_corpus(list_path: &str) -> Vec<Doc> {
    let list = fs::read_to_string(list_path).unwrap_or_else(|e| {
        eprintln!("bench: cannot open file list '{list_path}': {e}");
        std::process::exit(1);
    });
    let mut docs = Vec::new();
    for line in list.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let data = fs::read(line).unwrap_or_else(|e| {
            eprintln!("bench: cannot open corpus file '{line}': {e}");
            std::process::exit(1);
        });
        docs.push(Doc {
            path: line.to_string(),
            data: Bytes::from(data),
        });
    }
    if docs.is_empty() {
        eprintln!("bench: file list '{list_path}' produced zero documents");
        std::process::exit(1);
    }
    docs
}

fn parse_one(
    data: &Bytes,
    path: &str,
    chunk_size: usize,
    features: &FeatureSet,
    use_dtd_resolver: bool,
) -> Result<(), String> {
    let mut app = RecordingHandler { error: None };
    let mut filter = NamespaceFilter::new(&mut app, false);

    let resolver: Option<Box<dyn EntityResolver>> = if use_dtd_resolver {
        Some(Box::new(FileEntityResolver::default()))
    } else {
        None
    };
    let system_id = if use_dtd_resolver {
        Some(path.to_string())
    } else {
        None
    };

    let mut parser = Parser::new(&mut filter, features, resolver, None, system_id)
        .map_err(|e| format!("{e}"))?;

    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        parser
            .receive(data.slice(offset..end))
            .map_err(|e| format!("{e}"))?;
        offset = end;
    }
    parser.close().map_err(|e| format!("{e}"))?;
    drop(parser);
    drop(filter);
    if let Some(msg) = app.error {
        return Err(msg);
    }
    Ok(())
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

fn peak_rss_bytes() -> i64 {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        #[cfg(target_os = "macos")]
        {
            usage.ru_maxrss as i64
        }
        #[cfg(not(target_os = "macos"))]
        {
            usage.ru_maxrss as i64 * 1024
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <file-list> <chunk-size-bytes> <iterations> <ns|ns+dtd|skip>",
            args[0]
        );
        return ExitCode::from(2);
    }
    let list_path = &args[1];
    let chunk_size: usize = args[2].parse().unwrap_or(0);
    let iterations: usize = args[3].parse().unwrap_or(0);
    let config = args[4].as_str();
    if chunk_size == 0 || iterations == 0 {
        eprintln!("chunk-size and iterations must be positive");
        return ExitCode::from(2);
    }
    let (validation, use_dtd_resolver, doctype_handling) = match config {
        "ns" => (false, false, DoctypeHandling::Process),
        "ns+dtd" => (true, true, DoctypeHandling::Process),
        "skip" => (false, false, DoctypeHandling::Skip),
        _ => {
            eprintln!("config must be 'ns', 'ns+dtd', or 'skip', got '{config}'");
            return ExitCode::from(2);
        }
    };

    let mut features = FeatureSet::default(); // namespaces: true, validation: false
    features.doctype_handling = doctype_handling;
    if validation {
        features.validation = true;
        features.external_general_entities = true;
        features.external_parameter_entities = true;
        features.access_external_dtd = "file".to_string();
    }

    let corpus = load_corpus(list_path);
    let total_bytes: usize = corpus.iter().map(|d| d.data.len()).sum();

    let mut wall_times = Vec::with_capacity(iterations);
    let mut errors: Vec<(String, String)> = Vec::new();

    for iter in 0..iterations {
        let start = Instant::now();
        for doc in &corpus {
            if let Err(msg) = parse_one(
                &doc.data,
                &doc.path,
                chunk_size,
                &features,
                use_dtd_resolver,
            ) {
                if iter == 0 {
                    errors.push((doc.path.clone(), msg));
                }
            }
        }
        wall_times.push(start.elapsed().as_secs_f64());
    }

    let warmup_discarded = if iterations > 1 { 1 } else { 0 };
    let mut timed: Vec<f64> = wall_times[warmup_discarded..].to_vec();
    let median_sec = median(&mut timed);
    let mb_per_sec = if median_sec > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / median_sec
    } else {
        0.0
    };
    let peak_rss = peak_rss_bytes();

    print!(
        "{{\"parser\":\"tractrix\",\"config\":\"{}\",\"file_count\":{},\"total_bytes\":{},",
        config,
        corpus.len(),
        total_bytes
    );
    print!(
        "\"iterations\":{},\"warmup_discarded\":{},\"wall_times_sec\":[",
        iterations, warmup_discarded
    );
    for (i, t) in wall_times.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{:.6}", t);
    }
    print!(
        "],\"median_sec\":{:.6},\"mb_per_sec\":{:.3},\"peak_rss_bytes\":{},",
        median_sec, mb_per_sec, peak_rss
    );
    print!("\"errors\":[");
    for (i, (file, message)) in errors.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            "{{\"file\":\"{}\",\"message\":\"{}\"}}",
            json_escape(file),
            json_escape(message)
        );
    }
    println!("]}}");

    if errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
