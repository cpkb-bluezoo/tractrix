//! Throughput benchmark for quick-xml: namespace-aware (`NsReader`), no DTD
//! validation (quick-xml doesn't validate against a DTD, matching the
//! feature-parity matrix). quick-xml has no push API — it pulls via
//! `BufRead` — so [`ChunkedByteReader`] below caps each underlying pull at
//! `chunk_size` bytes, giving it the same I/O granularity the push-based
//! harnesses (Expat, libxml2, tractrix) are fed with explicitly.
//!
//! Usage: bench_quick_xml <file-list> <chunk-size-bytes> <iterations>

use std::env;
use std::fs;
use std::io::{self, BufRead, Read};
use std::process::ExitCode;
use std::time::Instant;

use quick_xml::events::Event;
use quick_xml::reader::NsReader;

struct ChunkedByteReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk_size: usize,
    buf: Vec<u8>,
    buf_pos: usize,
    buf_len: usize,
}

impl<'a> ChunkedByteReader<'a> {
    fn new(data: &'a [u8], chunk_size: usize) -> Self {
        Self {
            data,
            pos: 0,
            chunk_size: chunk_size.max(1),
            buf: vec![0u8; chunk_size.max(1)],
            buf_pos: 0,
            buf_len: 0,
        }
    }
}

impl<'a> Read for ChunkedByteReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl<'a> BufRead for ChunkedByteReader<'a> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.buf_pos == self.buf_len {
            let remaining = self.data.len() - self.pos;
            let n = remaining.min(self.chunk_size);
            self.buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            self.buf_pos = 0;
            self.buf_len = n;
        }
        Ok(&self.buf[self.buf_pos..self.buf_len])
    }

    fn consume(&mut self, amt: usize) {
        self.buf_pos = (self.buf_pos + amt).min(self.buf_len);
    }
}

struct Doc {
    path: String,
    data: Vec<u8>,
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
            data,
        });
    }
    if docs.is_empty() {
        eprintln!("bench: file list '{list_path}' produced zero documents");
        std::process::exit(1);
    }
    docs
}

/// Parses one document, discarding every event. Returns Err(message) on the
/// first parse error.
fn parse_one(data: &[u8], chunk_size: usize) -> Result<(), String> {
    let reader_src = ChunkedByteReader::new(data, chunk_size);
    let mut reader = NsReader::from_reader(reader_src);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_resolved_event_into(&mut buf) {
            Ok((_, Event::Eof)) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(format!("{e}")),
        }
    }
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
    if args.len() != 4 {
        eprintln!(
            "usage: {} <file-list> <chunk-size-bytes> <iterations>",
            args[0]
        );
        return ExitCode::from(2);
    }
    let list_path = &args[1];
    let chunk_size: usize = args[2].parse().unwrap_or(0);
    let iterations: usize = args[3].parse().unwrap_or(0);
    if chunk_size == 0 || iterations == 0 {
        eprintln!("chunk-size and iterations must be positive");
        return ExitCode::from(2);
    }

    let corpus = load_corpus(list_path);
    let total_bytes: usize = corpus.iter().map(|d| d.data.len()).sum();

    let mut wall_times = Vec::with_capacity(iterations);
    let mut errors: Vec<(String, String)> = Vec::new();

    for iter in 0..iterations {
        let start = Instant::now();
        for doc in &corpus {
            if let Err(msg) = parse_one(&doc.data, chunk_size) {
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
        "{{\"parser\":\"quick-xml\",\"config\":\"ns\",\"file_count\":{},\"total_bytes\":{},",
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
