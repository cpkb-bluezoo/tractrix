# Tractrix

A non-blocking, push-model XML parser and serializer for Rust. Ported from the
[Gonzalez](https://github.com/cpkb-bluezoo/gonzalez) streaming XML scanner and
writer.

**Documentation:** [Usage guides (GitHub Pages)](https://cpkb-bluezoo.github.io/tractrix/)
cover the `XmlHandler` and `XmlWriter` contracts, features, and security
defaults. This README is a short overview; the HTML docs are the primary
reference for sequencing and lifetime rules.

## Overview

Tractrix accepts document bytes incrementally via `receive()` and emits
structural events into an `XmlHandler` callback trait — no intermediate token
stream, no blocking I/O, minimal allocation. It is designed for environments
where XML arrives as a byte stream (network sockets, chunked HTTP, async
readers) and the consumer processes events as they appear.

```text
bytes ──▶ ExternalEntityDecoder ──▶ Scanner ──▶ (NamespaceFilter?) ──▶ XmlHandler
           (BOM, XML/text decl,       (WF + DTD        (xmlns → namespace
            charset, line endings)      + validation)    events)
```

## Push API

```rust
use bytes::Bytes;
use tractrix::{FeatureSet, Parser, XmlHandler};

struct CountingHandler {
    elements: usize,
}

impl XmlHandler for CountingHandler {
    fn start_element(&mut self, _q_name: &str) -> tractrix::ParseResult<()> {
        self.elements += 1;
        Ok(())
    }
}

let mut handler = CountingHandler { elements: 0 };
let features = FeatureSet::default();
let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();

parser.receive(Bytes::from("<root>hel")).unwrap();
parser.receive(Bytes::from("lo</root>")).unwrap();
parser.close().unwrap();
assert_eq!(handler.elements, 1);

// Reuse for another document
parser.reset();
parser.parse_all(Bytes::from("<doc/>")).unwrap();
```

## Writing an `XmlHandler`

Implement [`XmlHandler`](src/handler.rs) on your own type. Every method has a
default no-op (except `fatal_error`, which stops parsing), so override only
what you care about.

### Event order for an element

For `<item id="42">text</item>` the handler sees, in order:

1. `start_element("item")`
2. `start_attribute("id", "CDATA", …)` then one or more
   `attribute_value_content(…, end)` (last chunk has `end = true`)
3. `end_attributes()` — always fired once, even with no attributes
4. `characters(…, ignorable, end)` — text may arrive in several chunks
5. `end_element()` — no name; keep your own stack from `start_element` if needed

With a [`NamespaceFilter`](src/namespace.rs) in front, `xmlns` / `xmlns:prefix`
become `namespace(prefix, uri)` instead of (or in addition to) attributes,
depending on `namespace-prefixes`.

### Streaming chunks and `end`

Attribute values, character data, comments, and PI data are **streamed**: a
single logical run may be one call or many. The `end` flag is true on the
chunk that completes the run. If the first call already has `end = true`,
you can use the slice immediately with no buffering.

Text slices are borrowed from the parser’s scan buffer and are only valid
for the duration of the callback. If you need to keep data across calls,
copy it — and honour `save_buffers()`, which fires before the scanner reuses
storage (e.g. after a numeric character reference or at the end of a
`receive` chunk).

### Errors

- `fatal_error` — well-formedness failure; returning `Err` aborts the parse
  (the default implementation does this).
- `error` — recoverable (typically a DTD validity constraint when
  `validation` is on); parsing continues unless you return `Err`.

### Example: collect text under one element

```rust
use bytes::Bytes;
use tractrix::{FeatureSet, ParseResult, Parser, XmlHandler};

struct TitleCollector {
    depth: usize,
    in_title: bool,
    title: String,
}

impl XmlHandler for TitleCollector {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        self.depth += 1;
        if q_name == "title" {
            self.in_title = true;
            self.title.clear();
        }
        Ok(())
    }

    fn characters(&mut self, text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        if self.in_title {
            self.title.push_str(text);
        }
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        if self.in_title {
            self.in_title = false;
        }
        self.depth -= 1;
        Ok(())
    }
}

let xml = br#"<doc><title>Hello &amp; world</title></doc>"#;
let mut handler = TitleCollector {
    depth: 0,
    in_title: false,
    title: String::new(),
};
let features = FeatureSet::default();
let mut parser = Parser::new(&mut handler, &features, None, None, None).unwrap();
parser.parse_all(Bytes::from_static(xml)).unwrap();
assert_eq!(handler.title, "Hello & world");
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `namespaces` | on | Namespace processing (xmlns → namespace events) |
| `namespace-prefixes` | off | Report xmlns attrs alongside namespace events |
| `validation` | off | DTD validation (element models, attribute types, ID/IDREF) |
| `external-general-entities` | **off** | Load external general entities |
| `external-parameter-entities` | **off** | Load external parameter entities |
| `disallow-doctype-decl` | off | Reject any DOCTYPE declaration |
| `accessExternalDTD` | `""` | Protocol allow-list for external DTD ("file", "all", etc.) |
| `entity-expansion-limit` | 64000 | Maximum entity expansions per document |

`disallow-doctype-decl` is the standard SAX/Xerces boolean feature, but it's
backed by a 3-way `doctype_handling: DoctypeHandling` field
(`Disallow` / `Skip` / `Process`, default `Process`) rather than a plain
bool. The boolean feature only ever sets `Disallow` or `Process` — the third
option, `Skip` (recognize and skip past a DOCTYPE's contents without
parsing them: no entity table, no attribute defaults, matching what parsers
without DTD support do), has no standard-feature equivalent and is set
directly: `features.doctype_handling = DoctypeHandling::Skip;`.

Features are configured via `FeatureSet` before creating the parser:

```rust
use tractrix::FeatureSet;

let mut f = FeatureSet::default();
f.validation = true;
f.external_general_entities = true;
f.access_external_dtd = "file".to_string();
```

## Security Defaults

Tractrix ships secure by default:

- External general/parameter entities are **disabled** — no XXE.
- External DTD access is empty (no protocol allowed).
- Entity expansion is capped at 64,000 expansions (billion-laughs mitigation).
- `RefusingEntityResolver` is the implicit resolver when none is provided.

To process documents that use external DTDs or entities, you must explicitly
enable those features and supply a `FileEntityResolver` (or your own
`EntityResolver` implementation).

## Namespace Processing

The `Scanner` itself is namespace-unaware. Wrap your handler in
`NamespaceFilter` to convert `xmlns`/`xmlns:prefix` attributes into
`XmlHandler::namespace()` events:

```rust
use tractrix::{DefaultHandler, FeatureSet, NamespaceFilter, Parser};

let mut app = DefaultHandler;
let mut filter = NamespaceFilter::new(&mut app, false);
let features = FeatureSet::default(); // namespaces=true by default
let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();
```

## Testing

Unit tests and the W3C conformance suite are separate Cargo test targets
(and separate CI jobs):

```bash
# Focused unit tests (fast)
cargo test --test unit_tests

# W3C XML Conformance Suite (vendored at xmlconf/)
cargo test --test xmlconf

# Everything
cargo test
```

The `xmlconf/` tree is the W3C suite (xmltest, eduni, IBM, OASIS, Sun,
Japanese encodings). Override the path with `TRACTRIX_XMLCONF` only if you
need an alternate checkout. A report is written to
`target/xml-conformance-report.txt`.

Current score: **2359 / 2359 (100%)**.

## Serialization

[`XmlWriter`](src/writer.rs) is a streaming serializer matching Gonzalez
`XMLWriter`. It writes to any `std::io::Write` sink and supports:

- Pretty-print via [`IndentConfig`](src/indent.rs) (`tabs`, `spaces2`,
  `spaces4`, `spaces(n)`)
- Output charset / BOM (`UTF-8`, `UTF-16BE/LE`, `UTF-32BE/LE`, `ISO-8859-1`,
  `US-ASCII`, plus other `encoding_rs` encodings)
- XML 1.1 escaping mode
- Namespace declarations with redundant-decl suppression
- Empty-element optimization (`<foo/>`)
- Full DTD output, including standalone conversion (inline external subset)

```rust
use tractrix::{IndentConfig, XmlWriter};

let mut w = XmlWriter::new_vec();
w.set_indent_config(Some(IndentConfig::spaces2()));
w.write_start_element("root").unwrap();
w.write_start_element("child").unwrap();
w.write_characters("hello").unwrap();
w.write_end_element().unwrap();
w.write_end_element().unwrap();
w.flush().unwrap();
assert_eq!(
    String::from_utf8(w.into_inner()).unwrap(),
    "<root>\n  <child>hello</child>\n</root>"
);
```

## Non-Goals

Tractrix is intentionally minimal — a streaming well-formedness checker and
DTD validator with namespace support, plus a matching streaming serializer.
The following are explicitly out of scope:

- **SAX/JAXP compatibility layer** — Tractrix uses its own `XmlHandler` trait,
  not `org.xml.sax.ContentHandler`.
- **XSLT / XPath / XQuery** — Tractrix is not a processing engine.
- **XML Schema / RELAX NG** — Only DTD validation is supported.
- **DOM / tree building** — The consumer builds whatever representation it
  needs from the event stream.
- **Async runtime integration** — Tractrix is runtime-agnostic; it accepts
  `Bytes` and calls your handler synchronously.

## License

LGPL-2.1-or-later
