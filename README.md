# Tractrix

A non-blocking, push-model XML parser for Rust. Ported from the
[Gonzalez](https://github.com/cpkb-bluezoo/gonzalez) streaming XML scanner.

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
use tractrix::{DefaultHandler, FeatureSet, NamespaceFilter, Parser};

let mut app = DefaultHandler;
let mut filter = NamespaceFilter::new(&mut app, false);
let features = FeatureSet::default();
let mut parser = Parser::new(&mut filter, &features, None, None, None).unwrap();

// Feed chunks as they arrive
parser.receive(Bytes::from("<root>hel")).unwrap();
parser.receive(Bytes::from("lo</root>")).unwrap();

// Signal end-of-input
parser.close().unwrap();

// Reuse for another document
parser.reset();
parser.parse_all(Bytes::from("<doc/>")).unwrap();
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

## Non-Goals

Tractrix is intentionally minimal — a streaming well-formedness checker and
DTD validator with namespace support. The following are explicitly out of
scope:

- **SAX/JAXP compatibility layer** — Tractrix uses its own `XmlHandler` trait,
  not `org.xml.sax.ContentHandler`.
- **XSLT / XPath / XQuery** — Tractrix is a parser, not a processing engine.
- **XML Schema / RELAX NG** — Only DTD validation is supported.
- **XMLWriter / serialization** — Tractrix is read-only.
- **DOM / tree building** — The consumer builds whatever representation it
  needs from the event stream.
- **Async runtime integration** — Tractrix is runtime-agnostic; it accepts
  `Bytes` and calls your handler synchronously.

## License

LGPL-2.1-or-later
