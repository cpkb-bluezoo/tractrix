# tractrix benchmarks

Throughput and memory comparison of tractrix against three high-performance
native/Rust XML parsers: **Expat** (C), **libxml2** (C), and **quick-xml**
(Rust). Self-contained and decoupled from the published `tractrix` crate —
nothing here is vendored into git except our own harness code, a corpus
manifest, and results.

## Running it

```bash
cd benchmarks
./scripts/fetch.sh              # clones expat/libxml2/quick-xml + the W3C xmltest suite into vendor/ (gitignored)
./scripts/build.sh               # builds expat/libxml2 as static libs, builds all four harness binaries
./scripts/assemble_corpus.sh     # pools a shared corpus from each project's own test documents
./scripts/run.sh                 # runs the full matrix + pathological case, writes results/REPORT.md
```

`versions.env` pins the exact Expat/libxml2/quick-xml versions; `config.env`
holds the chunk size and iteration count. Bump either and re-run.

## Ground rules

- **Pooled corpus, not isolated per-parser suites.** Every parser runs
  against the exact same set of files, assembled from each project's own
  test documents (see "Corpus" below) — otherwise the numbers aren't
  comparable across parsers.
- **Feature parity.** Each comparison enables in tractrix exactly the
  features the target parser itself supports — nobody does (or skips) extra
  work relative to its counterpart. See the matrix below.
- **No-op sink.** Every parser is driven with a registered-but-no-op
  handler/callback set — dispatch overhead is included, but no application
  logic runs. (One exception, explained below: libxml2's validating run.)
- **≤32KB chunks, no FFI.** Every parser is fed the document in ≤32KB
  slices. Expat and libxml2 are driven from plain C programs; quick-xml and
  tractrix from plain Rust binaries. No bindings, no cross-language calls.
- **Local only, not CI.** Fetches real source trees and builds C libraries
  from scratch; deliberately not wired into automated CI.

## Feature-parity matrix

Namespaces are on in every comparison — all three target parsers support
namespace-aware parsing. DTD handling is where the real differences are, and
it turns out there are three genuinely different amounts of work a parser
can do with a `<!DOCTYPE ...>`, not two:

1. **Ignore it entirely** — recognize the construct just well enough to skip
   past it, but never parse a single declaration: no entity table, no
   attribute defaults. quick-xml's own source says this outright ("this
   crate does not support parsing DTDs").
2. **Parse and use it, but don't validate** — build the entity table, apply
   attribute defaults, but never check a validity constraint as an error.
   Expat works this way unconditionally (it has no validation mode at all).
3. **Parse, use, and validate** — libxml2 with `XML_PARSE_DTDVALID`.

The first version of this benchmark compared tractrix's non-validating
config (tier 2) against quick-xml (tier 1) under the same "ns" label — not a
fair fight, since quick-xml is doing categorically less work. tractrix has a
`DoctypeHandling` feature with three matching settings — `Disallow` (reject
any DOCTYPE outright, unrelated to this), `Skip` (tier 1), and `Process`
(tiers 2/3, `validation` on or off) — so now each comparison actually
matches capability tiers:

| vs. | tractrix config | tier | why |
|---|---|---|---|
| quick-xml | `doctype_handling: Skip` | 1 | quick-xml never processes DTD contents at all |
| Expat | `doctype_handling: Process`, `validation: false` | 2 | Expat parses the DTD (entities, attribute defaults) but has no validating mode |
| libxml2 | `doctype_handling: Process`, `validation: true` | 3 | libxml2's SAX2 interface does full DTD validation |

## The libxml2 exception to "no-op sink"

libxml2's DTD validation (`xmlValidateOneElement`, `xmlValidateOneAttribute`,
ID/IDREF tracking, ...) is implemented *inside* its default SAX2 callbacks
(`SAX2.c`), not in the core tokenizer. There's no public API to get
validation without also building the DOM tree those callbacks build as a
side effect — overriding `startElementNs`/`characters`/etc. with our own
no-ops (as the non-validating harnesses do) silently disables validation
entirely. So `harness/libxml2/bench_libxml2.c` uses libxml2's real default
SAX2 handler and frees the resulting tree with `xmlFreeDoc()` after each
file. That's an inherent property of libxml2's public API, not a
benchmarking artifact — see the comment at the top of that file. We did not
implement manual node-pruning to claw back a bounded-memory story here: it's
a well-known footgun with libxml2's ID/IDREF validation (freeing a node
still referenced by the ID table dangles a pointer that
`xmlValidateDocumentFinal` dereferences later), and the throughput corpus is
made of small regression-test files where it wouldn't move the numbers
anyway.

## Corpus

Two tiers, both assembled by `scripts/assemble_corpus.sh` and pooled across
projects (not isolated per-parser):

- **Tier 1 (well-formed)** — used for Expat + tractrix's `ns` config, and
  quick-xml + tractrix's `skip` config.
- **Tier 2 (DTD-validating)** — a subset of Tier 1: must contain a
  `<!DOCTYPE`, and pass tractrix's own validating oracle. Used for libxml2
  and tractrix's `ns+dtd` config. (libxml2's `XML_PARSE_DTDVALID` errors
  outright on a document with no DTD at all, so Tier 1 can't be reused
  there.)

Sources, inventoried directly rather than guessed:

- **libxml2**'s `test/` — a large real regression corpus (namespaces, DTDs,
  validity, encodings, XInclude, ...). The bulk of the pool.
- **quick-xml**'s `tests/documents/` — a modest set of real documents (RSS,
  RPM repodata).
- **Expat** doesn't bundle a redistributable document corpus — its own
  `tests/` are inline XML string literals in C, not files. Its *actual* own
  test suite is the external W3C XML Test Suite, referenced directly by URL
  in `tests/xmltest.sh`, and its own `tests/benchmark/benchmark.c` (a
  buffer-size-driven timing tool, the same shape as this harness) is built
  to run against exactly that suite. We fetch that zip as Expat's
  contribution to the pool.

Directories that are deliberately-bad fixtures by naming convention
(`not-wf/`, `invalid/` in the W3C suite; `test/errors*/` in libxml2) are
excluded before pooling — several of them test grammar productions that
only apply to a non-standalone-document parse mode (e.g. the W3C suite's
"P85 external parsed entity" not-wf cases under `ibm/not-wf/P85/`), which
none of these four harnesses specifically drive, so a raw accept/reject
verdict on them isn't meaningful here.

What's left is filtered through **tractrix as the accept/reject oracle**
(via `bench_tractrix`'s own `ns`/`ns+dtd` configs, run once with
`iterations=1`) — reasonable given its 100% W3C conformance record. Files
requiring network access to resolve are dropped outright, since every
config here runs with external fetching pointed only at the local
filesystem.

`corpus_manifest.json` (committed) records exactly which files went in —
relative path, sha256, size, source project, and which tier(s) — so results
are auditable even though the actual XML files aren't checked in
(regenerated by re-running `fetch.sh` + `assemble_corpus.sh`).

## Timing methodology

- Every file is pre-loaded into memory before the clock starts — isolating
  parse cost from disk I/O.
- One iteration = one full pass over the pooled corpus, each file fed in
  ≤32KB slices to a fresh parser instance with the no-op sink.
- 10 iterations, first discarded as warm-up; reported time is the median of
  the remaining 9, MB/s = total corpus bytes / median seconds.
- Peak RSS via `getrusage(RUSAGE_SELF)` (or the Rust equivalent), read once
  at process exit — RSS is monotonic within a process, so this is the worst
  case across all iterations.
- Any parse error during a throughput run is a **warning**, not a stop —
  the corpus was filtered through tractrix's own oracle, so a failure here
  usually means a genuine divergence between that parser and tractrix
  (interesting!), not a broken run. See `results/REPORT.md`'s Errors
  section.

## Per-parser chunking notes

- **Expat** and **libxml2** are genuinely push-based (`XML_Parse` /
  `xmlParseChunk` in a loop) — this is their native mode.
- **quick-xml** has no push API; it pulls via `Read`/`BufRead`. Driven
  through a custom `ChunkedByteReader` (`harness/quick-xml/src/main.rs`)
  that caps each underlying pull at the configured chunk size, so it ends
  up consuming the document in the same granularity as the push-based
  harnesses even though the control flow is inverted.
- **tractrix** is native push via `Parser::receive(Bytes)` in a loop.

None of the four are unconditionally constant-memory regardless of document
shape — element-nesting depth and (when validation is on) DTD/entity
tables all scale with the document. The one dimension that *does*
differentiate them cleanly is a single very large token:

## Pathological case

`scripts/generate_pathological.sh` writes two documents — one element with
a single ~64MB attribute value, and one with a single ~64MB CDATA run — and
`run.sh` benchmarks each in isolation (1 iteration, dedicated peak-RSS
reading). Expat, libxml2, and quick-xml must buffer an unterminated
attribute value or CDATA/text run *in full* before the corresponding
callback fires — that's how their public APIs work, not an implementation
oversight. tractrix streams `attribute_value_content()` and `characters()`
in chunks with an `end` flag (`src/handler.rs`), so it isn't forced to. The
results consistently show tractrix's peak RSS flat (~1x the filler size)
across both documents, while the other three run at roughly 2-4x — see
`results/REPORT.md` for current numbers. libxml2's runs on this case are
expected to report a validation error (neither document has a DOCTYPE, and
`XML_PARSE_DTDVALID` errors outright without one) — the peak RSS / timing
numbers are still meaningful.

One methodology note: libxml2 ships a default hardening limit on
attribute-value length (~10MB) as protection against untrusted input; left
alone, the pathological attribute case would hit "AttValue length too long"
partway through rather than actually buffering the full 64MB value —
measuring a truncated parse, not the full buffering cost we're comparing.
`bench_libxml2.c` sets `XML_PARSE_HUGE` to relax that (and the matching
nesting-depth limit) specifically so this comparison is genuine; it's a
no-op for the throughput corpus, whose files are all far under either
limit already.

## Known, expected divergences

A few parse errors show up in every run and are worth naming rather than
treating as bugs:

- **Expat** rejects EUC-JP/ISO-2022-JP encoded documents — Expat only
  supports UTF-8/UTF-16/ISO-8859-1/US-ASCII natively.
- **quick-xml** rejects UTF-16BE/UTF-16LE/ISO-2022-JP documents even with
  its `encoding` feature enabled (which this harness does) — its own
  `Cargo.toml` documents this as a permanent, known non-compliance, not an
  oversight.
- **libxml2** rejects a number of Tier 2 documents with "No declaration for
  element/attribute X" that tractrix's oracle accepted as valid — most
  visibly libxml2's own `test/c14n/*` fixtures, whose internal DTD subsets
  are minimal (built for entity/attribute-default testing, not full
  validation). Whether this reflects a gap in tractrix's `VC: Element
  Valid`/`VC: Attribute Value Type` enforcement for minimal/partial DTD
  subsets, or a legitimately different (and defensible) reading of those
  specific fixtures, is an open question this benchmark surfaced rather
  than answered — worth a closer look separately, not something this
  harness should paper over.
- **tractrix's `skip` config** rejects one Tier 1 document,
  `libxml2/test/valid/ns.xml`, with "Element prefix is not bound to a
  namespace URI". That file supplies its `xmlns:a`/`xmlns:b` bindings via
  `#FIXED` ATTLIST defaults rather than explicit attributes — exactly the
  DTD-dependent behavior `Skip` mode deliberately forgoes (no attribute
  defaults are applied). Expected, not a bug — it's the direct, documented
  consequence of `DoctypeHandling::Skip`, see `docs/security.html`.
