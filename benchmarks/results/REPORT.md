# Benchmark results

Generated: 2026-08-06T06:06:52Z

Versions: Expat 2.8.2 · libxml2 2.15.3 · quick-xml 0.39.0 · chunk size 32768 bytes · 10 iterations (first discarded as warm-up)

Corpus: 1206 well-formed files (Tier 1) / 417 DTD-validating files (Tier 2), pooled from libxml2's `test/`, quick-xml's `tests/documents/`, and the W3C XML Test Suite (Expat's own referenced suite). Generated 2026-08-05T06:01:04Z. See corpus_manifest.json.

> **Note:** one or more runs reported parse errors — see the Errors section below. This can mean a genuine divergence between that parser and tractrix's well-formedness/validity oracle (interesting!), not necessarily a broken run.

## Throughput


**quick-xml vs. tractrix** — quick-xml never parses DTD contents at all — matched against tractrix's `Skip` config (tier 1).

1206 files, 3.21 MB corpus.

| Parser | Config | Handler | Median (s) | MB/s | Peak RSS (MB) | Errors |
|---|---|---|---:|---:|---:|---:|
| quick-xml | ns | no-op sink | 0.0114 | 280.7 | 6.8 | **3** (see below) |
| tractrix | skip | no-op sink (RecordingHandler — tracks error() only) | 0.0245 | 131.0 | 8.6 | **1** (see below) |

**expat vs. tractrix** — Expat parses the DTD (entities, attribute defaults) but has no validating mode — matched against tractrix's `Process`/non-validating config (tier 2).

1206 files, 3.21 MB corpus.

| Parser | Config | Handler | Median (s) | MB/s | Peak RSS (MB) | Errors |
|---|---|---|---:|---:|---:|---:|
| expat | ns | no-op sink | 0.0340 | 94.4 | 6.4 | **2** (see below) |
| tractrix | ns | no-op sink (RecordingHandler — tracks error() only) | 0.0278 | 115.6 | 8.7 | 0 |

**libxml2 vs. tractrix** — libxml2's SAX2 interface does full DTD validation — matched against tractrix's `Process`/validating config (tier 3).

417 files, 0.10 MB corpus.

| Parser | Config | Handler | Median (s) | MB/s | Peak RSS (MB) | Errors |
|---|---|---|---:|---:|---:|---:|
| libxml2 | ns+dtd | default SAX2 (tree-building — required for validation, see harness/libxml2/bench_libxml2.c) | 0.0088 | 11.0 | 4.0 | **2** (see below) |
| tractrix | ns+dtd | no-op sink (RecordingHandler — tracks error() only) | 0.0172 | 5.6 | 6.0 | 0 |


## Pathological case (single huge token)

One element with a single ~64MB attribute value / CDATA run, fed in the same 32768-byte chunks as everything else. Expat, libxml2, and quick-xml must buffer the whole token before their callback fires; tractrix streams `attribute_value_content()`/`characters()` with an `end` flag (src/handler.rs) and isn't forced to. libxml2's runs are expected to report a validation error here (neither document has a DOCTYPE) — that's fine, the peak RSS / timing numbers are still meaningful.

| Parser | Config | Document | Peak RSS (MB) | Time (s) |
|---|---|---|---:|---:|
| expat | ns | attribute | 259.8 | 0.5638 |
| expat | ns | text/CDATA | 65.6 | 0.2415 |
| libxml2 | ns+dtd | attribute | 259.0 | 0.3430 |
| libxml2 | ns+dtd | text/CDATA | 259.7 | 0.3768 |
| quick-xml | ns | attribute | 131.7 | 0.0593 |
| quick-xml | ns | text/CDATA | 131.7 | 0.0130 |
| tractrix | ns | attribute | 66.1 | 0.1084 |
| tractrix | ns | text/CDATA | 66.1 | 0.1282 |

## Errors


**expat / ns** (expat.json) — 2 error(s):

- `vendor/libxml2/test/icu_parse_test.xml`: unknown encoding at line 1
- `vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/weekly-iso-2022-jp.xml`: unknown encoding at line 1

**libxml2 / ns+dtd** (libxml2.json) — 2 error(s):

- `vendor/libxml2/test/xmlid/id_err2.xml`: xml:id : attribute type should be ID
 (line 3)
- `vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/weekly-iso-2022-jp.xml`: Unsupported encoding: iso-2022-jp
 (line 1)

**quick-xml / ns** (quick-xml.json) — 3 error(s):

- `vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/pr-xml-little-endian.xml`: ill-formed document: entity or character reference not closed: `;` not found before end of input
- `vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/pr-xml-utf-16.xml`: ill-formed document: entity or character reference not closed: `;` not found before end of input
- `vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/weekly-iso-2022-jp.xml`: ill-formed document: expected `</$N4pK\;EMM$N:n@.</P>`, but `</予定項目>` was found

**tractrix / skip** (tractrix-skip.json) — 1 error(s):

- `vendor/libxml2/test/valid/ns.xml`: NSC: Element prefix "a" is not bound to a namespace URI

**libxml2 / ns+dtd** (pathological-libxml2-attribute.json) — 1 error(s):

- `corpus_pathological/huge_attribute.xml`: Validation failed: no DTD found ! (line 2033603)

**libxml2 / ns+dtd** (pathological-libxml2-text.json) — 1 error(s):

- `corpus_pathological/huge_text.xml`: Validation failed: no DTD found ! (line 2)
