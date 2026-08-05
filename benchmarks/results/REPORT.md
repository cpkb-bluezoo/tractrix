# Benchmark results

Generated: 2026-08-05T05:30:39Z

Versions: Expat 2.8.2 · libxml2 2.15.3 · quick-xml 0.39.0 · chunk size 32768 bytes · 10 iterations (first discarded as warm-up)

Corpus: 1212 well-formed files (Tier 1) / 482 DTD-validating files (Tier 2), pooled from libxml2's `test/`, quick-xml's `tests/documents/`, and the W3C XML Test Suite (Expat's own referenced suite). Generated 2026-08-04T19:31:25Z. See corpus_manifest.json.

> **Note:** one or more runs reported parse errors — see the Errors section below. This can mean a genuine divergence between that parser and tractrix's well-formedness/validity oracle (interesting!), not necessarily a broken run.

## Throughput

| Parser | Config | Handler | Files | Corpus (MB) | Median (s) | MB/s | Peak RSS (MB) | Errors |
|---|---|---|---:|---:|---:|---:|---:|---:|
| expat | ns | no-op sink | 1212 | 3.21 | 0.0332 | 96.8 | 6.3 | **2** (see below) |
| libxml2 | ns+dtd | default SAX2 (tree-building — required for validation, see harness/libxml2/bench_libxml2.c) | 482 | 0.60 | 0.0261 | 23.2 | 9.2 | **61** (see below) |
| quick-xml | ns | no-op sink | 1212 | 3.21 | 0.0113 | 283.1 | 6.5 | **3** (see below) |
| tractrix | ns+dtd | no-op sink (DefaultHandler) | 482 | 0.60 | 0.0661 | 9.1 | 8.3 | 0 |
| tractrix | ns | no-op sink (DefaultHandler) | 1212 | 3.21 | 0.0619 | 51.9 | 9.0 | 0 |
| tractrix | skip | no-op sink (DefaultHandler) | 1212 | 3.21 | 0.0449 | 71.5 | 9.0 | **1** (see below) |


## Pathological case (single huge token)

One element with a single ~64MB attribute value / CDATA run, fed in the same 32768-byte chunks as everything else. Expat, libxml2, and quick-xml must buffer the whole token before their callback fires; tractrix streams `attribute_value_content()`/`characters()` with an `end` flag (src/handler.rs) and isn't forced to. libxml2's runs are expected to report a validation error here (neither document has a DOCTYPE) — that's fine, the peak RSS / timing numbers are still meaningful.

| Parser | Config | Document | Peak RSS (MB) | Time (s) |
|---|---|---|---:|---:|
| expat | ns | attribute | 259.8 | 0.5709 |
| expat | ns | text/CDATA | 65.6 | 0.2439 |
| libxml2 | ns+dtd | attribute | 259.0 | 0.3566 |
| libxml2 | ns+dtd | text/CDATA | 259.7 | 0.3622 |
| quick-xml | ns | attribute | 131.7 | 0.0651 |
| quick-xml | ns | text/CDATA | 131.7 | 0.0149 |
| tractrix | ns | attribute | 66.4 | 0.5500 |
| tractrix | ns | text/CDATA | 66.3 | 0.4424 |

## Errors


**expat / ns** (expat.json) — 2 error(s):

- `benchmarks/vendor/libxml2/test/icu_parse_test.xml`: unknown encoding at line 1
- `benchmarks/vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/weekly-iso-2022-jp.xml`: unknown encoding at line 1

**libxml2 / ns+dtd** (libxml2.json) — 61 error(s):

- `benchmarks/vendor/libxml2/test/bigentname.xml`: No declaration for element doc
 (line 5)
- `benchmarks/vendor/libxml2/test/boundaries1.xml`: No declaration for attribute a of element d
 (line 9)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-1.xml`: No declaration for element doc
 (line 8)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-3.xml`: No declaration for element e1
 (line 3)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-4.xml`: No declaration for element text
 (line 3)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-5.xml`: No declaration for element doc
 (line 10)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-7.xml`: No declaration for attribute xmlns of element doc
 (line 5)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/example-8.xml`: No declaration for attribute xmlns of element doc
 (line 5)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/xmlbase-c14n11spec-102.xml`: No declaration for attribute xmlns of element doc
 (line 10)
- `benchmarks/vendor/libxml2/test/c14n/1-1-without-comments/xmlbase-c14n11spec2-102.xml`: No declaration for attribute xmlns of element doc
 (line 10)
- `benchmarks/vendor/libxml2/test/c14n/exc-without-comments/test-0.xml`: No declaration for attribute xmlns:foo of element doc
 (line 2)
- `benchmarks/vendor/libxml2/test/c14n/without-comments/test-0.xml`: No declaration for attribute Id of element Object
 (line 9)
- `benchmarks/vendor/libxml2/test/c14n/without-comments/test-1.xml`: No declaration for attribute xmlns of element Signature
 (line 9)
- `benchmarks/vendor/libxml2/test/def-xml-attr.xml`: No declaration for element foo
 (line 7)
- `benchmarks/vendor/libxml2/test/defattr2.xml`: No declaration for attribute att of element doc
 (line 8)
- `benchmarks/vendor/libxml2/test/ent_738805.xml`: No declaration for attribute someattribute of element somebeacon
 (line 9)
- `benchmarks/vendor/libxml2/test/entity-in-ns-uri.xml`: No declaration for attribute xmlns of element e
 (line 5)
- `benchmarks/vendor/libxml2/test/eve.xml`: No declaration for element spec
 (line 6)
- `benchmarks/vendor/libxml2/test/intsubset2.xml`: Element kanjidic2 content does not follow the DTD, expecting (header , character*), got ()
 (line 291)
- `benchmarks/vendor/libxml2/test/issue626.xml`: No declaration for element e
 (line 12)
- ... and 41 more

**quick-xml / ns** (quick-xml.json) — 3 error(s):

- `benchmarks/vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/pr-xml-little-endian.xml`: ill-formed document: entity or character reference not closed: `;` not found before end of input
- `benchmarks/vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/pr-xml-utf-16.xml`: ill-formed document: entity or character reference not closed: `;` not found before end of input
- `benchmarks/vendor/w3c-xmltest/XML-Test-Suite/xmlconf/japanese/weekly-iso-2022-jp.xml`: ill-formed document: expected `</$N4pK\;EMM$N:n@.</P>`, but `</予定項目>` was found

**tractrix / skip** (tractrix-skip.json) — 1 error(s):

- `benchmarks/vendor/libxml2/test/valid/ns.xml`: NSC: Element prefix "a" is not bound to a namespace URI

**libxml2 / ns+dtd** (pathological-libxml2-attribute.json) — 1 error(s):

- `benchmarks/corpus_pathological/huge_attribute.xml`: Validation failed: no DTD found ! (line 2033603)

**libxml2 / ns+dtd** (pathological-libxml2-text.json) — 1 error(s):

- `benchmarks/corpus_pathological/huge_text.xml`: Validation failed: no DTD found ! (line 2)
