#!/usr/bin/env python3
"""Renders benchmarks/results/latest/*.json into benchmarks/results/REPORT.md.

Run by scripts/run.sh after the full matrix + pathological case complete.
"""
import json
import os
import sys
from datetime import datetime, timezone

BENCH_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BENCH_DIR, "results", "latest")
REPORT_PATH = os.path.join(BENCH_DIR, "results", "REPORT.md")
MANIFEST_PATH = os.path.join(BENCH_DIR, "corpus_manifest.json")

# Not part of the JSON schema the harnesses emit — this is fixed knowledge
# about how each binary is built (see README.md "Feature-parity matrix").
HANDLER_KIND = {
    "expat": "no-op sink",
    "quick-xml": "no-op sink",
    "libxml2": "default SAX2 (tree-building — required for validation, see harness/libxml2/bench_libxml2.c)",
    "tractrix": "no-op sink (RecordingHandler — tracks error() only)",
}


def read_env_file(path):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"')
    return values


def load_results():
    throughput = []
    pathological = []
    if not os.path.isdir(RESULTS_DIR):
        return throughput, pathological
    for name in sorted(os.listdir(RESULTS_DIR)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(RESULTS_DIR, name)
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"report: skipping unparseable {path}: {e}", file=sys.stderr)
            continue
        data["_file"] = name
        if name.startswith("pathological-"):
            pathological.append(data)
        else:
            throughput.append(data)
    return throughput, pathological


def mb(bytes_val):
    return bytes_val / (1024.0 * 1024.0)


def render_throughput_table(results):
    lines = [
        "| Parser | Config | Handler | Files | Corpus (MB) | Median (s) | MB/s | Peak RSS (MB) | Errors |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        parser = r.get("parser", "?")
        handler = HANDLER_KIND.get(parser, "?")
        errors = len(r.get("errors", []))
        err_note = str(errors) if errors == 0 else f"**{errors}** (see below)"
        lines.append(
            "| {parser} | {config} | {handler} | {files} | {corpus_mb:.2f} | {median:.4f} | {mbs:.1f} | {rss:.1f} | {err} |".format(
                parser=parser,
                config=r.get("config", "?"),
                handler=handler,
                files=r.get("file_count", 0),
                corpus_mb=mb(r.get("total_bytes", 0)),
                median=r.get("median_sec", 0.0),
                mbs=r.get("mb_per_sec", 0.0),
                rss=mb(r.get("peak_rss_bytes", 0)),
                err=err_note,
            )
        )
    return "\n".join(lines)


def render_pathological_table(results):
    lines = [
        "| Parser | Config | Document | Peak RSS (MB) | Time (s) |",
        "|---|---|---|---:|---:|",
    ]
    for r in results:
        name = r.get("_file", "")
        doc = "attribute" if "attribute" in name else ("text/CDATA" if "text" in name else "?")
        lines.append(
            "| {parser} | {config} | {doc} | {rss:.1f} | {t:.4f} |".format(
                parser=r.get("parser", "?"),
                config=r.get("config", "?"),
                doc=doc,
                rss=mb(r.get("peak_rss_bytes", 0)),
                t=r.get("median_sec", 0.0),
            )
        )
    return "\n".join(lines)


def render_errors_section(results):
    parts = []
    for r in results:
        errors = r.get("errors", [])
        if not errors:
            continue
        parts.append(f"\n**{r.get('parser')} / {r.get('config')}** ({r.get('_file')}) — {len(errors)} error(s):\n")
        for e in errors[:20]:
            parts.append(f"- `{e.get('file')}`: {e.get('message')}")
        if len(errors) > 20:
            parts.append(f"- ... and {len(errors) - 20} more")
    return "\n".join(parts)


def main():
    config = read_env_file(os.path.join(BENCH_DIR, "config.env"))
    versions = read_env_file(os.path.join(BENCH_DIR, "versions.env"))
    manifest = {}
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)

    throughput, pathological = load_results()
    if not throughput and not pathological:
        print("report: no results found under results/latest/ — run scripts/run.sh first", file=sys.stderr)
        sys.exit(1)

    files = manifest.get("files", [])
    wf_count = sum(1 for f in files if f.get("tier_wf"))
    valid_count = sum(1 for f in files if f.get("tier_valid"))

    all_errors = throughput + pathological
    warn = any(len(r.get("errors", [])) > 0 for r in all_errors)

    out = []
    out.append("# Benchmark results\n")
    out.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    out.append(
        "Versions: Expat {expat} · libxml2 {libxml2} · quick-xml {qx} · chunk size {cs} bytes · {it} iterations (first discarded as warm-up)\n".format(
            expat=versions.get("EXPAT_VERSION", "?"),
            libxml2=versions.get("LIBXML2_VERSION", "?"),
            qx=versions.get("QUICK_XML_VERSION", "?"),
            cs=config.get("CHUNK_SIZE_BYTES", "?"),
            it=config.get("ITERATIONS", "?"),
        )
    )
    out.append(
        f"Corpus: {wf_count} well-formed files (Tier 1) / {valid_count} DTD-validating files (Tier 2), "
        f"pooled from libxml2's `test/`, quick-xml's `tests/documents/`, and the W3C XML Test Suite "
        f"(Expat's own referenced suite). Generated {manifest.get('generated_at', '?')}. "
        "See corpus_manifest.json.\n"
    )

    if warn:
        out.append(
            "> **Note:** one or more runs reported parse errors — see the Errors section "
            "below. This can mean a genuine divergence between that parser and tractrix's "
            "well-formedness/validity oracle (interesting!), not necessarily a broken run.\n"
        )

    out.append("## Throughput\n")
    out.append(render_throughput_table(throughput))
    out.append("")

    out.append("\n## Pathological case (single huge token)\n")
    out.append(
        "One element with a single ~64MB attribute value / CDATA run, fed in the same "
        f"{config.get('CHUNK_SIZE_BYTES', '?')}-byte chunks as everything else. Expat, "
        "libxml2, and quick-xml must buffer the whole token before their callback fires; "
        "tractrix streams `attribute_value_content()`/`characters()` with an `end` flag "
        "(src/handler.rs) and isn't forced to. libxml2's runs are expected to report a "
        "validation error here (neither document has a DOCTYPE) — that's fine, the peak "
        "RSS / timing numbers are still meaningful.\n"
    )
    out.append(render_pathological_table(pathological))

    errors_section = render_errors_section(all_errors)
    if errors_section:
        out.append("\n## Errors\n")
        out.append(errors_section)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"report: wrote {REPORT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
