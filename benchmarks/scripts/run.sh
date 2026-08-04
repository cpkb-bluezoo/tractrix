#!/usr/bin/env bash
# Runs the full comparison matrix (throughput + the pathological single-huge-
# token case) and generates results/REPORT.md. Run fetch.sh, build.sh, and
# assemble_corpus.sh first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck disable=SC1090
source "$BENCH_DIR/config.env"

CORPUS_DIR="$BENCH_DIR/corpus"
PATHOLOGICAL_DIR="$BENCH_DIR/corpus_pathological"
RESULTS_DIR="$BENCH_DIR/results/latest"

EXPAT_BIN="$BENCH_DIR/harness/expat/bench_expat"
LIBXML2_BIN="$BENCH_DIR/harness/libxml2/bench_libxml2"
QUICKXML_BIN="$BENCH_DIR/harness/quick-xml/target/release/bench_quick_xml"
TRACTRIX_BIN="$BENCH_DIR/harness/tractrix/target/release/bench_tractrix"

log() { printf '[run] %s\n' "$*" >&2; }

for b in "$EXPAT_BIN" "$LIBXML2_BIN" "$QUICKXML_BIN" "$TRACTRIX_BIN"; do
    if [ ! -x "$b" ]; then
        log "ERROR: $b missing — run scripts/build.sh first"
        exit 1
    fi
done
if [ ! -f "$CORPUS_DIR/filelist_wf.txt" ] || [ ! -f "$CORPUS_DIR/filelist_valid.txt" ]; then
    log "ERROR: $CORPUS_DIR is missing filelists — run scripts/assemble_corpus.sh first"
    exit 1
fi
if [ ! -f "$PATHOLOGICAL_DIR/filelist_attribute.txt" ]; then
    log "pathological corpus missing, generating it now"
    "$SCRIPT_DIR/generate_pathological.sh"
fi

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/*.json

# run_one <output-filename> <command...>
# Any parse error is a warning, not a hard stop — the corpus was filtered
# through tractrix's own oracle, so a failure here means either a genuine
# divergence between that parser and tractrix (worth knowing about) or an
# expected case like libxml2's pathological run (no DOCTYPE, DTDVALID
# trivially errors, but still parses and reports valid timing/RSS numbers).
run_one() {
    local out="$1"
    shift
    log "running: $*"
    set +e
    "$@" > "$RESULTS_DIR/$out"
    local rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        local n
        n="$(jq '.errors | length' "$RESULTS_DIR/$out" 2>/dev/null || echo '?')"
        log "WARNING: $out reported $n error(s) — see results/REPORT.md for details"
    fi
}

log "=== throughput matrix (chunk=${CHUNK_SIZE_BYTES} bytes, iterations=${ITERATIONS}) ==="
run_one expat.json           "$EXPAT_BIN"    "$CORPUS_DIR/filelist_wf.txt"    "$CHUNK_SIZE_BYTES" "$ITERATIONS"
run_one quick-xml.json       "$QUICKXML_BIN" "$CORPUS_DIR/filelist_wf.txt"    "$CHUNK_SIZE_BYTES" "$ITERATIONS"
run_one tractrix-ns.json     "$TRACTRIX_BIN" "$CORPUS_DIR/filelist_wf.txt"    "$CHUNK_SIZE_BYTES" "$ITERATIONS" ns
run_one libxml2.json         "$LIBXML2_BIN"  "$CORPUS_DIR/filelist_valid.txt" "$CHUNK_SIZE_BYTES" "$ITERATIONS"
run_one tractrix-ns+dtd.json "$TRACTRIX_BIN" "$CORPUS_DIR/filelist_valid.txt" "$CHUNK_SIZE_BYTES" "$ITERATIONS" ns+dtd

log "=== pathological case (single huge token, 1 iteration each) ==="
run_one pathological-expat-attribute.json       "$EXPAT_BIN"    "$PATHOLOGICAL_DIR/filelist_attribute.txt" "$CHUNK_SIZE_BYTES" 1
run_one pathological-expat-text.json            "$EXPAT_BIN"    "$PATHOLOGICAL_DIR/filelist_text.txt"      "$CHUNK_SIZE_BYTES" 1
run_one pathological-libxml2-attribute.json     "$LIBXML2_BIN"  "$PATHOLOGICAL_DIR/filelist_attribute.txt" "$CHUNK_SIZE_BYTES" 1
run_one pathological-libxml2-text.json          "$LIBXML2_BIN"  "$PATHOLOGICAL_DIR/filelist_text.txt"      "$CHUNK_SIZE_BYTES" 1
run_one pathological-quick-xml-attribute.json   "$QUICKXML_BIN" "$PATHOLOGICAL_DIR/filelist_attribute.txt" "$CHUNK_SIZE_BYTES" 1
run_one pathological-quick-xml-text.json        "$QUICKXML_BIN" "$PATHOLOGICAL_DIR/filelist_text.txt"      "$CHUNK_SIZE_BYTES" 1
run_one pathological-tractrix-ns-attribute.json "$TRACTRIX_BIN" "$PATHOLOGICAL_DIR/filelist_attribute.txt" "$CHUNK_SIZE_BYTES" 1 ns
run_one pathological-tractrix-ns-text.json      "$TRACTRIX_BIN" "$PATHOLOGICAL_DIR/filelist_text.txt"      "$CHUNK_SIZE_BYTES" 1 ns
log "(libxml2's pathological runs are expected to report a validation error — neither document has a DOCTYPE, and DTDVALID trivially errors without one. Peak RSS / timing are still valid.)"

log "=== generating report ==="
python3 "$SCRIPT_DIR/report.py"

log "done. See $BENCH_DIR/results/REPORT.md"
