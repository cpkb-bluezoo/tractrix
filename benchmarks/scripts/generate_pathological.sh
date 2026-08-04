#!/usr/bin/env bash
# Generates the adversarial documents used to demonstrate the
# single-huge-token memory behavior discussed in README.md: Expat, libxml2,
# and quick-xml must buffer an unterminated attribute value / CDATA run in
# full before their callback fires; tractrix streams both with an `end`
# flag (see src/handler.rs) and isn't forced to.
#
# Two documents, run and reported separately from the throughput corpus:
#   huge_attribute.xml — one element, one PATHOLOGICAL_SIZE_MB attribute value
#   huge_text.xml       — one element, one PATHOLOGICAL_SIZE_MB CDATA section
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BENCH_DIR/corpus_pathological"
SIZE_MB="${PATHOLOGICAL_SIZE_MB:-64}"

log() { printf '[pathological] %s\n' "$*" >&2; }

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

log "generating a ${SIZE_MB}MB filler run (safe for both an attribute value and CDATA content)"
FILLER="$OUT_DIR/.filler"
# `yes` gets SIGPIPE'd once `head -c` has read enough — expected, but
# pipefail would otherwise turn that into a hard error.
set +o pipefail
yes 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | head -c "$((SIZE_MB * 1024 * 1024))" > "$FILLER"
set -o pipefail

ATTR_FILE="$OUT_DIR/huge_attribute.xml"
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<root attr="'
    cat "$FILLER"
    printf '"/>\n'
} > "$ATTR_FILE"

TEXT_FILE="$OUT_DIR/huge_text.xml"
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<root><![CDATA['
    cat "$FILLER"
    printf ']]></root>\n'
} > "$TEXT_FILE"

rm -f "$FILLER"

# One-line file lists, so run.sh can benchmark each document individually
# (a combined list would blend both peak-RSS measurements into one number).
printf '%s\n' "$ATTR_FILE" > "$OUT_DIR/filelist_attribute.txt"
printf '%s\n' "$TEXT_FILE" > "$OUT_DIR/filelist_text.txt"

log "wrote $(wc -c < "$ATTR_FILE" | tr -d ' ') bytes -> $ATTR_FILE"
log "wrote $(wc -c < "$TEXT_FILE" | tr -d ' ') bytes -> $TEXT_FILE"
