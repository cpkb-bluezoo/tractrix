#!/usr/bin/env bash
# Pools each project's own test-suite documents into one shared corpus that
# every parser runs against (see README.md for why "pooled" beats
# "isolated per-parser"). Produces two tiers:
#
#   corpus/filelist_wf.txt    — well-formed only, used for Expat/quick-xml
#                                and tractrix's `ns` config
#   corpus/filelist_valid.txt — has a DOCTYPE and validates cleanly, used
#                                for libxml2 and tractrix's `ns+dtd` config
#                                (libxml2's DTDVALID option errors outright
#                                on a DTD-less document, so Tier 1 can't be
#                                reused there — see bench_libxml2.c)
#
# tractrix — with its 100% W3C conformance record — is used as the
# accept/reject oracle for both tiers, via the same bench_tractrix binary
# used for timing (run once per candidate list with iterations=1).
#
# Nothing under corpus/ is committed (regenerated from vendor/, which is
# itself gitignored); corpus_manifest.json is committed as the audit trail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$BENCH_DIR/vendor"
CORPUS_DIR="$BENCH_DIR/corpus"
TRACTRIX_BIN="$BENCH_DIR/harness/tractrix/target/release/bench_tractrix"

# shellcheck disable=SC1090
source "$BENCH_DIR/config.env"

log() { printf '[assemble] %s\n' "$*" >&2; }

for d in libxml2 quick-xml w3c-xmltest; do
    if [ ! -d "$VENDOR_DIR/$d" ]; then
        log "ERROR: $VENDOR_DIR/$d missing — run scripts/fetch.sh first"
        exit 1
    fi
done
if [ ! -x "$TRACTRIX_BIN" ]; then
    log "ERROR: $TRACTRIX_BIN missing — run scripts/build.sh first"
    exit 1
fi
if ! command -v jq >/dev/null; then
    log "ERROR: jq is required (used to read the oracle's JSON output)"
    exit 1
fi

rm -rf "$CORPUS_DIR"
mkdir -p "$CORPUS_DIR"

# ---- 1. gather raw candidates from each project's own test documents ------
# Directories named not-wf/, invalid/, or errors*/ are deliberately-bad
# fixtures by convention (W3C suite's not-wf/invalid categories; libxml2's
# own test/errors/, test/errors10/) — excluded here rather than left to the
# tractrix oracle below, since several of them test grammar productions
# that only apply to a non-standalone-document parse mode (e.g. the W3C
# suite's P85 "external parsed entity" not-wf cases), which none of these
# four harnesses specifically drive — see README.md for the full rationale.
RAW_LIST="$CORPUS_DIR/.raw_candidates.txt"
{
    find "$VENDOR_DIR/libxml2/test" -type f -name '*.xml'
    find "$VENDOR_DIR/quick-xml/tests/documents" -maxdepth 1 -type f -name '*.xml'
    find "$VENDOR_DIR/w3c-xmltest" -type f -name '*.xml'
} | grep -viE '/(not-wf|invalid|errors[0-9]*)/' | sort > "$RAW_LIST"
raw_count=$(wc -l < "$RAW_LIST" | tr -d ' ')
log "raw candidates: $raw_count (deliberately-bad fixture directories excluded)"

# ---- 2. dedupe by content hash ---------------------------------------------
# (two source projects could plausibly ship a byte-identical fixture)
HASHED_LIST="$CORPUS_DIR/.hashed_candidates.txt"
: > "$HASHED_LIST"
while IFS= read -r f; do
    h=$(shasum -a 256 "$f" | cut -d' ' -f1)
    printf '%s\t%s\n' "$h" "$f" >> "$HASHED_LIST"
done < "$RAW_LIST"
DEDUPED_LIST="$CORPUS_DIR/.deduped_candidates.txt"
sort -k1,1 -u "$HASHED_LIST" | cut -f2 | sort > "$DEDUPED_LIST"
deduped_count=$(wc -l < "$DEDUPED_LIST" | tr -d ' ')
log "after dedup: $deduped_count (dropped $((raw_count - deduped_count)) exact duplicates)"

# ---- 3. drop anything that needs network access ----------------------------
# Every benchmark config runs with external entity fetching pointed only at
# the local filesystem — a doc whose correct parse depends on fetching an
# http(s)/ftp SYSTEM id would just error out (or hang) in all four parsers.
PREFILTERED_LIST="$CORPUS_DIR/.prefiltered_candidates.txt"
: > "$PREFILTERED_LIST"
network_dropped=0
while IFS= read -r f; do
    if grep -qE 'SYSTEM[[:space:]]*["'"'"'](https?|ftp):' "$f" 2>/dev/null; then
        network_dropped=$((network_dropped + 1))
    else
        printf '%s\n' "$f" >> "$PREFILTERED_LIST"
    fi
done < "$DEDUPED_LIST"
log "dropped $network_dropped file(s) referencing network SYSTEM ids"

# ---- 4. Tier 1 (well-formed): tractrix ns-config oracle --------------------
log "running tractrix ns-oracle over $(wc -l < "$PREFILTERED_LIST" | tr -d ' ') candidates"
ns_oracle_json="$CORPUS_DIR/.oracle_ns.json"
set +e
"$TRACTRIX_BIN" "$PREFILTERED_LIST" "$CHUNK_SIZE_BYTES" 1 ns > "$ns_oracle_json"
set -e
WF_LIST="$CORPUS_DIR/filelist_wf.txt"
jq -r '.errors[].file' "$ns_oracle_json" | sort -u > "$CORPUS_DIR/.rejected_wf.txt"
comm -23 "$PREFILTERED_LIST" "$CORPUS_DIR/.rejected_wf.txt" > "$WF_LIST"
wf_count=$(wc -l < "$WF_LIST" | tr -d ' ')
wf_rejected=$(wc -l < "$CORPUS_DIR/.rejected_wf.txt" | tr -d ' ')
log "Tier 1 (well-formed): $wf_count files ($wf_rejected rejected by tractrix as not well-formed)"

# ---- 5. Tier 2 (DTD-validating): DOCTYPE-bearing subset of Tier 1, ---------
#         then tractrix ns+dtd-config oracle
DOCTYPE_CANDIDATES="$CORPUS_DIR/.doctype_candidates.txt"
: > "$DOCTYPE_CANDIDATES"
while IFS= read -r f; do
    grep -qF '<!DOCTYPE' "$f" 2>/dev/null && printf '%s\n' "$f" >> "$DOCTYPE_CANDIDATES"
done < "$WF_LIST"
doctype_count=$(wc -l < "$DOCTYPE_CANDIDATES" | tr -d ' ')
log "Tier 1 files with a DOCTYPE: $doctype_count"

VALID_LIST="$CORPUS_DIR/filelist_valid.txt"
if [ "$doctype_count" -eq 0 ]; then
    : > "$VALID_LIST"
    log "Tier 2 (validating): 0 files (no DOCTYPE-bearing candidates)"
else
    log "running tractrix ns+dtd-oracle over $doctype_count candidates"
    dtd_oracle_json="$CORPUS_DIR/.oracle_dtd.json"
    set +e
    "$TRACTRIX_BIN" "$DOCTYPE_CANDIDATES" "$CHUNK_SIZE_BYTES" 1 ns+dtd > "$dtd_oracle_json"
    set -e
    jq -r '.errors[].file' "$dtd_oracle_json" | sort -u > "$CORPUS_DIR/.rejected_valid.txt"
    comm -23 "$DOCTYPE_CANDIDATES" "$CORPUS_DIR/.rejected_valid.txt" > "$VALID_LIST"
    valid_count=$(wc -l < "$VALID_LIST" | tr -d ' ')
    valid_rejected=$(wc -l < "$CORPUS_DIR/.rejected_valid.txt" | tr -d ' ')
    log "Tier 2 (validating): $valid_count files ($valid_rejected rejected by tractrix as invalid/not well-formed)"
fi

# ---- 6. manifest (committed) -----------------------------------------------
MANIFEST="$BENCH_DIR/corpus_manifest.json"
log "writing $MANIFEST"
{
    echo '{'
    echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo '  "files": ['
    first=1
    while IFS= read -r f; do
        rel="${f#"$VENDOR_DIR"/}"
        case "$rel" in
            libxml2/*) source=libxml2 ;;
            quick-xml/*) source=quick-xml ;;
            w3c-xmltest/*) source="w3c-xmltest (Expat's referenced suite)" ;;
            *) source=unknown ;;
        esac
        sha=$(shasum -a 256 "$f" | cut -d' ' -f1)
        size=$(wc -c < "$f" | tr -d ' ')
        in_wf=$(grep -qxF "$f" "$WF_LIST" && echo true || echo false)
        in_valid=$(grep -qxF "$f" "$VALID_LIST" && echo true || echo false)
        [ "$first" -eq 1 ] && first=0 || echo ','
        printf '    {"path": "%s", "sha256": "%s", "size": %s, "source": "%s", "tier_wf": %s, "tier_valid": %s}' \
            "$rel" "$sha" "$size" "$source" "$in_wf" "$in_valid"
    done < <(cat "$WF_LIST" "$VALID_LIST" | sort -u)
    echo ''
    echo '  ]'
    echo '}'
} > "$MANIFEST"

# clean up scratch files, keep the two filelists + manifest
rm -f "$RAW_LIST" "$HASHED_LIST" "$DEDUPED_LIST" "$PREFILTERED_LIST" "$ns_oracle_json" \
      "$CORPUS_DIR/.rejected_wf.txt" "$DOCTYPE_CANDIDATES" \
      "$CORPUS_DIR"/.oracle_dtd.json "$CORPUS_DIR"/.rejected_valid.txt

log "done. $wf_count files in Tier 1 (wf), ${valid_count:-0} files in Tier 2 (valid)."
