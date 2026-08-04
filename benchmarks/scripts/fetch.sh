#!/usr/bin/env bash
# Fetches the parser sources under comparison into benchmarks/vendor/ (gitignored).
# Nothing here is committed — re-run this script to regenerate the checkout.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$BENCH_DIR/vendor"

# shellcheck disable=SC1090
source "$BENCH_DIR/versions.env"

mkdir -p "$VENDOR_DIR"

log() { printf '[fetch] %s\n' "$*" >&2; }

# resolve_tag <repo_url> <version> -> prints the matching git ref name
#
# Tries a few naming conventions since expat/libxml2/quick-xml don't agree
# on one (R_2_8_2 vs v2.15.3 vs v0.39.0).
resolve_tag() {
    local repo="$1" version="$2"
    local underscored="${version//./_}"
    local candidates=("$version" "v$version" "R_$underscored" "V$version")
    local refs
    refs="$(git ls-remote --tags "$repo")"
    local candidate ref
    for candidate in "${candidates[@]}"; do
        # Prefer the dereferenced annotated-tag commit (^{}) if present.
        ref="$(printf '%s\n' "$refs" | awk -v t="refs/tags/$candidate^{}" '$2==t{print $2; found=1} END{if(!found) exit 1}' || true)"
        if [ -z "$ref" ]; then
            ref="$(printf '%s\n' "$refs" | awk -v t="refs/tags/$candidate" '$2==t{print $2; found=1} END{if(!found) exit 1}' || true)"
        fi
        if [ -n "$ref" ]; then
            # Strip the trailing ^{} decoration to get a checkoutable ref name.
            printf '%s\n' "${ref%^{\}}"
            return 0
        fi
    done
    log "ERROR: no tag matching version '$version' found in $repo (tried: ${candidates[*]})"
    return 1
}

clone_at_tag() {
    local name="$1" repo="$2" version="$3"
    local dest="$VENDOR_DIR/$name"
    local tag
    tag="$(resolve_tag "$repo" "$version")"
    if [ -d "$dest/.git" ]; then
        local have_tag
        have_tag="$(git -C "$dest" describe --tags --exact-match 2>/dev/null || true)"
        if [ "$have_tag" = "${tag#refs/tags/}" ]; then
            log "$name already at $tag, skipping"
            return 0
        fi
        log "$name present but at a different ref, removing for re-clone"
        rm -rf "$dest"
    fi
    log "cloning $name @ $tag"
    git clone --quiet --depth 1 --branch "${tag#refs/tags/}" "$repo" "$dest"
}

clone_at_tag expat "$EXPAT_REPO" "$EXPAT_VERSION"
clone_at_tag libxml2 "$LIBXML2_REPO" "$LIBXML2_VERSION"
# Cloned only to harvest tests/documents/*.xml for the corpus — the actual
# quick-xml build dependency is resolved by Cargo via harness/quick-xml/Cargo.toml.
clone_at_tag quick-xml "$QUICK_XML_REPO" "$QUICK_XML_VERSION"

# Expat's own tests/xmltest.sh points at this suite rather than bundling it;
# fetch it as Expat's corpus contribution (see README.md).
W3C_DIR="$VENDOR_DIR/w3c-xmltest"
if [ -d "$W3C_DIR" ]; then
    log "W3C xmltest suite already present, skipping download"
else
    log "downloading W3C xmltest suite"
    mkdir -p "$W3C_DIR"
    zip_path="$VENDOR_DIR/xmlts.zip"
    curl -fsSL "$W3C_XMLTEST_URL" -o "$zip_path"
    unzip -q "$zip_path" -d "$W3C_DIR"
    rm -f "$zip_path"
fi

log "done. Vendored sources are in $VENDOR_DIR (gitignored)."
