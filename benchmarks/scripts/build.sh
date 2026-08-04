#!/usr/bin/env bash
# Builds the vendored C parsers as minimal static libs, then builds the
# harness programs (C + Cargo). Run scripts/fetch.sh first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$BENCH_DIR/vendor"
NPROC="$( (command -v nproc >/dev/null && nproc) || (command -v sysctl >/dev/null && sysctl -n hw.ncpu) || echo 4)"

log() { printf '[build] %s\n' "$*" >&2; }

require_vendor() {
    if [ ! -d "$VENDOR_DIR/$1" ]; then
        log "ERROR: $VENDOR_DIR/$1 missing — run scripts/fetch.sh first"
        exit 1
    fi
}

# ---- Expat: static lib, no tools/examples/tests/docs -----------------------
build_expat() {
    require_vendor expat
    local src="$VENDOR_DIR/expat/expat"
    local build="$src/build"
    log "configuring expat"
    cmake -S "$src" -B "$build" -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DEXPAT_SHARED_LIBS=OFF \
        -DEXPAT_BUILD_TOOLS=OFF \
        -DEXPAT_BUILD_EXAMPLES=OFF \
        -DEXPAT_BUILD_TESTS=OFF \
        -DEXPAT_BUILD_DOCS=OFF \
        -DEXPAT_BUILD_FUZZERS=OFF \
        -DEXPAT_BUILD_PKGCONFIG=OFF \
        -DEXPAT_ENABLE_INSTALL=OFF \
        >/dev/null
    log "building expat"
    cmake --build "$build" --parallel "$NPROC" >/dev/null
    local lib
    lib="$(find "$build" -maxdepth 1 -name 'libexpat.a' | head -1)"
    if [ -z "$lib" ]; then
        log "ERROR: libexpat.a not found under $build"
        exit 1
    fi
    log "expat static lib: $lib"
}

# ---- libxml2: static lib, minimal optional deps -----------------------------
build_libxml2() {
    require_vendor libxml2
    local src="$VENDOR_DIR/libxml2"
    local build="$src/build"
    log "configuring libxml2"
    cmake -S "$src" -B "$build" -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_PYTHON=OFF \
        -DLIBXML2_WITH_HTTP=OFF \
        -DLIBXML2_WITH_ICU=OFF \
        -DLIBXML2_WITH_LZMA=OFF \
        -DLIBXML2_WITH_ZLIB=OFF \
        -DLIBXML2_WITH_ICONV=OFF \
        -DLIBXML2_WITH_MODULES=OFF \
        -DLIBXML2_WITH_TESTS=OFF \
        -DLIBXML2_WITH_PROGRAMS=OFF \
        -DLIBXML2_WITH_DOCS=OFF \
        -DLIBXML2_WITH_READLINE=OFF \
        -DLIBXML2_WITH_PUSH=ON \
        -DLIBXML2_WITH_VALID=ON \
        >/dev/null
    log "building libxml2"
    cmake --build "$build" --parallel "$NPROC" >/dev/null
    local lib
    lib="$(find "$build" -maxdepth 1 -name 'libxml2.a' | head -1)"
    if [ -z "$lib" ]; then
        log "ERROR: libxml2.a not found under $build"
        exit 1
    fi
    log "libxml2 static lib: $lib"
}

build_expat
build_libxml2

# ---- C harnesses -------------------------------------------------------------
log "building bench_expat"
make -C "$BENCH_DIR/harness/expat" >/dev/null
log "building bench_libxml2"
make -C "$BENCH_DIR/harness/libxml2" >/dev/null

# ---- Rust harnesses -----------------------------------------------------------
log "building quick-xml harness"
(cd "$BENCH_DIR/harness/quick-xml" && cargo build --release --quiet)
log "building tractrix harness"
(cd "$BENCH_DIR/harness/tractrix" && cargo build --release --quiet)

log "done. Binaries:"
log "  $BENCH_DIR/harness/expat/bench_expat"
log "  $BENCH_DIR/harness/libxml2/bench_libxml2"
log "  $BENCH_DIR/harness/quick-xml/target/release/bench_quick_xml"
log "  $BENCH_DIR/harness/tractrix/target/release/bench_tractrix"
