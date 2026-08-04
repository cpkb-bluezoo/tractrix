/* Throughput benchmark for libxml2: namespace-aware SAX2 + DTD validation
 * on, fed via the genuine push API (xmlCreatePushParserCtxt/xmlParseChunk)
 * in caller-chosen chunks.
 *
 * IMPORTANT DEVIATION from the plain no-op sink used by the other three
 * harnesses: libxml2's DTD validation (xmlValidateOneElement/
 * xmlValidateOneAttribute/ID-IDREF tracking/...) is implemented *inside*
 * its default SAX2 callbacks (SAX2.c), not in the core tokenizer. There is
 * no public API to get validation without also building the DOM tree those
 * callbacks build as a side effect — overriding startElementNs/characters/
 * etc. with our own no-ops (as the ns-only harnesses do) silently disables
 * validation entirely. So this harness uses libxml2's real default SAX2
 * handler (xmlSAXVersion(&sax, 2), untouched) and frees the resulting tree
 * with xmlFreeDoc() after each file. This means the "ns+dtd" run measures
 * libxml2 doing its actual validating work, tree-building included — that
 * is an inherent property of libxml2's public API, not a benchmark
 * artifact, and it's the one config in this suite that isn't a pure no-op
 * sink. See benchmarks/README.md for the full explanation.
 *
 * Usage: bench_libxml2 <file-list> <chunk-size-bytes> <iterations>
 */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlversion.h>
#include <stdio.h>
#include <stdlib.h>

#include "../common/bench_common.h"

typedef struct {
    int had_error;
    char msg[256];
} lx_error_state;

static void on_structured_error(void *user_data, const xmlError *err) {
    lx_error_state *st = (lx_error_state *)user_data;
    if (st->had_error) return; /* keep the first error only */
    if (err->level < XML_ERR_ERROR) return; /* ignore warnings */
    st->had_error = 1;
    snprintf(st->msg, sizeof(st->msg), "%s (line %d)",
             err->message ? err->message : "unknown error", err->line);
    /* Trim the trailing newline libxml2 error messages usually carry. */
    size_t n = strlen(st->msg);
    if (n > 0 && st->msg[n - 1] == '\n') {
        st->msg[n - 1] = '\0';
    }
}

static size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }

static int parse_one(const bench_doc *doc, size_t chunk_size, char *err_msg, size_t err_msg_len) {
    xmlSAXHandler sax;
    memset(&sax, 0, sizeof(sax));
    xmlSAXVersion(&sax, 2); /* default SAX2 callbacks — required for validation, see file header */

    lx_error_state st;
    st.had_error = 0;
    st.msg[0] = '\0';

    /* doc->path is passed as the base URI (not read from disk again — the
     * bytes still come from the pre-loaded buffer below) so that sibling
     * relative SYSTEM identifiers (e.g. test/valid/t6.xml -> "t6.dtd") in
     * the same corpus directory resolve correctly. */
    size_t first_len = min_sz(doc->len, chunk_size);
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(
        &sax, NULL, (const char *)doc->data, (int)first_len, doc->path);
    if (!ctxt) {
        snprintf(err_msg, err_msg_len, "xmlCreatePushParserCtxt failed");
        return 0;
    }
    xmlCtxtSetErrorHandler(ctxt, on_structured_error, &st);
    /* XML_PARSE_HUGE relaxes libxml2's default hardening limits on
     * text/attribute-value length and nesting depth (~10MB / depth 256).
     * Without it, the pathological single-huge-token case hits "AttValue
     * length too long" partway through instead of actually buffering the
     * whole value — which would measure a truncated parse, not the full
     * buffering cost we're comparing. Harmless for the throughput corpus,
     * whose files are all far under either limit already. */
    xmlCtxtUseOptions(ctxt, XML_PARSE_DTDVALID | XML_PARSE_NONET | XML_PARSE_HUGE);

    size_t offset = first_len;
    if (offset >= doc->len) {
        /* Whole document (or an empty one) fit in the initial chunk. */
        xmlParseChunk(ctxt, NULL, 0, 1);
    } else {
        while (offset < doc->len) {
            size_t n = min_sz(chunk_size, doc->len - offset);
            int terminate = (offset + n >= doc->len) ? 1 : 0;
            xmlParseChunk(ctxt, (const char *)doc->data + offset, (int)n, terminate);
            offset += n;
        }
    }

    int ok = ctxt->wellFormed && ctxt->valid && !st.had_error;
    if (!ok && err_msg_len > 0) {
        if (st.had_error) {
            snprintf(err_msg, err_msg_len, "%s", st.msg);
        } else if (!ctxt->wellFormed) {
            snprintf(err_msg, err_msg_len, "not well-formed");
        } else {
            snprintf(err_msg, err_msg_len, "DTD validation failed");
        }
    }

    if (ctxt->myDoc) {
        xmlFreeDoc(ctxt->myDoc);
    }
    xmlFreeParserCtxt(ctxt);
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <file-list> <chunk-size-bytes> <iterations>\n", argv[0]);
        return 2;
    }
    const char *list_path = argv[1];
    size_t chunk_size = (size_t)strtoul(argv[2], NULL, 10);
    int iterations = (int)strtol(argv[3], NULL, 10);
    if (chunk_size == 0 || iterations <= 0) {
        fprintf(stderr, "chunk-size and iterations must be positive\n");
        return 2;
    }

    xmlInitParser();

    bench_corpus corpus = bench_load_corpus(list_path);

    double *wall_times = malloc((size_t)iterations * sizeof(double));
    bench_error *errors = malloc((size_t)corpus.count * sizeof(bench_error));
    int error_count = 0;
    char err_msg_buf[256 * 64];
    size_t err_msg_used = 0;

    for (int iter = 0; iter < iterations; iter++) {
        double start = bench_now();
        for (int i = 0; i < corpus.count; i++) {
            char msg[256];
            if (!parse_one(&corpus.docs[i], chunk_size, msg, sizeof(msg))) {
                if (iter == 0 && error_count < corpus.count) {
                    size_t msg_len = strlen(msg) + 1;
                    if (err_msg_used + msg_len < sizeof(err_msg_buf)) {
                        char *copy = err_msg_buf + err_msg_used;
                        memcpy(copy, msg, msg_len);
                        err_msg_used += msg_len;
                        errors[error_count].file = corpus.docs[i].path;
                        errors[error_count].message = copy;
                        error_count++;
                    }
                }
            }
        }
        wall_times[iter] = bench_now() - start;
    }

    long peak_rss = bench_peak_rss_bytes();
    bench_emit_result(stdout, "libxml2", "ns+dtd", corpus.count, corpus.total_bytes,
                       wall_times, iterations, iterations > 1 ? 1 : 0,
                       peak_rss, errors, error_count);

    xmlCleanupParser();
    return error_count > 0 ? 1 : 0;
}
