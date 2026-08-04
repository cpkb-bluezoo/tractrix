/* Throughput benchmark for Expat: namespace-aware, no DTD validation
 * (Expat has no validating mode). Fed via the genuine push API,
 * XML_Parse(), in caller-chosen chunks — see tests/benchmark/benchmark.c
 * in the Expat source tree for the pattern this follows.
 *
 * Usage: bench_expat <file-list> <chunk-size-bytes> <iterations>
 */
#include <expat.h>
#include <stdio.h>
#include <stdlib.h>

#include "../common/bench_common.h"

/* No-op handlers: registered and invoked (dispatch overhead included) but
 * do no work, matching tractrix::DefaultHandler and the quick-xml/libxml2
 * harnesses. */
static void XMLCALL on_start_element(void *ud, const XML_Char *name, const XML_Char **atts) {
    (void)ud; (void)name; (void)atts;
}
static void XMLCALL on_end_element(void *ud, const XML_Char *name) {
    (void)ud; (void)name;
}
static void XMLCALL on_characters(void *ud, const XML_Char *s, int len) {
    (void)ud; (void)s; (void)len;
}
static void XMLCALL on_comment(void *ud, const XML_Char *data) {
    (void)ud; (void)data;
}
static void XMLCALL on_pi(void *ud, const XML_Char *target, const XML_Char *data) {
    (void)ud; (void)target; (void)data;
}
static void XMLCALL on_start_cdata(void *ud) { (void)ud; }
static void XMLCALL on_end_cdata(void *ud) { (void)ud; }

static XML_Parser make_parser(void) {
    /* Namespace-aware, matching the feature-parity matrix (Expat supports
     * this so tractrix's NamespaceFilter is enabled for this comparison
     * too). Separator character must not appear in real names. */
    XML_Parser p = XML_ParserCreateNS(NULL, '\x01');
    XML_SetElementHandler(p, on_start_element, on_end_element);
    XML_SetCharacterDataHandler(p, on_characters);
    XML_SetCommentHandler(p, on_comment);
    XML_SetProcessingInstructionHandler(p, on_pi);
    XML_SetCdataSectionHandler(p, on_start_cdata, on_end_cdata);
    return p;
}

/* Parses one already-loaded document in chunk_size slices. Returns 1 on
 * success, 0 on a well-formedness error (message left in *err_msg, a
 * static buffer good until the next call). */
static int parse_one(const bench_doc *doc, size_t chunk_size, char *err_msg, size_t err_msg_len) {
    XML_Parser p = make_parser();
    size_t offset = 0;
    int ok = 1;
    while (offset < doc->len) {
        size_t n = doc->len - offset;
        if (n > chunk_size) n = chunk_size;
        int is_final = (offset + n >= doc->len);
        if (XML_Parse(p, (const char *)doc->data + offset, (int)n, is_final) == XML_STATUS_ERROR) {
            snprintf(err_msg, err_msg_len, "%s at line %lu",
                     XML_ErrorString(XML_GetErrorCode(p)),
                     (unsigned long)XML_GetCurrentLineNumber(p));
            ok = 0;
            break;
        }
        offset += n;
    }
    if (doc->len == 0) {
        /* Empty document: still need one XML_Parse(..., isFinal=1) call. */
        if (XML_Parse(p, "", 0, 1) == XML_STATUS_ERROR) {
            snprintf(err_msg, err_msg_len, "%s", XML_ErrorString(XML_GetErrorCode(p)));
            ok = 0;
        }
    }
    XML_ParserFree(p);
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

    bench_corpus corpus = bench_load_corpus(list_path);

    double *wall_times = malloc((size_t)iterations * sizeof(double));
    bench_error *errors = malloc((size_t)corpus.count * sizeof(bench_error));
    int error_count = 0;
    char err_msg_buf[256 * 64]; /* generous static pool for error message copies */
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
    bench_emit_result(stdout, "expat", "ns", corpus.count, corpus.total_bytes,
                       wall_times, iterations, iterations > 1 ? 1 : 0,
                       peak_rss, errors, error_count);

    return error_count > 0 ? 1 : 0;
}
