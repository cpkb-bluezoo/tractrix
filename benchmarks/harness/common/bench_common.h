/* Shared timing/loading/output helpers for the C benchmark harnesses
 * (bench_expat.c, bench_libxml2.c). Single-header, static-linkage only —
 * each .c file that includes this gets its own private copy, no separate
 * translation unit to build/link. */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

/* ---- timing --------------------------------------------------------- */

static double bench_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long bench_peak_rss_bytes(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
    return (long)ru.ru_maxrss; /* macOS reports bytes */
#else
    return (long)ru.ru_maxrss * 1024L; /* Linux reports KB */
#endif
}

static int bench_cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* Sorts in place; caller passes the array to sort. */
static double bench_median(double *values, int n) {
    qsort(values, (size_t)n, sizeof(double), bench_cmp_double);
    if (n % 2 == 1) {
        return values[n / 2];
    }
    return (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

/* ---- corpus loading --------------------------------------------------- */

typedef struct {
    char *path;
    unsigned char *data;
    size_t len;
} bench_doc;

typedef struct {
    bench_doc *docs;
    int count;
    size_t total_bytes;
} bench_corpus;

/* Reads one absolute path per line from `list_path`, loads each file fully
 * into memory up front (outside any timed region). Blank lines and lines
 * starting with '#' are skipped. Exits the process on any I/O error — a
 * benchmark run with a silently-missing file isn't trustworthy. */
static bench_corpus bench_load_corpus(const char *list_path) {
    FILE *lf = fopen(list_path, "r");
    if (!lf) {
        fprintf(stderr, "bench: cannot open file list '%s': %s\n", list_path, strerror(errno));
        exit(1);
    }

    bench_corpus corpus;
    corpus.docs = NULL;
    corpus.count = 0;
    corpus.total_bytes = 0;
    int capacity = 0;

    char line[4096];
    while (fgets(line, sizeof(line), lf)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        if (n == 0 || line[0] == '#') {
            continue;
        }

        FILE *f = fopen(line, "rb");
        if (!f) {
            fprintf(stderr, "bench: cannot open corpus file '%s': %s\n", line, strerror(errno));
            exit(1);
        }
        if (fseek(f, 0, SEEK_END) != 0) {
            fprintf(stderr, "bench: cannot seek '%s'\n", line);
            exit(1);
        }
        long size = ftell(f);
        if (size < 0) {
            fprintf(stderr, "bench: cannot tell '%s'\n", line);
            exit(1);
        }
        rewind(f);

        unsigned char *buf = malloc((size_t)size);
        if (size > 0 && !buf) {
            fprintf(stderr, "bench: out of memory loading '%s' (%ld bytes)\n", line, size);
            exit(1);
        }
        if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
            fprintf(stderr, "bench: short read on '%s'\n", line);
            exit(1);
        }
        fclose(f);

        if (corpus.count == capacity) {
            capacity = capacity ? capacity * 2 : 64;
            corpus.docs = realloc(corpus.docs, (size_t)capacity * sizeof(bench_doc));
            if (!corpus.docs) {
                fprintf(stderr, "bench: out of memory growing corpus list\n");
                exit(1);
            }
        }
        corpus.docs[corpus.count].path = strdup(line);
        corpus.docs[corpus.count].data = buf;
        corpus.docs[corpus.count].len = (size_t)size;
        corpus.count++;
        corpus.total_bytes += (size_t)size;
    }
    fclose(lf);

    if (corpus.count == 0) {
        fprintf(stderr, "bench: file list '%s' produced zero documents\n", list_path);
        exit(1);
    }
    return corpus;
}

/* ---- JSON output ------------------------------------------------------ */
/* All string fields we emit here are program-controlled (parser name,
 * config, file paths from our own corpus listing) — no untrusted input
 * reaches this, so a minimal backslash/quote escaper is sufficient. */

static void bench_json_escape(FILE *out, const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', out);
            fputc((char)c, out);
        } else if (c == '\n') {
            fputs("\\n", out);
        } else if (c < 0x20) {
            fprintf(out, "\\u%04x", c);
        } else {
            fputc((char)c, out);
        }
    }
}

typedef struct {
    const char *file;
    const char *message;
} bench_error;

static void bench_emit_result(
    FILE *out,
    const char *parser,
    const char *config,
    int file_count,
    size_t total_bytes,
    double *wall_times_sec,
    int iterations,
    int warmup_discarded,
    long peak_rss_bytes,
    bench_error *errors,
    int error_count
) {
    int timed_n = 0;
    double *timed = malloc((size_t)iterations * sizeof(double));
    if (!timed) {
        fprintf(stderr, "bench: out of memory computing median\n");
        exit(1);
    }
    for (int i = warmup_discarded; i < iterations; i++) {
        timed[timed_n++] = wall_times_sec[i];
    }
    double median = bench_median(timed, timed_n);
    free(timed);
    double mb_per_sec = (median > 0.0) ? ((double)total_bytes / (1024.0 * 1024.0)) / median : 0.0;

    fprintf(out, "{\"parser\":\"%s\",\"config\":\"%s\",\"file_count\":%d,\"total_bytes\":%zu,",
            parser, config, file_count, total_bytes);
    fprintf(out, "\"iterations\":%d,\"warmup_discarded\":%d,\"wall_times_sec\":[",
            iterations, warmup_discarded);
    for (int i = 0; i < iterations; i++) {
        fprintf(out, "%s%.6f", i ? "," : "", wall_times_sec[i]);
    }
    fprintf(out, "],\"median_sec\":%.6f,\"mb_per_sec\":%.3f,\"peak_rss_bytes\":%ld,",
            median, mb_per_sec, peak_rss_bytes);
    fprintf(out, "\"errors\":[");
    for (int i = 0; i < error_count; i++) {
        fprintf(out, "%s{\"file\":\"", i ? "," : "");
        bench_json_escape(out, errors[i].file);
        fprintf(out, "\",\"message\":\"");
        bench_json_escape(out, errors[i].message);
        fprintf(out, "\"}");
    }
    fprintf(out, "]}\n");
}

#endif /* BENCH_COMMON_H */
