EXPAT_ROOT := ../../vendor/expat/expat
EXPAT_BUILD := $(EXPAT_ROOT)/build

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS := -I$(EXPAT_ROOT)/lib -I$(EXPAT_BUILD)
LDFLAGS := -L$(EXPAT_BUILD)
LDLIBS := -lexpat

.PHONY: all clean
all: bench_expat

bench_expat: bench_expat.c ../common/bench_common.h
	@if [ ! -f $(EXPAT_BUILD)/libexpat.a ]; then \
		echo "error: $(EXPAT_BUILD)/libexpat.a not found — run scripts/fetch.sh && scripts/build.sh from benchmarks/" >&2; \
		exit 1; \
	fi
	$(CC) $(CFLAGS) $(CPPFLAGS) bench_expat.c -o bench_expat $(LDFLAGS) $(LDLIBS)

clean:
	rm -f bench_expat
