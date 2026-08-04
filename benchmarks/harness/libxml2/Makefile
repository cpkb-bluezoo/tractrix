LIBXML2_ROOT := ../../vendor/libxml2
LIBXML2_BUILD := $(LIBXML2_ROOT)/build

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
# The build dir has the generated libxml/xmlversion.h; the source dir has
# everything else under include/libxml/.
CPPFLAGS := -I$(LIBXML2_ROOT)/include -I$(LIBXML2_BUILD)
LDFLAGS := -L$(LIBXML2_BUILD)
LDLIBS := -lxml2 -lm

.PHONY: all clean
all: bench_libxml2

bench_libxml2: bench_libxml2.c ../common/bench_common.h
	@if [ ! -f $(LIBXML2_BUILD)/libxml2.a ]; then \
		echo "error: $(LIBXML2_BUILD)/libxml2.a not found — run scripts/fetch.sh && scripts/build.sh from benchmarks/" >&2; \
		exit 1; \
	fi
	$(CC) $(CFLAGS) $(CPPFLAGS) bench_libxml2.c -o bench_libxml2 $(LDFLAGS) $(LDLIBS)

clean:
	rm -f bench_libxml2
