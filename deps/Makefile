include ../Makefile.common

.PHONY: all clean

DIRS=$(DEPS_PACKAGES)
# relic openssl gtest
all: $(DIRS)
	mkdir -p root/lib
	mkdir -p root/bin
ifndef NO_DEPS
	for d in $(DIRS); do \
		make -C $$d; \
	done
endif

clean: $(DIRS)
	rm -rf root
	for d in relic openssl gtest; do \
		make -C $$d clean; \
	done
