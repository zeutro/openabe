include ../Makefile.common

.PHONY: all clean

DIRS=$(DEPS_PACKAGES)
# relic openssl gtest
all: $(DIRS)
	mkdir -p root/lib
	for d in $(DIRS); do \
		make -C $$d; \
	done

clean: $(DIRS)
	rm -rf root
	for d in $(DIRS); do \
		make -C $$d clean; \
	done
