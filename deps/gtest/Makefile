.PHONY: all clean

VERSION := 1.8.0

include ../../Makefile.common

all: package googletest-release-$(VERSION)/.built

DEST_LIBDIR := $(DEPS_INSTALL_ZROOT)/lib
DEST_INCLUDEDIR := $(DEPS_INSTALL_ZROOT)/include

package:
	./download_gtest.sh $(VERSION)

googletest-release-$(VERSION)/.built: googletest-release-$(VERSION)
	cd $<; \
	mkdir -p build && cd build/ && \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(DEPS_INSTALL_ZROOT) ../googletest/ && \
	make install && \
	touch ../.built

googletest-release-$(VERSION): googletest-release-$(VERSION).zip
	unzip $^

clean:
	rm -rf googletest-release-$(VERSION)

distclean:
	rm -rf googletest-release-$(VERSION)*
