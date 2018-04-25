.PHONY: all clean

include ../../Makefile.common

# defined in Makefile.common
VERSION=${OPENSSL_VERSION}

all: package openssl-${VERSION}/.built

DEST_LIBDIR := $(DEPS_INSTALL_ZROOT)/lib
DEST_INCLUDEDIR := $(DEPS_INSTALL_ZROOT)/include

openssl-${VERSION}/.built: openssl-${VERSION}
	cd $<; \
	./${OPENSSL_CONFIG} --prefix=$(DEPS_INSTALL_ZROOT) && \
	make && \
	make install_sw && \
	touch .built

package:
	./download_openssl.sh ${WITH_BP}

openssl-${VERSION}: openssl-${VERSION}.tar.gz
	tar -zxf $^

clean:
	rm -rf openssl-$(VERSION)

distclean:
	rm -rf openssl-$(VERSION)*
