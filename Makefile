.PHONY: all clean deps src cli examples bindings

all: check-env deps src cli examples

check-env:
ifndef ZROOT
    $(error ZROOT is undefined. Need to source env file: . ./env)
endif

INSTALL_PREFIX := /usr/local

docs:
	$(MAKE) -C docs

deps:
	$(MAKE) -C deps

src:
	$(MAKE) -C src
	$(MAKE) -C cli 

cli:
	$(MAKE) -C cli 

examples:
	$(MAKE) -C examples

bindings:
	$(MAKE) -C bindings

install-deps:
	mkdir -p $(ZROOT)/deps/root/bin
	mkdir -p $(INSTALL_PREFIX)
	cp -r $(ZROOT)/deps/root/lib $(INSTALL_PREFIX)
	cp -r $(ZROOT)/deps/root/include $(INSTALL_PREFIX)
	cp -rn $(ZROOT)/deps/root/bin $(INSTALL_PREFIX)

install: install-deps
	mkdir -p $(INSTALL_PREFIX)/bin
	cp -r $(ZROOT)/root/lib $(INSTALL_PREFIX)
	cp -r $(ZROOT)/root/include $(INSTALL_PREFIX)
	install -m 755 $(ZROOT)/src/bench_libopenabe $(INSTALL_PREFIX)/bin
	install -m 755 $(ZROOT)/src/profile_libopenabe $(INSTALL_PREFIX)/bin
	install -m 755 $(ZROOT)/cli/oabe_setup $(INSTALL_PREFIX)/bin
	install -m 755 $(ZROOT)/cli/oabe_keygen $(INSTALL_PREFIX)/bin
	install -m 755 $(ZROOT)/cli/oabe_enc $(INSTALL_PREFIX)/bin
	install -m 755 $(ZROOT)/cli/oabe_dec $(INSTALL_PREFIX)/bin
	
test:
	(cd src && ./test_libopenabe) || exit 1
	(cd src && ./test_zml) || exit 1
	(cd src && ./test_abe) || exit 1
	(cd src && ./test_pke) || exit 1
	(cd src && ./test_ske) || exit 1
	(cd src && ./test_zsym) || exit 1
	(cd cli && echo "hello world!" > ./input.txt && ./runTest.sh input.txt) || exit 1

clean:
	$(MAKE) -C src clean
	$(MAKE) -C cli clean
	$(MAKE) -C examples clean
	$(RM) -rf $(ZROOT)/deps/root
	$(RM) -rf $(ZROOT)/root/lib/* $(ZROOT)/root/include/*

distclean:	clean
	$(MAKE) -C deps distclean
