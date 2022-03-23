
ZSYMLIB = libzsym.a
ZSYM_DEP_LIBS = -lcrypto
OABELIB = libopenabe.a

AR = ar
MAKE = make
ifndef BISON

BISON = /bin/bison
# BISON = ${ZROOT}/bin/bison

endif
FLEX = flex
INSTALL = install
