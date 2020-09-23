include ../Makefile.common

.PHONY: all

ifdef LOCAL_INCLUDE
LOC_INC="-I$(LOCAL_INCLUDE)"
endif
ifdef LOCAL_LIB_ROOT
LOC_LIB="-L$(LOCAL_LIB_ROOT)"
endif

CXXFLAGS := $(CXX11FLAGS) $(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT -I${ZROOT}/deps/root/include -I${ZROOT}/root/include $(LOC_INC)
LDFLAGS := -L${ZROOT}/deps/root/lib -L${ZROOT}/root/lib $(LOC_LIB)
LIBS := -lcrypto -lrelic -lrelic_ec -lopenabe

all: test_kp test_cp test_pk test_km

test_kp: test_kp.o
	$(CXX) -o test_kp $(CXXFLAGS) $(LDFLAGS) test_kp.cpp $(LIBS)

test_cp: test_cp.o
	$(CXX) -o test_cp $(CXXFLAGS) $(LDFLAGS) test_cp.cpp $(LIBS)

test_pk: test_pk.o
	$(CXX) -o test_pk $(CXXFLAGS) $(LDFLAGS) test_pk.cpp $(LIBS)

test_km: test_km.o
	$(CXX) -o test_km $(CXXFLAGS) $(LDFLAGS) test_km.cpp $(LIBS)

test:
	./test_kp
	./test_cp
	./test_pk
	./test_km

clean:
	rm -rf *.o *.dSYM test_kp test_cp test_pk test_km
