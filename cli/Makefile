include ../src/Makefile.inc
include ../Makefile.common

CUR_DIR = .
OBJS    = common.o
BINOBJS = oabe_setup oabe_keygen oabe_enc oabe_dec
OABE_LIB = $(OABE_LIB_ROOT)/$(OABELIB)

all: $(BINOBJS)

clean:
	-rm -rf *.o *.dSYM input.txt $(TESTOBJS) $(BINOBJS) $(OABELIB)

install: $(BINOBJS)
	for b in $(BINOBJS); do \
		$(INSTALL) -m 0755 $$b $(USERB); \
	done

# NOTE: order of library matters: libztk first, then relic, then gmp
# if relic goes before ztk, then you'll see a bunch of undefined references to relic symbols!
oabe_setup: $(OBJS)
	$(CXX) -o oabe_setup $(OBJS) -I../src/ $(CXXFLAGS) $(LDFLAGS) $(CUR_DIR)/setup.cpp $(OABE_LIB) $(OABELDSHLIBS)

oabe_keygen: $(OBJS)
	$(CXX) -o oabe_keygen $(OBJS) -I../src/ $(CXXFLAGS) $(LDFLAGS) $(CUR_DIR)/keygen.cpp $(OABE_LIB) $(OABELDSHLIBS)

oabe_enc: $(OBJS)
	$(CXX) -o oabe_enc $(OBJS) -I../src/ $(CXXFLAGS) $(LDFLAGS) $(CUR_DIR)/encrypt.cpp $(OABE_LIB) $(OABELDSHLIBS)

oabe_dec: $(OBJS)
	$(CXX) -o oabe_dec $(OBJS) -I../src/ $(CXXFLAGS) $(LDFLAGS) $(CUR_DIR)/decrypt.cpp $(OABE_LIB) $(OABELDSHLIBS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $<

%.o: %.cpp
	$(CXX) -I../ $(CXXFLAGS) -c $<

%.h:
