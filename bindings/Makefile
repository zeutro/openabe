include ../Makefile.common

.PHONY: all test clean

DIRS=python

all: $(DIRS)
	for d in $(DIRS); do \
	    make -C $$d; \
	done

test: $(DIRS)
	for d in $(DIRS); do \
	    make -C $$d test; \
	done

clean: $(DIRS)
	for d in $(DIRS); do \
	    make -C $$d clean; \
	done
