.PHONY: all setup test install clean

PYTHON := python
PYOPENABE := pyopenabe

all: $(PYOPENABE)

setup:
	virtualenv venv;
	. venv/bin/activate && \
	pip install -r requirements.txt;

$(PYOPENABE): setup
	. venv/bin/activate && \
	$(PYTHON) setup.py build_ext --inplace; \
	$(PYTHON) setup.py bdist --format=zip; \

test:
	. venv/bin/activate && \
	$(PYTHON) test.py

install:
	$(PYTHON) setup.py install

clean:
	$(RM) -rf dist/ build/ *.cpp *.so

distclean:
	$(RM) -rf venv/ dist/ build/ *.cpp *.so
