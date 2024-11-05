SHELL		= /bin/bash
PY3		?= $(shell python3 --version >/dev/null 2>&1 && echo python3 || echo python )
PY3_V		= $(shell $(PY3) -c "import sys; print('-'.join((next(iter(filter(None,sys.executable.split('/')))),sys.platform,sys.implementation.cache_tag)))" 2>/dev/null )
VERSION		= $(shell $(PY3) -c 'exec(open("hdwallet/version.py", "r").read()); print( __version__.strip("v"))')
WHEEL		= dist/hdwallet-$(VERSION)-py3-none-any.whl

PY3TEST		= $(PY3) -m pytest

GHUB_NAME	= python-hdwallet
VENV_DIR	= $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/.. )
VENV_NAME	= $(GHUB_NAME)-$(VERSION)-$(PY3_V)
VENV		= $(VENV_DIR)/$(VENV_NAME)
VENV_OPTS	=

.PHONY:			all test build build-check wheel install-dev install clean FORCE

all:			build

test:
	$(PY3TEST)

# Run only tests with a prefix containing the target string, eg test-blah
test-%:
	$(PY3TEST) *$*_test.py

unit-%:
	$(PY3TEST) -k $*

nix-%:
	nix-shell --pure --run "make $*"

build:			clean wheel

wheel:			$(WHEEL)

$(WHEEL):		FORCE
	$(PY3) -m pip install -r requirements-dev.txt
	$(PY3) -m build
	@ls -last dist

install:		$(WHEEL) FORCE
	$(PY3) -m pip install --force-reinstall .[cli,docs]

clean:
	@rm -rf build dist *.egg-info $(shell find . -name '__pycache__' )

venv:			$(VENV)
	@echo; echo "*** Activating $< VirtualEnv for Interactive $(SHELL)"
	@bash --init-file $</bin/activate -i

$(VENV):
	@echo; echo "*** Building $@ VirtualEnv..."
	@rm -rf $@ && $(PY3) -m venv $(VENV_OPTS) $@ \
	    && source $@/bin/activate \
	    && make install
