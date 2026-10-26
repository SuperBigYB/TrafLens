PYTHON ?= python3
INTERFACES ?=
PREFLIGHT_ARGS := $(foreach interface,$(INTERFACES),--interface $(interface))

.PHONY: preflight test protocol-test server
preflight:
	$(PYTHON) scripts/preflight.py $(PREFLIGHT_ARGS)

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

protocol-test:
	bash protocol-smoke/run.sh

server:
	bash scripts/server-build.sh
