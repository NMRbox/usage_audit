.DEFAULT_GOAL := build
SHELL := /bin/bash
IDIR := /opt/nmrbox.d/usage_audit
PYTHON := python3.12

$(IDIR):
	$(PYTHON) -m venv $(IDIR)
	

$(IDIR)/bin/setup_nmrbox_audit: | $(IDIR) 
	$(IDIR)/bin/pip install .

usage_audit:  $(IDIR)/bin/setup_nmrbox_audit
	cp -r $(IDIR) usage_audit 

build: usage_audit 
	
clean:
	rm -fr $(IDIR) usage_audit 
