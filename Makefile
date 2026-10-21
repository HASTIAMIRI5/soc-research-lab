#!/usr/bin/env python3
"""Convenience commands for the SOC Research Lab project."""

.PHONY: demo test lint

PYTHON ?= python3

help:
	@echo "Available targets: demo, test"

demo:
	$(PYTHON) scripts/run_demo.py

test:
	$(PYTHON) -m unittest discover -s tests -v
