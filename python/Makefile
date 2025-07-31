# Simple Makefile for bpftrace Python transpiler

.PHONY: test examples clean install dev-install

# Run tests
test:
	python3 -m unittest test_bpftrace.py -v

# Run examples
examples:
	@echo "Running simple example:"
	python3 examples/simple.py
	@echo "\nRunning constants example:"
	python3 examples/constants.py

# Clean up generated files
clean:
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/

# Install the package
install:
	pip3 install .

# Install in development mode
dev-install:
	pip3 install -e .

# Run a quick smoke test
smoke-test:
	python3 -c "import bpftrace; print('Import successful')"

# Show help
help:
	@echo "Available targets:"
	@echo "  test        - Run unit tests"
	@echo "  examples    - Run example scripts"
	@echo "  clean       - Clean up generated files"
	@echo "  install     - Install the package"
	@echo "  dev-install - Install in development mode"
	@echo "  smoke-test  - Quick import test"
	@echo "  help        - Show this help"
