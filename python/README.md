# bpftrace Python Transpiler

A simple Python module that transpiles Python functions to bpftrace scripts using decorators and map objects.

## Quick Start

```python
import bpftrace

# Create maps
x = bpftrace.ArrayMap(10)
counters = bpftrace.HashMap()

# Global constants (resolved at transpilation time)
MAX_COUNT = 100
DEBUG = True

@bpftrace.kprobe("sys_openat")
def trace_openat():
    x[4] = 3
    if DEBUG:  # Becomes: if (1)
        x[5] = MAX_COUNT  # Becomes: @x[5] = 100

    for i in range(5):
        counters[i] = i * 2

# Generate and show the bpftrace script
bpftrace.start()
```

## Features

- **Simple decorator API**: `@bpftrace.kprobe()`, `@bpftrace.uprobe()`, `@bpftrace.tracepoint()`
- **Map objects**: `ArrayMap` and `HashMap` classes shared between Python and bpftrace
- **Constant resolution**: Python globals resolved at transpilation time
- **Control flow**: if/else, for loops, while loops
- **No external dependencies**: Uses only Python standard library

## Installation

```bash
# Install from source
pip install .

# Or install in development mode
pip install -e .
```

## Development

```bash
# Run tests
make test

# Run examples
make examples

# Clean up
make clean

# Show all available targets
make help
```

## File Structure

```
python/
├── bpftrace.py          # Main transpiler module
├── test_bpftrace.py     # Unit tests
├── examples/            # Example scripts
│   ├── simple.py        # Basic usage example
│   └── constants.py     # Constant resolution example
├── setup.py             # Package setup
├── Makefile             # Development tasks
├── requirements.txt     # Dependencies (none required)
└── README.md           # This file
```

## API Reference

### Maps

- `ArrayMap(size, name=None)` - Fixed-size array map
- `HashMap(name=None)` - Hash map with dynamic keys

### Decorators

- `@bpftrace.kprobe(target)` - Kernel probe
- `@bpftrace.uprobe(target)` - User-space probe
- `@bpftrace.tracepoint(target)` - Tracepoint

### Functions

- `bpftrace.start()` - Generate and display the bpftrace script

## Generated Code Example

Python:
```python
foo = 42
x = bpftrace.ArrayMap(10)

@bpftrace.kprobe("sys_open")
def trace():
    x[0] = foo
    if foo > 0:
        x[1] = 1
```

Generated bpftrace:
```bpftrace
#!/usr/bin/env bpftrace

@x[int64] = int64;

kprobe:sys_open
{
    @x[0] = 42;
    if ((42 > 0)) {
        @x[1] = 1;
    }
}

END
{
    // Script ended
}
```
