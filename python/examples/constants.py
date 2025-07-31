#!/usr/bin/env python3
"""
Example demonstrating constant resolution from Python globals.
"""

import bpftrace

# Global constants that should be resolved at transpilation time
foo = 0
bar = 42
message = "Hello from bpftrace"
debug_enabled = True
max_count = 100

# Maps
x = bpftrace.ArrayMap(10)
counters = bpftrace.HashMap()

@bpftrace.kprobe("myfunc")
def trace_func():
    """This function will be transpiled with constant resolution."""
    # This should resolve to: $f = 0
    f = foo
    
    # This should resolve to: $b = 42
    b = bar
    
    # This should resolve to: $msg = "Hello from bpftrace"
    msg = message
    
    # This should resolve to: $enabled = 1
    enabled = debug_enabled
    
    # Use constants in expressions
    x[0] = foo + bar  # Should become: @x[0] = (0 + 42)
    
    # Use in conditions
    if foo == 0:  # Should become: if (0 == 0)
        x[1] = max_count  # Should become: @x[1] = 100
    
    # Mix constants and variables
    for i in range(foo, bar):  # Should become range(0, 42)
        counters[i] = i * max_count  # @counters[$i] = ($i * 100)

@bpftrace.tracepoint("syscalls:sys_enter_openat")
def trace_openat():
    """Another function using constants."""
    if debug_enabled:  # Should become: if (1)
        print(message)  # Should become: printf("%s\n", "Hello from bpftrace")

def main():
    print("=== Constant Resolution Demo ===")
    print()
    
    print("Python constants:")
    print(f"foo = {foo}")
    print(f"bar = {bar}")
    print(f"message = '{message}'")
    print(f"debug_enabled = {debug_enabled}")
    print(f"max_count = {max_count}")
    print()
    
    print("Generated bpftrace script with resolved constants:")
    bpftrace.start()

if __name__ == "__main__":
    main()