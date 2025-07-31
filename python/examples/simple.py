#!/usr/bin/env python3
"""
Example usage of the simple bpftrace API.

This demonstrates the exact API you requested.
"""

import bpftrace

# Create a map that can be shared between Python and bpftrace
x = bpftrace.ArrayMap(10)

@bpftrace.kprobe("sys_openat")
def fn():
    """This function will be transpiled to bpftrace."""
    x[4] = 3  # This reference will be resolvable
    x[5] = x[4] + 1

    # Some control flow
    if x[4] > 0:
        x[6] = 100

    # A simple loop
    for i in range(3):
        x[i] = i * 2

# Another example with different probe type
y = bpftrace.HashMap()

@bpftrace.tracepoint("syscalls:sys_enter_write")
def write_tracker():
    """Track write system calls."""
    y[1] = y[1] + 1  # Count writes
    if y[1] > 10:
        print("Many writes detected!")

def main():
    print("=== Simple bpftrace API Demo ===")
    print()

    # Show initial map state
    print("Initial map state:")
    print(f"x[4] = {x.get(4)}")
    print(f"y[1] = {y.get(1)}")
    print()

    # Start bpftrace (this will generate and show the script)
    bpftrace.start()

    # After bpftrace runs, you could read values like:
    # print(f"Final x[4] = {x.get(4)}")

if __name__ == "__main__":
    main()
