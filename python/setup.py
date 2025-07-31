#!/usr/bin/env python3
"""
Setup script for bpftrace Python transpiler.
"""

from setuptools import setup

setup(
    name="bpftrace-python",
    version="0.1.0",
    description="Python to bpftrace transpiler",
    author="bpftrace contributors",
    py_modules=["bpftrace"],
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Monitoring",
    ],
)
