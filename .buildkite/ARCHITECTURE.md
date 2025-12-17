# Pipeline Structure Overview

## Architecture

```
pipeline.yml (Orchestrator)
│
├─> pipeline.quality.yml (All events)
│   ├── clang-format
│   ├── bpftrace-tidy
│   ├── clang-tidy
│   └── stdlib-docs
│
├─> pipeline.ci.yml (master, release/*, PRs)
│   └── Matrix: 10 configurations
│       ├── LLVM 17 Debug
│       ├── LLVM 18 Debug
│       ├── LLVM 19 Debug
│       ├── LLVM 20 Debug
│       ├── LLVM 21 Release
│       ├── LLVM 21 Debug
│       ├── LLVM 21 Clang Debug
│       ├── Fuzzing
│       ├── Latest kernel (6.14)
│       └── AOT Tests
│
├─> pipeline.distros.yml (master, release/*)
│   └── Matrix: 4 distributions
│       ├── Alpine
│       ├── Debian
│       ├── Fedora
│       └── Ubuntu
│
├─> pipeline.binary.yml (master, release/*)
│   ├── Static Build
│   └── Matrix: 2 architectures
│       ├── AppImage x86_64
│       └── AppImage ARM64
│
├─> pipeline.codeql.yml (master, release/*)
│   ├── CodeQL C++
│   └── CodeQL Python
│
└─> pipeline.release.yml (tags only)
    └── Build & Upload Release Artifacts
```

## Trigger Conditions

| Event Type | Quality | CI | Distros | Binary | CodeQL | Release |
|------------|---------|----|---------|---------| -------|---------|
| PR         | ✓       | ✓  | ✗       | ✗       | ✗      | ✗       |
| Push to master | ✓   | ✓  | ✓       | ✓       | ✓      | ✗       |
| Push to release/* | ✓ | ✓ | ✓      | ✓       | ✓      | ✗       |
| Tag (release) | ✓    | ✗  | ✗       | ✗       | ✗      | ✓       |

## Matrix Configurations

### CI Matrix (10 parallel jobs)
Each matrix job runs the full build, test, and validation suite with different configurations.

### Distros Matrix (4 parallel jobs)
Each job builds in a different Linux distribution Docker container.

### Binary Matrix (2 parallel jobs)
Each job builds an AppImage for a specific architecture (requires corresponding agent).

## Migration from GitHub Actions

| GitHub Actions Workflow | Buildkite Pipeline |
|-------------------------|-------------------|
| ci.yml                  | pipeline.ci.yml (matrix) |
| distros.yml             | pipeline.distros.yml (matrix) |
| static.yml              | pipeline.binary.yml |
| binary.yml              | pipeline.binary.yml (matrix) |
| bpftrace-tidy.yml       | pipeline.quality.yml |
| clang-tidy.yml          | pipeline.quality.yml |
| stdlib-docs.yml         | pipeline.quality.yml |
| codeql.yml              | pipeline.codeql.yml |
| release.yml             | pipeline.release.yml |
| issue-metrics.yml       | Not migrated (GitHub-specific) |
| flakehub.yml            | Not migrated (consider keeping on GHA) |
