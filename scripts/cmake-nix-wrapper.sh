#!/usr/bin/env bash

set -e

# Run cmake inside the nix development environment.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec nix develop "$SCRIPT_DIR" --command cmake "$@"
