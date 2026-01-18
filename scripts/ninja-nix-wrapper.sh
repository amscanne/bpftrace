#!/usr/bin/env bash

set -e

# Execute in the nix environment.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec nix develop "$SCRIPT_DIR" --command ninja "$@"
