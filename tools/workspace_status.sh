#!/bin/bash

# Get the current git tag
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")

if [[ -n "$GIT_TAG" && "$GIT_TAG" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    # Extract version components from tag like v0.23.0
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
else
    # Fallback to git describe or default values
    GIT_DESCRIBE=$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")

    # Try to extract version from the most recent tag
    RECENT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    if [[ -n "$RECENT_TAG" && "$RECENT_TAG" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        MAJOR="${BASH_REMATCH[1]}"
        MINOR="${BASH_REMATCH[2]}"
        PATCH="${BASH_REMATCH[3]}"
        # Add a suffix to indicate this is not an exact tag match
        GIT_TAG="${RECENT_TAG}-dev"
    else
        # Ultimate fallback
        MAJOR="0"
        MINOR="23"
        PATCH="0"
        GIT_TAG="v0.23.0-dev"
    fi
fi

# Get git commit info
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_COMMIT_DATE=$(git log -1 --format=%cd --date=iso 2>/dev/null || echo "unknown")

# Output stable status (changes rarely, cached)
echo "STABLE_GIT_TAG $GIT_TAG"

# Output volatile status (changes frequently, not cached)
echo "BUILD_TIMESTAMP $(date +%s)"
echo "GIT_COMMIT $GIT_COMMIT"
echo "GIT_COMMIT_SHORT $GIT_COMMIT_SHORT"
echo "GIT_COMMIT_DATE $GIT_COMMIT_DATE"
echo "VERSION_MAJOR $MAJOR"
echo "VERSION_MINOR $MINOR"
echo "VERSION_PATCH $PATCH"
