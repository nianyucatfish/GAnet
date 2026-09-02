#!/bin/sh
# Finder double-click entry on macOS: opens Terminal and runs the GAnet launcher.
exec "$(dirname -- "$0")/ganet.sh" "$@"
