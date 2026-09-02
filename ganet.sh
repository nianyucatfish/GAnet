#!/bin/sh
# GAnet launcher for macOS/Linux. Mirrors ganet.cmd: run the user center under
# the GenericAgent Python recorded by `configure-host`, from any working directory.
set -eu
GANET_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GANET_PYTHON_SHIM="$HOME/.genericagent/ganet/ga_python.sh"

GANET_PYTHON=""
if [ -f "$GANET_PYTHON_SHIM" ]; then
  # The shim contains a single `GANET_PYTHON=<quoted path>` assignment.
  . "$GANET_PYTHON_SHIM"
fi

if [ -z "$GANET_PYTHON" ]; then
  echo "GAnet host binding is missing." >&2
  echo "Ask GenericAgent to configure device interconnect first." >&2
  exit 1
fi
if [ ! -x "$GANET_PYTHON" ]; then
  echo "The bound GenericAgent Python no longer exists." >&2
  echo "Ask GenericAgent to repair device interconnect." >&2
  exit 1
fi

export PYTHONPATH="$GANET_ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$GANET_PYTHON" -m ganet "$@"
