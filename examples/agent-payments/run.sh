#!/bin/sh
# Starts the regtest stack and runs the safe agent payments story.
# The stack stays up afterwards; ./teardown.sh removes it.
set -eu
cd "$(dirname "$0")"
exec node demo.mjs "$@"
