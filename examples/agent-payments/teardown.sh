#!/bin/sh
# Removes the example's containers, volumes and runtime/ directory.
set -eu
cd "$(dirname "$0")"
exec node demo.mjs down
