#!/bin/sh
# Berkeley `size` over the given binaries -- raw output; lib/aggregate.mjs
# parses it. Usage: sections.sh <binary>...
exec size "$@"
