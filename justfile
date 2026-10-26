# wired build. libc-free, x86_64-linux only.
#
# Comments: the line right above a recipe is its `just --list` summary.
# Every recipe body is at most two lines; anything longer lives in
# scripts/just/ (shared helpers in lib.sh, the compile flags in flags.sh).

set ignore-comments

# --- environment ------------------------------------------------------------

# One-time bootstrap: install nix when absent.
setup:
    @sh scripts/just/setup.sh

# Run any recipe inside the flake devShell, e.g. `just nix test`.
nix +args:
    nix develop -c just {{ args }}

# --- build ------------------------------------------------------------------

# Full build: fmt + freestanding compile (ninja) + lint.
build:
    sh scripts/just/build.sh

# Regenerate build.ninja from the current source list.
gen-ninja:
    sh scripts/gen_ninja.sh

# Compile freestanding (all of src/, or the named ninja targets).
ninja *targets: gen-ninja
    # No targets = every src/**/*.c into build/<path>.o (the libc-independence
    # proof). Targets: examples/<name>/wired_server, guide, build/src/<path>.o.
    ninja {{ targets }}

# Archive the SDK objects into build/libwired.a.
lib: gen-ninja
    # sys.o is left out: applications supply their own _start.
    ninja build/libwired.a

# Emit compile_commands.json for clangd/IDEs.
compdb: gen-ninja
    ninja -t compdb > compile_commands.json

# --- test -------------------------------------------------------------------

# Run all tests (hosted, assertions on): the single-TU build CI gates on.
test: fmt gen-ninja
    sh scripts/just/test.sh

# Same tests as `test`, ~3x faster (parallel shard TUs).
test-fast: fmt gen-ninja
    sh scripts/just/test.sh --fast

# CI only: the unity test under ASan + UBSan (slow).
test-san: gen-ninja
    sh scripts/just/test.sh --san

# ccn + test.
check: ccn test

# CCN <= 3 and nesting depth <= 2 for every C function (lizard).
ccn *paths="src examples/*/*.c examples/*/*.h":
    # Default is src/ and the examples' C (the gate); pass files to measure
    # only those.
    # The nesting limit is the tree's maximum when it was set.
    lizard {{ paths }} --CCN 3 -END -T max_nesting_depth=2 -w

# Report only: function NLOC/CCN/length/nesting (ND) and file NLOC (lizard).
metrics *paths="src":
    sh scripts/just/metrics.sh {{ paths }}

# Report only: Halstead, maintainability index, exits and parameters.
halstead *paths="src":
    sh scripts/just/rca.sh {{ paths }}

# Halstead/MI/exits/parameter limits per function and file (rust-code-analysis).
halstead-check *paths="src examples/*/*.c examples/*/*.h scripts":
    sh scripts/just/rca.sh --check {{ paths }}

# Report only: per-function cognitive complexity; 0 scores are not listed.
cognitive *paths="src":
    sh scripts/just/cognitive.sh {{ paths }}

# Check every src/**/*.c is in tests/run.c once and builds one object.
wire-check: ninja
    sh scripts/just/wire_check.sh

# Line coverage of the unity test (LLVM source-based).
cov: fmt gen-ninja
    sh scripts/just/cov.sh

# CI only: production build with UBSan/bounds traps, run by the guide snippets.
san-check *ids: gen-ninja
    # No ids = all snippets. Needs go + node 22 on PATH.
    sh scripts/just/san_check.sh {{ ids }}

# Run the unity test binary under valgrind --track-origins.
valgrind: gen-ninja
    sh scripts/just/valgrind.sh

# Verify tests/app/moqt_golden.h has no drift.
golden-check:
    sh scripts/just/golden_check.sh

# Requirement ledgers: test links resolve, IDs unique, coverage counts match.
features-check:
    python3 scripts/check_features.py

# Python: ruff, unittests, CCN <= 3.
py-check:
    sh scripts/just/py_check.sh

# Vulnerability ledger: row rules plus reachability of every closed row's
# cited code (from examples/) and test (from tests/run.c).
vuln-check:
    python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md

# Shell: shellcheck every tracked .sh; justfile in `just --fmt` form.
sh-check:
    sh scripts/just/sh_check.sh

# moqt_chat frontend and e2e: biome, tsc, unit tests, complexity limits.
js-check:
    sh scripts/just/js_check.sh

# --- fuzz -------------------------------------------------------------------

# Per-PR gate: every fuzz harness builds and survives one run.
fuzz-smoke: gen-ninja
    sh scripts/just/fuzz.sh smoke

# Nightly sweep: every fuzz harness for secs seconds each.
fuzz-ci secs="120": gen-ninja
    sh scripts/just/fuzz.sh ci {{ secs }}

# --- format & lint (pinned toolchain) ---------------------------------------

# Format the C sources in place with the pinned clang-format.
fmt:
    sh scripts/just/fmt.sh

# Verify C formatting without writing (fails on diff).
fmt-check:
    sh scripts/just/fmt.sh --check

# Static analysis (CERT C + bug finders); any warning fails.
lint: gen-ninja
    sh scripts/just/lint.sh

# --- docs -------------------------------------------------------------------

# Regenerate the public-API reference into docs/sdk (doxygen).
docs:
    sh scripts/just/docs.sh

# Build and run the guide snippets, compare with their golden.txt.
guide-verify *ids: (ninja "guide")
    # No ids = all. Needs go + node 22 on PATH.
    cd guide && node runner/run.ts {{ ids }}
