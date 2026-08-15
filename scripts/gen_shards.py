#!/usr/bin/env python3
"""Split tests/run.c into K shard TUs for parallel compilation.

tests/run.c stays the single source of truth (its include list and main()
calls); this script only regroups them. The single-TU `just test` remains
the commit gate -- shards cannot detect cross-TU static/typedef/macro
collisions, so `test-fast` is a fast dev-loop approximation only.

Tests call static functions of their production .c directly, so each
production file and its *_test.c MUST land in the same shard TU. The
mapping is derived from the test filename: strip `_test.c`, then match
the stem (dropping trailing `_component`s until a hit) against directory
components or basenames of the production include paths. Names that the
rule cannot resolve live in OVERRIDES; an unresolved test is a hard error
so a new test can never be silently dropped.
"""

import os
import re
import sys

RUN_C = "tests/run.c"
OUT_DIR = "build/shards"
K = 8  # fixed: >8 cores gain nothing (largest domain shard is the limit)

# test stem -> production group dir (as it appears in run.c includes).
OVERRIDES = {
    "gcm256": "crypto/symmetric/aead/gcm",
    "packet2": "transport/packet/header/packet",
    "h3control": "app/http3/core/h3",
    "h3frame": "app/http3/core/h3",
    "h3grease": "app/http3/core/h3",
    "h3stream_type": "app/http3/core/h3",
    "h3method": "app/http3/core/h3",
    "rsachain": "crypto/pki/trust/castore",
    "p256field_n": "crypto/asymmetric/ecc/p256",
    "ecdsa_p384_verify": "crypto/asymmetric/ecc/p384",
    "p384chain": "crypto/pki/trust/castore",
    "versdowngrade": "transport/version/versmgr",
    "sigmask": "app/http3/server/sigterm",
    "wt_session": "app/webtransport/session/session",
    "wterrmap": "app/webtransport/errmap/errmap",
    "v2ku_appendix": "tls/keys/keyupdate",
}

# Tests that share static helpers (or a production-static counter) across
# files must land in the same shard TU. Entries are test stems or, with a
# '/', production group dirs; each cluster's groups are merged. Public
# cross-domain symbols need no entry here -- every shard includes all
# production headers, so only true statics force co-location.
COLOCATE = [
    # appdata_{frame,send,recv}_flat live in stream_send_test.c
    ["stream_send", "app_send", "app_recv", "h3conn_roundtrip", "srvloop",
     "h3reqdrive", "client_wire", "tparam", "h3settings_control_open"],
    # client_open_onertt / lp_confirm live in srvloop_test.c;
    # srvrun_conn / wired_srvrun_env are TU-local types in srvrun.c;
    # srvboot_acc_admit is a static in srvboot.c
    # srvdriver/srvthreads tests also use TU-locals of srvthreads.c and
    # srvrun.c (srvthreads_worker_arg, srvrun_broadcast_to_all)
    ["srvloop", "srvrun", "srvinbox", "h3_loopback", "srvdriver",
     "app/http3/server/srvboot", "app/http3/server/srvthreads"],
    # x25519_mult_count is a static in tls core's x25519.c
    ["server", "tls/handshake/core/tls"],
    # p256_field_test uses `fe`, a TU-local typedef of ed25519_field.c
    # that leaks across the unity TU
    ["p256_field", "crypto/asymmetric/ecc/ed25519"],
]


def parse_run_c():
    prod, tests, calls = [], [], []
    for line in open(RUN_C):
        m = re.match(r'#include "(.+\.c)"', line)
        if m:
            (tests if m.group(1).endswith("_test.c") else prod).append(m.group(1))
            continue
        m = re.match(r"\s*(test_\w+)\(\);", line)
        if m:
            calls.append(m.group(1))
    return prod, tests, calls


class Groups:
    """Production includes grouped by directory, union-find mergeable."""

    def __init__(self, prod):
        self.keys = []  # group dir, first-appearance order
        self.members = {}  # key -> [prod include]
        self.parent = {}  # union-find
        for p in prod:
            d = os.path.dirname(p)
            if d not in self.members:
                self.keys.append(d)
                self.members[d] = []
                self.parent[d] = d
            self.members[d].append(p)

    def find(self, k):
        while self.parent[k] != k:
            k = self.parent[k]
        return k

    def union(self, keys):
        root = self.find(keys[0])
        for k in keys[1:]:
            self.parent[self.find(k)] = root
        return root

    def match(self, stem):
        """Most-specific tier wins: a file stem.c, then a group dir named
        stem, then any path component == stem. Without the tiers a broad
        component like `conn` or `server` unions dozens of groups into one
        mega-shard and the parallelism is gone."""
        by_file, by_dir, by_comp = [], [], []
        for k in self.keys:
            if any(os.path.basename(p) == stem + ".c" for p in self.members[k]):
                by_file.append(k)
            elif os.path.basename(k) == stem:
                by_dir.append(k)
            elif stem in k.split("/"):
                by_comp.append(k)
        return by_file or by_dir or by_comp


def resolve(groups, test):
    stem = os.path.basename(test)[: -len("_test.c")]
    if stem in OVERRIDES:
        return groups.union([OVERRIDES[stem]])
    s = stem
    while s:
        hits = groups.match(s)
        if hits:
            # a test bridging several dirs needs them co-located (statics)
            return groups.union(hits)
        if "_" not in s:
            break
        s = s.rsplit("_", 1)[0]
    sys.exit("gen_shards: UNRESOLVED test %s -- add to OVERRIDES" % test)


def test_functions(test):
    """Entry functions defined in a test file (static ones included: the
    shard entry lives in the same TU, exactly like run.c's main)."""
    src = open(os.path.join("tests", test)).read()
    return re.findall(r"^(?:static )?void (test_\w+)\(void\)", src, re.M)


def write_if_changed(path, content):
    if os.path.exists(path) and open(path).read() == content:
        return
    with open(path, "w") as f:
        f.write(content)


def main():
    prod, tests, calls = parse_run_c()
    for lst, what in ((prod, "production"), (tests, "test")):
        if len(set(lst)) != len(lst):
            sys.exit("gen_shards: duplicate %s include in run.c" % what)

    groups = Groups(prod)
    assign = {t: resolve(groups, t) for t in tests}  # test -> group root
    stem_root = {
        os.path.basename(t)[: -len("_test.c")]: r for t, r in assign.items()
    }
    for cluster in COLOCATE:
        groups.union([k if "/" in k else stem_root[k] for k in cluster])

    # merged group -> its production files and tests, weighted by file size
    merged = {}
    for k in groups.keys:
        merged.setdefault(groups.find(k), []).append(k)
    weight, gtests = {}, {r: [] for r in merged}
    for r, ks in merged.items():
        weight[r] = sum(
            os.path.getsize(os.path.join("src", p))
            for k in ks
            for p in groups.members[k]
        )
    for t, r in assign.items():
        gtests[groups.find(r)].append(t)
        weight[groups.find(r)] += os.path.getsize(os.path.join("tests", t))

    # LPT: heaviest merged group first into the lightest shard
    shards = [{"w": 0, "roots": []} for _ in range(K)]
    for r in sorted(merged, key=lambda r: -weight[r]):
        s = min(shards, key=lambda s: s["w"])
        s["w"] += weight[r]
        s["roots"].append(r)

    # every shard sees every production header: in the unity TU all
    # production .c precede all tests, so tests freely use cross-domain
    # public declarations; the headers restore that visibility per shard.
    headers = sorted(
        os.path.relpath(os.path.join(d, f), "src")
        for d, _, fs in os.walk("src")
        for f in fs
        if f.endswith(".h")
    )

    prod_order = {p: i for i, p in enumerate(prod)}
    test_order = {t: i for i, t in enumerate(tests)}
    call_order = {c: i for i, c in enumerate(calls)}
    fn_of, emitted_calls = {}, []
    os.makedirs(OUT_DIR, exist_ok=True)

    for n, s in enumerate(shards):
        sprod = sorted(
            (p for r in s["roots"] for k in merged[r] for p in groups.members[k]),
            key=prod_order.get,
        )
        stests = sorted(
            (t for r in s["roots"] for t in gtests[r]), key=test_order.get
        )
        fns = []
        for t in stests:
            for fn in test_functions(t):
                if fn not in call_order:
                    continue  # helper called from another test_*, not main
                if fn in fn_of:
                    sys.exit("gen_shards: %s defined in %s and %s" % (fn, fn_of[fn], t))
                fn_of[fn] = t
                fns.append(fn)
        fns.sort(key=lambda f: call_order.get(f, -1))
        emitted_calls.extend(fns)
        lines = ["/* generated by scripts/gen_shards.py -- do not edit */"]
        lines.append('#include "test.h"')
        lines += ['#include "%s"' % h for h in headers]
        lines += ['#include "%s"' % p for p in sprod]
        lines += ['#include "%s"' % t for t in stests]
        lines.append("int wired_test_shard_%d(void) {" % n)
        lines += ["  %s();" % fn for fn in fns]
        lines.append("  return quic_test_fails;")
        lines.append("}")
        write_if_changed(os.path.join(OUT_DIR, "shard_%d.c" % n), "\n".join(lines) + "\n")

    # invariants: run.c is fully covered, nothing extra, call counts agree
    if sorted(fn_of) != sorted(calls):
        sys.exit(
            "gen_shards: test call mismatch vs run.c main: shards=%d run.c=%d "
            "(missing: %s extra: %s)"
            % (
                len(fn_of),
                len(calls),
                sorted(set(calls) - set(fn_of)),
                sorted(set(fn_of) - set(calls)),
            )
        )
    covered = [p for s in shards for r in s["roots"] for k in merged[r] for p in groups.members[k]]
    if sorted(covered) != sorted(prod):
        sys.exit("gen_shards: production include set differs from run.c")

    lines = ["/* generated by scripts/gen_shards.py -- do not edit */"]
    lines.append("#include <stdio.h>")
    lines += ["int wired_test_shard_%d(void);" % n for n in range(K)]
    lines.append("int main(void) {")
    lines.append("  int fails = 0;")
    lines += ["  fails += wired_test_shard_%d();" % n for n in range(K)]
    lines.append('  if (fails) { printf("%d failure(s)\\n", fails); return 1; }')
    lines.append('  printf("all tests passed\\n");')
    lines.append("  return 0;")
    lines.append("}")
    write_if_changed(os.path.join(OUT_DIR, "shard_main.c"), "\n".join(lines) + "\n")
    print(
        "gen_shards: %d shards, %d prod, %d tests, %d calls"
        % (K, len(prod), len(tests), len(emitted_calls))
    )


if __name__ == "__main__":
    main()
