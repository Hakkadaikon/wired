"""How gen_shards.py groups run.c's files: production includes by directory
(union-find), each *_test.c onto the group whose statics it uses, clusters
that share statics merged, then the merged groups packed into K shards.

The test -> group mapping is derived from the test filename: strip
`_test.c`, then match the stem (dropping trailing `_component`s until a hit)
against directory components or basenames of the production include paths.
Names that the rule cannot resolve live in OVERRIDES; an unresolved test is
a hard error so a new test can never be silently dropped.
"""

import os
import sys

K = 8  # fixed: >8 cores gain nothing (largest domain shard is the limit)
NO_HIT = 3  # Groups._tier index of a key the stem does not match

# test stem -> production group dir (as it appears in run.c includes).
OVERRIDES = {
    "gcm256": "crypto/symmetric/aead/gcm",
    "bssl_aes128gcm": "crypto/symmetric/aead/gcm",
    "bssl_aes256gcm": "crypto/symmetric/aead/gcm",
    "bssl_chacha20poly1305": "crypto/symmetric/aead/chacha",
    "packet2": "transport/packet/header/packet",
    "h3control": "app/http3/core/h3",
    "h3frame": "app/http3/core/h3",
    "h3grease": "app/http3/core/h3",
    "h3reqgrease": "app/http3/server/srvloop",
    "udpfam": "transport/io/socket/io",
    "h3stream_type": "app/http3/core/h3",
    "h3method": "app/http3/core/h3",
    "rsachain": "crypto/pki/trust/castore",
    "p256field_n": "crypto/asymmetric/ecc/p256",
    "ecdsa_diff": "crypto/asymmetric/ecc/p256",
    "ecdsa_p384_verify": "crypto/asymmetric/ecc/p384",
    "ecdsa_p521_verify": "crypto/asymmetric/ecc/p521",
    "bssl_ecdsa": "crypto/asymmetric/ecc/p256",
    "bssl_hmac": "crypto/symmetric/hash/hash",
    "wyc_rsa_pkcs1": "crypto/asymmetric/rsa",
    "wyc_rsa_pss": "crypto/asymmetric/rsa",
    "wyc_aesgcm": "crypto/symmetric/aead/gcm",
    "wyc_chacha20poly1305": "crypto/symmetric/aead/chacha",
    "wyc_hmac_sha256": "crypto/symmetric/hash/hash",
    "wyc_hkdf_sha256": "crypto/kdf/hkdf",
    "wyc_x25519": "tls/handshake/core/tls",
    "wyc_ed25519": "crypto/asymmetric/ecc/ed25519",
    "wyc_ecdsa": "crypto/asymmetric/ecc/p256",
    "p384chain": "crypto/pki/trust/castore",
    "p521chain": "crypto/pki/trust/castore",
    "versdowngrade": "transport/version/versmgr",
    "sigmask": "app/http3/server/sigterm",
    "wt_session": "app/webtransport/session/session",
    "wterrmap": "app/webtransport/errmap/errmap",
    "v2ku_appendix": "tls/keys/keyupdate",
    "bssl_ed25519": "crypto/asymmetric/ecc/ed25519",
    "bssl_x25519": "tls/handshake/core/tls",
}

# Tests that share static helpers (or a production-static counter) across
# files must land in the same shard TU. Entries are test stems or, with a
# '/', production group dirs; each cluster's groups are merged. Public
# cross-domain symbols need no entry here -- every shard includes all
# production headers, so only true statics force co-location.
COLOCATE = [
    # appdata_{frame,send,recv}_flat live in stream_send_test.c
    [
        "stream_send",
        "app_send",
        "app_recv",
        "h3conn_roundtrip",
        "srvloop",
        "h3reqdrive",
        "client_wire",
        "tparam",
        "h3settings_control_open",
    ],
    # client_open_onertt / lp_confirm live in srvloop_test.c;
    # srvrun_conn / wired_srvrun_env are TU-local types in srvrun.c;
    # srvboot_acc_admit is a static in srvboot.c
    # srvdriver/srvthreads tests also use TU-locals of srvthreads.c and
    # srvrun.c (srvthreads_worker_arg, srvrun_broadcast_to_all)
    [
        "srvloop",
        "srvrun",
        "srvinbox",
        "h3_loopback",
        "srvdriver",
        "app/http3/server/srvboot",
        "app/http3/server/srvthreads",
    ],
    # x25519_mult_count is a static in tls core's x25519.c
    ["server", "tls/handshake/core/tls"],
    # p256_field_test uses `fe`, a TU-local typedef of ed25519_field.c
    # that leaks across the unity TU
    ["p256_field", "crypto/asymmetric/ecc/ed25519"],
]


class Groups:
    """Production includes grouped by directory, union-find mergeable."""

    def __init__(self, prod):
        self.keys = []  # group dir, first-appearance order
        self.members = {}  # key -> [prod include]
        self.parent = {}  # union-find
        for p in prod:
            self._add(os.path.dirname(p), p)

    def _add(self, d, p):
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

    def _has_file(self, k, stem):
        return any(os.path.basename(p) == stem + ".c" for p in self.members[k])

    def _tier(self, k, stem):
        if self._has_file(k, stem):
            return 0
        if os.path.basename(k) == stem:
            return 1
        return {True: 2, False: NO_HIT}[stem in k.split("/")]

    def match(self, stem):
        """Most-specific tier wins: a file stem.c, then a group dir named
        stem, then any path component == stem. Without the tiers a broad
        component like `conn` or `server` unions dozens of groups into one
        mega-shard and the parallelism is gone."""
        tiers = ([], [], [], [])  # by_file, by_dir, by_comp, no hit
        for k in self.keys:
            tiers[self._tier(k, stem)].append(k)
        return next(filter(None, tiers[:NO_HIT]), [])

    def prod_of(self, merged, r):
        """Production includes of merged group r, in group order."""
        return [p for k in merged[r] for p in self.members[k]]


def stem_of(test):
    return os.path.basename(test)[: -len("_test.c")]


def candidates(stem):
    """stem, then stem with trailing `_component`s dropped one at a time."""
    parts = stem.split("_")
    return list(filter(None, ("_".join(parts[:i]) for i in range(len(parts), 0, -1))))


def resolve(groups, test):
    stem = stem_of(test)
    if stem in OVERRIDES:
        return groups.union([OVERRIDES[stem]])
    hits = next(filter(None, map(groups.match, candidates(stem))), None)
    if hits:
        # a test bridging several dirs needs them co-located (statics)
        return groups.union(hits)
    sys.exit("gen_shards: UNRESOLVED test %s -- add to OVERRIDES" % test)


def _cluster_key(k, stem_root):
    return k if "/" in k else stem_root[k]


def _cluster_keys(cluster, stem_root):
    return [_cluster_key(k, stem_root) for k in cluster]


def colocate(groups, assign):
    stem_root = {stem_of(t): r for t, r in assign.items()}
    for cluster in COLOCATE:
        groups.union(_cluster_keys(cluster, stem_root))


def merge_groups(groups):
    """merged group root -> its group keys"""
    merged = {}
    for k in groups.keys:
        merged.setdefault(groups.find(k), []).append(k)
    return merged


def _src_size(p):
    return os.path.getsize(os.path.join("src", p))


def group_tests(groups, merged, assign, weight):
    """merged root -> its tests; adds each test's size to its root's weight."""
    gtests = {r: [] for r in merged}
    for t, r in assign.items():
        root = groups.find(r)
        gtests[root].append(t)
        weight[root] += os.path.getsize(os.path.join("tests", t))
    return gtests


def pack(merged, weight):
    """LPT: heaviest merged group first into the lightest shard"""
    shards = [{"w": 0, "roots": []} for _ in range(K)]
    for r in sorted(merged, key=lambda r: -weight[r]):
        s = min(shards, key=lambda s: s["w"])
        s["w"] += weight[r]
        s["roots"].append(r)
    return shards


def plan(prod, tests):
    """Group, co-locate and weigh run.c's files, then pack them into K shards."""
    groups = Groups(prod)
    assign = {t: resolve(groups, t) for t in tests}  # test -> group root
    colocate(groups, assign)
    merged = merge_groups(groups)
    weight = {r: sum(map(_src_size, groups.prod_of(merged, r))) for r in merged}
    gtests = group_tests(groups, merged, assign, weight)
    return {
        "groups": groups,
        "merged": merged,
        "gtests": gtests,
        "shards": pack(merged, weight),
    }
