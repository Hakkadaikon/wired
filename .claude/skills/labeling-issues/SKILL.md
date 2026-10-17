---
name: labeling-issues
description: >
  Labels GitHub issues in the wired repo with one area label (quic, recovery,
  tls, pki, http3, webtransport, moqt, datapath) plus a type label (bug,
  enhancement, question, documentation), and routes security
  vulnerabilities to a draft security advisory instead of a public issue.
  Use whenever an issue is filed, triaged, relabeled or bulk-created for
  this repo — e.g. "issueにして", "issueを起票", "ラベルを付けて",
  "triage these issues", or when turning ledger gaps / review findings into
  issues with `gh issue create`.
---

# labeling-issues

Every open issue in `Hakkadaikon/wired` carries **exactly one area label**
and **at least one type label**. Ledger-process issues (about
`docs/features/` bookkeeping itself, not about code) carry a type label
only.

## Area labels

Pick the layer whose code the fix will touch, not the spec the issue cites.

| Label | Covers | Typical code |
|---|---|---|
| `quic` | QUIC transport (RFC 9000/9001/8999), frames, streams, flow control, CIDs, migration, tokens, key update, version negotiation, QUIC v2, grease_quic_bit, spin bit, 0-RTT transport parameters | `src/transport/`, srvrun/srvloop transport paths |
| `recovery` | Loss detection, RTT, PTO, congestion control (RFC 9002), DPLPMTUD (RFC 8899), anything that decides *when or how much* to send | `cc`, `rtt`, `sendsess`, pmtu |
| `tls` | TLS 1.3 handshake, alerts, PSK/tickets, 0-RTT acceptance, SNI, ALPN | `src/tls/` |
| `pki` | X.509 parsing and path validation, certificate name matching (RFC 6125), key encodings, crypto primitives and their vectors | `src/crypto/` |
| `http3` | HTTP/3 (RFC 9114), QPACK, Extensible Priorities, HTTP semantics (RFC 9110) | `src/app/http3/`, `src/app/qpack/` |
| `webtransport` | WebTransport over HTTP/3, Capsule Protocol (RFC 9297), Extended CONNECT (RFC 9220) | `src/app/webtransport/`, srvrun WT paths |
| `moqt` | Media over QUIC Transport, all supported drafts in one issue | `src/app/moqt/`, moqtrun |
| `datapath` | IPv4/UDP headers, sockets, AF_XDP, packet I/O | `src/transport/io/` |

Boundary cases already decided — follow them so labels stay consistent:

- DATAGRAM bypassing congestion control, DATAGRAM PTO probes → `recovery`.
  A DATAGRAM *API* (priority, send call) → `quic`.
- A lost-retransmission rule ("do not retransmit acknowledged data") →
  `recovery`; ACK *generation* → `quic`.
- AF_XDP anything, including CID bytes chosen for core routing → `datapath`.
- X.509 name matching for TLS server identity → `pki`, not `tls`.
- CRYPTO frames per encryption level, TLS KeyUpdate inside QUIC → `quic`.
- 0-RTT refused because remembered QUIC transport parameters changed →
  `quic`; 0-RTT policy inside the TLS handshake (HRR, opt-in) → `tls`.
- HTTP/3 + QPACK in one issue → `http3`.
- If two areas really both change, file two issues and cross-link them
  ("Related: #N") rather than putting two area labels on one.

Examples:

| Title | Labels |
|---|---|
| QUIC: enforce the connection-level receive flow-control limit | `quic` `bug` |
| Recovery: adjust RTT samples by the peer's ACK Delay | `recovery` `bug` |
| DPLPMTUD: cap the probe search at the local interface MTU | `recovery` `enhancement` |
| X.509 name matching: skip the CN-ID fallback when a URI-ID is present | `pki` `bug` |
| HTTP: generate the Date header on responses | `http3` `bug` |
| AF_XDP IPv4 send: set DF and a unique Identification | `datapath` `bug` |
| Ledger rule: does a test of an uncalled helper count as [x]? | `question` `documentation` |

## Type labels

- `bug` — the server violates a MUST/MUST NOT, does something wrong, or
  sends the wrong error code.
- `enhancement` — a missing SHOULD/MAY, a missing feature or API, or a
  missing test vector.
- `question` — a decision someone has to make (scope, interpretation,
  wire or delete a module).
- `documentation` — docs or ledger bookkeeping only.

`question` and `documentation` may be combined; `bug` and `enhancement`
are exclusive.

## Security vulnerabilities: never a public issue

The repo is public. If the issue would let someone attack a deployment
(key or nonce reuse, authentication bypass, memory corruption reachable
from the wire, a fixed secret in shipped code), do NOT run
`gh issue create`. Ask the user first, and by default create a draft
repository security advisory, visible only to admins:

```sh
# advisory.json: {"summary": "...", "description": "...",
#   "severity": "critical|high|medium|low",
#   "vulnerabilities": [{"package": {"ecosystem": "other", "name": "wired"},
#                        "vulnerable_version_range": "<= <sha>"}]}
gh api -X POST repos/Hakkadaikon/wired/security-advisories \
  --input advisory.json -q '.html_url'
```

File the public issue only after the fix has landed, if at all.

## Commands

```sh
# new issue: area + type in one call
gh issue create --repo Hakkadaikon/wired --title "QUIC: ..." \
  --body-file body.md --label quic --label bug

# add a label without touching the existing ones
gh issue edit 123 --repo Hakkadaikon/wired --add-label recovery

# find open issues missing an area label (should print [])
gh issue list --repo Hakkadaikon/wired --state open --limit 500 \
  --json number,labels -q '[.[] | select([.labels[].name] |
  map(IN("quic","recovery","tls","pki","http3","webtransport","moqt",
  "datapath")) | any | not) | .number]'
```

The last command lists ledger-process issues too, by design. Check that
each number it prints is one of those before adding an area label.

## Bulk filing

When turning many findings into issues (for example, ledger gaps):

1. Draft every issue body to a file first, and review the drafts for
   duplicates against `gh issue list` before creating anything.
2. Merge a duplicate into the existing issue as a comment instead of
   filing it again.
3. Put the area label on at creation time; do not plan to relabel later.
4. Check the drafts for security items (see above), and move those out
   before the batch runs.
5. After the batch, run the missing-area query above. If it prints any
   number that is not a ledger-process issue, add its area label and run
   the query again until it does.

## Adding a new area label

Add one only when a new protocol domain lands under `src/`, or when an
existing label holds more than about 30 open issues that are fixed in a
separate part of the tree (past that size a label stops narrowing the
list; `recovery` was split out of `quic` this way). Then:

1. `gh label create <name> --repo Hakkadaikon/wired --color <hex> --description "<scope>"`
2. Add a row to the area table and any new boundary case to this skill,
   in the same commit.
3. Relabel the affected open issues with `--add-label` / `--remove-label`.
