# Security policy

## Reporting a vulnerability

Do not open a public issue or pull request for a suspected vulnerability.
Report it through GitHub's private vulnerability reporting:

1. Open <https://github.com/Hakkadaikon/wired/security/advisories/new>.
2. Describe the affected commit, the impact, and a way to reproduce it
   (a packet trace, a fuzz input, or a test).

The report is visible only to the maintainers until an advisory is
published.

## Supported revisions

There are no release branches. Fixes land on `main` only; pin a commit and
move it forward to pick them up.

## What counts

Anything that lets a peer attack a deployment: memory corruption reachable
from the wire, key or nonce reuse, an authentication or address-validation
bypass, unbounded resource use by an unauthenticated peer. What the SDK
guarantees, and what it leaves to the application, is described in
[docs/security/](docs/security/README.md); documented limits are listed in
[docs/security/limitations/](docs/security/limitations/README.md).
