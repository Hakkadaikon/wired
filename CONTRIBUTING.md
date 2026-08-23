# Contributing

**The 30-second version.** Four rules govern every change:
**(1)** no libc — code must compile freestanding;
**(2)** every function's cyclomatic complexity ≤ 3;
**(3)** one concern = one `src/<dir>/`;
**(4)** all symbols share one global namespace (the tests build as a single
translation unit), so grep before naming.

Before opening a PR, all of `just test`, `just ninja`, and
`lizard src --CCN 3 -w` must pass:

```sh
just test && just ninja && lizard src --CCN 3 -w
```

For the full picture — the design philosophy, the layered architecture, the
constraints behind each rule above, and the workflow for adding a domain —
see [docs/development.md](docs/development.md).

## Reporting issues

Open a GitHub issue with a minimal reproduction. For a protocol-level bug,
include the RFC section you believe is violated where possible.

## Security

Do not open a public issue for a suspected security vulnerability. See
[docs/security.md](docs/security.md) for what the SDK guarantees and what it
leaves to the caller, then contact the maintainers privately.
