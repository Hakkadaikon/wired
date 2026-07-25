# WebTransport chat frontend

Next.js (App Router) + TypeScript scaffold for the WebTransport voice chat
example. UI components are [LiftKit](https://github.com/Chainlift/liftkit),
vendored into `src/` by its CLI (`pnpm run add <component>`); state management
is Zustand; tests run on vitest (jsdom).

## Commands

```sh
pnpm dev     # dev server
pnpm build   # production build
pnpm test    # vitest (jsdom)
pnpm lint    # eslint
```

## Layout

- `src/app/` — pages and layouts (App Router).
- `src/lib/` — pure logic, the TDD target. LiftKit's own utilities/CSS also
  live here (`css/`, `colorUtils.ts`, ...); keep new app logic in separate
  files.
- `src/components/` — UI components (currently the vendored LiftKit set:
  button, card, text-input, badge and their dependencies).
- `src/stores/` — Zustand stores (created when the first store lands).

## Notes

- LiftKit's `add` CLI shells out to `npm install`, which fails in this pnpm
  workspace; the component files still land. Install any runtime deps it
  reports with `pnpm add` instead.
- `pnpm-workspace.yaml` pins `postcss`/`sharp` overrides to patched versions
  flagged by `pnpm audit`.
