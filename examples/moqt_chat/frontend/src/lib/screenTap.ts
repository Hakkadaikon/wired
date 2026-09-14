// Optional per-frame trace tap for the e2e screen-share check
// (run-screenshare-check.mjs): pushes one entry per received-and-decoded
// screen-share frame onto window.__wiredScreenTap so the e2e script can
// assert frames actually arrived, without touching decode correctness.
// Unset in normal use -- the optional push is the whole overhead.

export type ScreenTapEvent = {
  senderId: string;
  width: number;
  height: number;
  t: number;
};

export function screenTap(e: ScreenTapEvent): void {
  (globalThis as { __wiredScreenTap?: ScreenTapEvent[] }).__wiredScreenTap?.push(e);
}
