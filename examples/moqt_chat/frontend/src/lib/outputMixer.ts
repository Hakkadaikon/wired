// Pure gain math for the per-peer volume x master gain mix, and the
// predicate that decides whether an output-device picker can be shown at
// all (AudioContext.setSinkId is not implemented in every browser).

function clamp01(v: number): number {
  return Math.min(1, Math.max(0, v));
}

export function effectiveGain(peer: number, master: number): number {
  return clamp01(clamp01(peer) * clamp01(master));
}

export function canPickOutput(ctx: object): boolean {
  return typeof (ctx as { setSinkId?: unknown }).setSinkId === "function";
}
