// Optional per-frame trace tap for the e2e load harness: the harness
// installs globalThis.__wiredVoiceTap before navigation (voiceLoadTest.mjs)
// and rewrites each event's t from the page-local performance.now() epoch to
// the shared Date.now() epoch. Unset in normal use -- the optional call is
// the whole overhead. lag (play only) is milliseconds.

export type VoiceTapEvent = {
  dir: "send" | "recv" | "drain" | "play";
  seq: number;
  t: number;
  src?: string;
  lag?: number;
  bytes?: number; // send only: encoded Opus payload size
  depth?: number; // drain only: jitter buffer depth remaining after the pull
  plc?: boolean; // drain only: this tick's pull() reported the seq lost
  skipped?: boolean; // play only: frame dropped for exceeding MAX_LAG_S
};

export function voiceTap(e: VoiceTapEvent): void {
  (globalThis as { __wiredVoiceTap?: (e: VoiceTapEvent) => void }).__wiredVoiceTap?.(e);
}
