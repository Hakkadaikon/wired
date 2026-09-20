// Per-peer voice quality: a pure rolling window fed by the receive-side
// events (frame received, frame lost to PLC, playback scheduling lag,
// jitter buffer depth) and a pure classifier read off its periodic
// snapshot. Kept framework-free so it's testable without a hook/store.

export type QualitySample = {
  received: number;
  lost: number;
  lagMs: number | undefined;
};

export type QualityLevel = "none" | "degraded" | "good";

const LOSS_RATIO_MAX = 0.02;
const LAG_MS_MAX = 150;

export function qualityLevel(sample: QualitySample): QualityLevel {
  if (sample.received === 0) return "none";
  const lossRatio = sample.lost / (sample.received + sample.lost);
  const degraded = lossRatio > LOSS_RATIO_MAX || (sample.lagMs ?? 0) > LAG_MS_MAX;
  return degraded ? "degraded" : "good";
}

type SenderWindow = { received: number; lost: number; lagMs: number | undefined };

const emptyWindow = (): SenderWindow => ({ received: 0, lost: 0, lagMs: undefined });

export type QualityWindow = {
  onFrame: (senderKey: string) => void;
  onLost: (senderKey: string) => void;
  onPlay: (senderKey: string, lagMs: number) => void;
  onDepth: (senderKey: string, depth: number) => void;
  snapshot: (senderKey: string) => QualitySample;
};

// createQualityWindow: one rolling window per sender, drained (and reset)
// by snapshot() -- the caller (useMoqtChat's 1s interval) reads a fresh
// sample every tick instead of an ever-growing lifetime average.
export function createQualityWindow(): QualityWindow {
  const windows = new Map<string, SenderWindow>();
  const windowFor = (senderKey: string): SenderWindow => {
    let w = windows.get(senderKey);
    if (!w) {
      w = emptyWindow();
      windows.set(senderKey, w);
    }
    return w;
  };

  return {
    onFrame: (senderKey) => {
      windowFor(senderKey).received += 1;
    },
    onLost: (senderKey) => {
      windowFor(senderKey).lost += 1;
    },
    onPlay: (senderKey, lagMs) => {
      windowFor(senderKey).lagMs = lagMs;
    },
    // depth alone isn't a quality signal in itself (yet) -- kept as its own
    // hook so the shape matches the brief's four voiceTap event kinds; the
    // classifier only reads received/lost/lagMs today.
    onDepth: (_senderKey, _depth) => {},
    snapshot: (senderKey) => {
      const w = windows.get(senderKey) ?? emptyWindow();
      windows.set(senderKey, emptyWindow());
      return { received: w.received, lost: w.lost, lagMs: w.lagMs };
    },
  };
}
