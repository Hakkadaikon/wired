// Per-peer voice quality: a pure rolling window fed by the receive-side
// events (frame received, frame lost to PLC, playback scheduling lag,
// jitter buffer depth) and a pure classifier read off its periodic
// snapshot. Kept framework-free so it's testable without a hook/store.

export type QualitySample = {
  received: number;
  lost: number;
  lagMs: number | undefined;
  speaking: boolean;
};

export type QualityLevel = "none" | "degraded" | "good";

const LOSS_RATIO_MAX = 0.02;
const LAG_MS_MAX = 150;
const SPEAKING_LEVEL_MIN = 10;

export function qualityLevel(sample: Omit<QualitySample, "speaking">): QualityLevel {
  if (sample.received === 0) return "none";
  const lossRatio = sample.lost / (sample.received + sample.lost);
  const degraded = lossRatio > LOSS_RATIO_MAX || (sample.lagMs ?? 0) > LAG_MS_MAX;
  return degraded ? "degraded" : "good";
}

// rmsLevel: RMS of the samples scaled to 0..100 (a full-scale +-1 signal
// tops out at 100), clamped for any signal hotter than that.
export function rmsLevel(samples: Float32Array): number {
  if (samples.length === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < samples.length; i++) sumSq += samples[i] * samples[i];
  const rms = Math.sqrt(sumSq / samples.length);
  return Math.min(100, rms * 100);
}

export function isSpeaking(level: number): boolean {
  return level >= SPEAKING_LEVEL_MIN;
}

type SenderWindow = {
  received: number;
  lost: number;
  lagMs: number | undefined;
  speaking: boolean;
};

const emptyWindow = (): SenderWindow => ({
  received: 0,
  lost: 0,
  lagMs: undefined,
  speaking: false,
});

export type QualityWindow = {
  onFrame: (senderKey: string) => void;
  onLost: (senderKey: string) => void;
  onPlay: (senderKey: string, lagMs: number) => void;
  onDepth: (senderKey: string, depth: number) => void;
  // A level sample (0..100, e.g. rmsLevel's own output) observed in this
  // window; speaking (read via snapshotSpeaking, or carried through by
  // snapshot -- see both below) is true if ANY call since the last
  // snapshotSpeaking() met isSpeaking's threshold.
  onLevel: (senderKey: string, level: number) => void;
  // received/lost/lagMs are reset here; speaking is carried through
  // UNCHANGED (snapshotSpeaking owns its reset -- see below) so the 1s
  // quality poll never discards evidence the 100ms speaking poll hasn't
  // consumed yet.
  snapshot: (senderKey: string) => QualitySample;
  // Reads and resets ONLY the speaking flag, independent of snapshot()'s
  // received/lost/lagMs reset -- so a faster speaking-poll cadence (Q-E's
  // 100ms timer) doesn't zero out the slower quality snapshot's counters.
  snapshotSpeaking: (senderKey: string) => boolean;
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
    onDepth: () => {},
    onLevel: (senderKey, level) => {
      if (isSpeaking(level)) windowFor(senderKey).speaking = true;
    },
    snapshot: (senderKey) => {
      const w = windows.get(senderKey) ?? emptyWindow();
      // received/lost/lagMs reset here (this is the 1s quality poll's own
      // window); speaking is owned by snapshotSpeaking's independent
      // 100ms cadence and must survive this reset untouched, or evidence
      // accumulated between speaking polls gets discarded here instead.
      windows.set(senderKey, { ...emptyWindow(), speaking: w.speaking });
      return { received: w.received, lost: w.lost, lagMs: w.lagMs, speaking: w.speaking };
    },
    snapshotSpeaking: (senderKey) => {
      const w = windowFor(senderKey);
      const speaking = w.speaking;
      w.speaking = false;
      return speaking;
    },
  };
}
