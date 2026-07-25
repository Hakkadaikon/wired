// Gates playback behind the browser's autoplay policy: the AudioContext is
// only ever resumed from a call made inside a trusted user-gesture handler,
// and voice data arriving before that resume is queued rather than dropped.

export interface AudioContextLike {
  state: "suspended" | "running" | "closed";
  resume: () => Promise<void>;
}

export type AudioContextGateOptions = {
  onResumeFailed?: (err: unknown) => void;
};

export type AudioContextGate = {
  readonly state: string;
  resumeFromUserGesture: () => Promise<void>;
  enqueue: (frame: unknown) => void;
  pendingCount: () => number;
};

const RESUME_TIMEOUT_MS = 3000;

function timeout(ms: number): Promise<"timeout"> {
  return new Promise((resolve) => setTimeout(() => resolve("timeout"), ms));
}

export function createAudioContextGate(
  makeContext: () => AudioContextLike,
  options: AudioContextGateOptions = {},
): AudioContextGate {
  const ctx = makeContext();
  const pending: unknown[] = [];

  return {
    get state() {
      return ctx.state;
    },
    enqueue: (frame) => {
      pending.push(frame);
    },
    pendingCount: () => pending.length,
    resumeFromUserGesture: async () => {
      try {
        const result = await Promise.race([ctx.resume(), timeout(RESUME_TIMEOUT_MS)]);
        if (result === "timeout" || ctx.state !== "running") {
          throw new Error("AudioContext.resume() did not reach running state");
        }
      } catch (err) {
        options.onResumeFailed?.(err);
      }
    },
  };
}
