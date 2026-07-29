// Gates playback behind the browser's autoplay policy: the AudioContext is
// only ever resumed from a call made inside a trusted user-gesture handler,
// and voice data arriving before that resume is queued rather than dropped.

export interface AudioContextLike {
  state: "suspended" | "running" | "closed";
  resume: () => Promise<void>;
}

export type AudioContextGateOptions = {
  onResumeFailed?: (err: unknown) => void;
  // Playback sink. Frames enqueued while suspended are handed to it in
  // arrival order once resume succeeds; while running they are handed over
  // immediately. Without it the gate only queues (as in tests). senderKey
  // is threaded through so the sink can schedule each speaker on their own
  // timeline (see playbackSink.ts).
  play?: (senderKey: string, frame: unknown) => void;
};

export type AudioContextGate = {
  readonly state: string;
  resumeFromUserGesture: () => Promise<void>;
  enqueue: (senderKey: string, frame: unknown) => void;
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
  const pending: { senderKey: string; frame: unknown }[] = [];

  const flush = () => {
    if (!options.play) return;
    while (pending.length > 0) {
      const { senderKey, frame } = pending.shift()!;
      options.play(senderKey, frame);
    }
  };

  return {
    get state() {
      return ctx.state;
    },
    enqueue: (senderKey, frame) => {
      pending.push({ senderKey, frame });
      if (ctx.state === "running") flush();
    },
    pendingCount: () => pending.length,
    resumeFromUserGesture: async () => {
      try {
        const result = await Promise.race([ctx.resume(), timeout(RESUME_TIMEOUT_MS)]);
        if (result === "timeout" || ctx.state !== "running") {
          throw new Error("AudioContext.resume() did not reach running state");
        }
        flush();
      } catch (err) {
        options.onResumeFailed?.(err);
      }
    },
  };
}
