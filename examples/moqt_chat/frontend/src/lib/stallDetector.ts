// Per-sender "no frame lately" detector for screen-share tiles. Time is
// injected (performance.now() in the hook) so it's testable without timers.

// 3 s is 30 missed frames at the pipeline's 10 fps and more than one
// keyframe interval (2 s): a sender that is merely between keyframes never
// trips it, a sender whose stream wedged does.
export const SCREEN_STALL_MS = 3000;

export type StallDetector = {
  frame: (now: number) => void;
  isStalled: (now: number) => boolean;
};

export function createStallDetector(thresholdMs: number): StallDetector {
  let lastFrameAt: number | undefined;
  return {
    frame: (now) => {
      lastFrameAt = now;
    },
    isStalled: (now) => lastFrameAt !== undefined && now - lastFrameAt >= thresholdMs,
  };
}
