// Closes the transport and releases the mic on page unload/unmount so the
// mic device is never left held after the user navigates away.

export type PageLifecycleDeps = {
  closeTransport: () => void;
  getMicTracks: () => { stop: () => void }[];
};

export interface UnloadTarget {
  addEventListener: (type: "beforeunload", handler: () => void) => void;
  removeEventListener: (type: "beforeunload", handler: () => void) => void;
}

export function registerPageLifecycleCleanup(
  deps: PageLifecycleDeps,
  target: UnloadTarget = window,
): () => void {
  const handler = () => {
    deps.closeTransport();
    for (const track of deps.getMicTracks()) track.stop();
  };
  target.addEventListener("beforeunload", handler);
  return () => target.removeEventListener("beforeunload", handler);
}
