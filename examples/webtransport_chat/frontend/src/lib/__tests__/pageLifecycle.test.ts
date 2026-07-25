import { describe, expect, it, vi } from "vitest";
import { registerPageLifecycleCleanup } from "../pageLifecycle";

describe("pageLifecycle", () => {
  it("closes the WebTransport connection and releases the mic MediaStream on beforeunload/unmount", () => {
    const closeTransport = vi.fn();
    const track = { stop: vi.fn() };
    const getTracks = () => [track];
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    const target = { addEventListener, removeEventListener } as never;

    const unregister = registerPageLifecycleCleanup(
      {
        closeTransport,
        getMicTracks: getTracks,
      },
      target,
    );

    expect(addEventListener).toHaveBeenCalledWith(
      "beforeunload",
      expect.any(Function),
    );
    const handler = addEventListener.mock.calls[0][1] as () => void;
    handler();

    expect(closeTransport).toHaveBeenCalledTimes(1);
    expect(track.stop).toHaveBeenCalledTimes(1);

    // component unmount path: calling the returned cleanup runs it again
    // (e.g. explicit unmount) and removes the listener so it does not fire twice.
    unregister();
    expect(removeEventListener).toHaveBeenCalledWith(
      "beforeunload",
      handler,
    );
  });
});
