import { describe, expect, it } from "vitest";
import { fitCanvasToFrame } from "../screenTileSize";

describe("fitCanvasToFrame", () => {
  it("resizes the backing store to the frame's size when it differs", () => {
    const canvas = { width: 320, height: 180 };
    expect(fitCanvasToFrame(canvas, 1280, 720)).toBe(true);
    expect(canvas).toEqual({ width: 1280, height: 720 });
  });

  it("leaves an already-matching canvas untouched (a width write clears it)", () => {
    const canvas = { width: 1280, height: 720 };
    expect(fitCanvasToFrame(canvas, 1280, 720)).toBe(false);
  });

  it("ignores a missing or zero dimension", () => {
    const canvas = { width: 320, height: 180 };
    expect(fitCanvasToFrame(canvas, undefined, 720)).toBe(false);
    expect(fitCanvasToFrame(canvas, 1280, 0)).toBe(false);
    expect(canvas).toEqual({ width: 320, height: 180 });
  });
});
