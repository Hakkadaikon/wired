// Remote screen-share tiles draw each decoded VideoFrame at its own size:
// the canvas backing store follows the frame, and CSS (--tile-w) sets the
// displayed width, so the aspect ratio is the sender's, never a stretch
// into a fixed 320x180.

export const SCREEN_TILE_MIN_PX = 160;
export const SCREEN_TILE_MAX_PX = 960;
export const SCREEN_TILE_STEP_PX = 20;
export const SCREEN_TILE_DEFAULT_PX = 320;

/** Sets the canvas backing store to frameW x frameH; returns whether it
 * changed. Writing width/height clears a canvas, so an equal size is a
 * no-op -- and a missing or zero dimension (a frame with no size yet)
 * never resizes. Call right before drawImage, in the same tick. */
export function fitCanvasToFrame(
  canvas: { width: number; height: number },
  frameW: number | undefined,
  frameH: number | undefined,
): boolean {
  if (!frameW || !frameH) return false;
  if (canvas.width === frameW && canvas.height === frameH) return false;
  canvas.width = frameW;
  canvas.height = frameH;
  return true;
}
