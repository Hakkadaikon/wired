// Injected before a page's own scripts run (page.evaluateOnNewDocument):
// headless Chrome has no screen to share, so navigator.mediaDevices.
// getDisplayMedia is replaced with a fake returning an offscreen
// <canvas>.captureStream() drawing a moving clock. The canvas size is the
// "screen" being shared: getDisplayMedia's constraints are only ideals in
// a real browser too, so the app must follow the frames' actual size
// (screenSharePipeline.ts) -- a portrait canvas here is how the check
// pins that. Also installs window.__wiredScreenTap so screenTap.ts
// records every decoded frame.
export function fakeDisplayMediaScript({ width = 1280, height = 720 } = {}) {
  return `
  (() => {
    const canvas = document.createElement("canvas");
    canvas.width = ${width};
    canvas.height = ${height};
    const ctx = canvas.getContext("2d");
    setInterval(() => {
      // 4..15 (never below 0x44) so VP8's lossy quantization on a keyframe
      // cannot push a channel value at or below the pixel-content check's
      // >8 threshold -- 0x11 was once observed decoding to <=8 on a fresh
      // keyframe right after a resize/reconfigure, reading as "blank" in
      // the check though the share itself was fine. This loop's period
      // (500ms * 12 = 6s) still cycles through visibly different shades
      // for the moving-pattern purpose this fake stream exists for.
      ctx.fillStyle = "#" + (4 + (Math.floor(Date.now() / 500) % 12)).toString(16).repeat(6);
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#fff";
      ctx.font = "48px sans-serif";
      ctx.fillText(new Date().toISOString(), 40, 100);
    }, 100);
    navigator.mediaDevices.getDisplayMedia = () => Promise.resolve(canvas.captureStream(10));
    window.__wiredScreenTap = [];
  })();
`;
}

export const FAKE_DISPLAY_MEDIA_SCRIPT = fakeDisplayMediaScript();
