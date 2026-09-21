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
      // 1..15 (never 0) so the fill is never near-black -- a near-black
      // frame occasionally landing in a canvas pixel-content check is a
      // flake, not a signal, and this loop's period (500ms * 15 = 7.5s)
      // still cycles through visibly different shades for the moving-
      // pattern purpose this fake stream exists for.
      ctx.fillStyle = "#" + (1 + (Math.floor(Date.now() / 500) % 15)).toString(16).repeat(6);
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
