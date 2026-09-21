// Injected before a page's own scripts run (page.evaluateOnNewDocument):
// headless Chrome has no screen to share, so navigator.mediaDevices.
// getDisplayMedia is replaced with a fake returning an offscreen
// <canvas>.captureStream() drawing a moving clock at the app's requested
// 1280x720 (screenSharePipeline.ts's WIDTH/HEIGHT -- the encoder scales to
// whatever it actually gets). Also installs window.__wiredScreenTap so
// screenTap.ts records every decoded frame.
export const FAKE_DISPLAY_MEDIA_SCRIPT = `
  (() => {
    const canvas = document.createElement("canvas");
    canvas.width = 1280;
    canvas.height = 720;
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
