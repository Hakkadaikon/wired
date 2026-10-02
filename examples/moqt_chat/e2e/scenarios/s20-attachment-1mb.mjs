// S20 attachment-1mb: one 1 MB image goes through the hub byte-exact. It
// travels as 15 KiB chunk Objects (moqtAttachmentWire.ts) on one stream in
// a Group of its own, under the hub's 16384-byte held-Object cap.
//
//   just e2e-stability s20-attachment-1mb

import { joinStabilityClient, closeClient } from "../lib/stabilityClient.mjs";

function pattern(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 37 + 11) & 0xff;
  return b;
}

export async function run({ pageUrl, serverUrl, server, arg, log }) {
  const bytes = Number(arg("bytes", "1000000"));
  const opts = (tag) => ({ pageUrl, serverUrl, certHash: server.certHash, participantId: tag });
  const failures = [];
  const report = { bytes };
  const clients = [];
  try {
    const sender = await joinStabilityClient(opts("user1"));
    clients.push(sender);
    const receiver = await joinStabilityClient(opts("user2"));
    clients.push(receiver);
    await receiver.page.waitForSelector('[data-testid="quality-user1"]', { timeout: 10000 });

    const sent = pattern(bytes);
    log(`user1 sends ${bytes} bytes`);
    await sender.page.evaluate((b64) => {
      const bin = atob(b64);
      const data = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
      const dt = new DataTransfer();
      dt.items.add(new File([data], "big.png", { type: "image/png" }));
      const input = document.querySelector('input[data-testid="attachment-file"]');
      input.files = dt.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }, Buffer.from(sent).toString("base64"));
    await sender.page.waitForSelector('[data-testid="draft-remove"]', { timeout: 10000 });
    const start = Date.now();
    await sender.page.evaluate(() =>
      document
        .querySelector('input[data-testid="text"]')
        .dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })),
    );

    try {
      await receiver.page.waitForSelector('[data-testid="message-image"]', { timeout: 60000 });
      report.deliveredMs = Date.now() - start;
      const b64 = await receiver.page.evaluate(async () => {
        const buf = new Uint8Array(await (await fetch(document.querySelector('[data-testid="message-image"]').src)).arrayBuffer());
        let s = "";
        for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
        return btoa(s);
      });
      const got = Buffer.from(b64, "base64");
      report.receivedBytes = got.length;
      if (!Buffer.from(sent).equals(got)) failures.push(`byte mismatch: sent ${sent.length}, received ${got.length}`);
    } catch (err) {
      failures.push(`receiver never showed the image: ${err}`);
    }
    for (const c of clients) if (c.errors.length) failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
