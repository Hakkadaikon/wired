// S15 image-send: 2 clients, one sends an image (small: fits in a single
// MAX_IMAGE_CHUNK_BYTES=480 chunk; large: tens of chunks), the other must
// receive it byte-identical. Proves the chunked image wire format
// (moqtImageWire.ts) round-trips through a real connection, not just unit
// tests of the encode/decode functions in isolation.
//
// DOM injection follows loadTest.mjs's sendOneMessage style (native setter +
// dispatchEvent) rather than Puppeteer's uploadFile/native file dialog, which
// is unreliable in headless CI: a File is synthesized inside the page via
// page.evaluate, attached to a DataTransfer, assigned to the hidden
// <input data-testid="image-file">, then a change event is dispatched.

import { CANDIDATE_PARTICIPANT_IDS } from "../lib/loadTest.mjs";

const JOIN_TIMEOUT_MS = 20000;
const IMAGE_TIMEOUT_MS = 15000;

async function joinClient(browser, pageUrl, certHash, participantId) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));

  // ns=0 disables the voice pipeline (see loadTest.mjs's joinClient for
  // why): this scenario measures the image chunk transport, not RNNoise CPU.
  const nsOffUrl = new URL(pageUrl);
  nsOffUrl.searchParams.set("ns", "0");
  await page.goto(nsOffUrl.href);
  await page.type('input[data-testid="certHash"]', certHash);
  await page.click(`[data-testid="participant-${participantId}"]`);
  await page.click('[data-testid="connect"]');
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected",
    { timeout: JOIN_TIMEOUT_MS },
  );

  return { tag: participantId, page, errors, ctx };
}

/** Deterministic non-zero byte pattern -- catches an all-zero reassembly bug
 * that an all-zero fixture would hide. */
function makePattern(length) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = (i * 37 + 11) & 0xff;
  return bytes;
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function sendImageFromPage(page, base64, mimeType) {
  await page.evaluate(
    async (b64, mime) => {
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const file = new File([bytes], "test.bin", { type: mime });
      const dt = new DataTransfer();
      dt.items.add(file);
      const input = document.querySelector('input[data-testid="image-file"]');
      input.files = dt.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    },
    base64,
    mimeType,
  );
}

async function waitForReceivedImage(page) {
  await page.waitForFunction(() => document.querySelector('[data-testid="message-image"]') !== null, {
    timeout: IMAGE_TIMEOUT_MS,
  });
  const receivedBase64 = await page.evaluate(async () => {
    const img = document.querySelector('[data-testid="message-image"]');
    const buf = await fetch(img.src).then((r) => r.arrayBuffer());
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  });
  return Buffer.from(receivedBase64, "base64");
}

function firstDiffOffset(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return i;
  }
  return a.length === b.length ? -1 : len;
}

async function runCase(sender, receiver, name, byteLength, failures, report) {
  const sent = makePattern(byteLength);
  await sendImageFromPage(sender.page, toBase64(sent), "application/octet-stream");
  let received;
  try {
    received = await waitForReceivedImage(receiver.page);
  } catch (err) {
    failures.push(`${name}: receiver never showed message-image: ${err}`);
    report.cases[name] = { sentBytes: sent.length, received: false };
    return;
  }
  const match = sent.length === received.length && firstDiffOffset(sent, received) === -1;
  report.cases[name] = {
    sentBytes: sent.length,
    receivedBytes: received.length,
    match,
  };
  if (!match) {
    const offset = firstDiffOffset(sent, received);
    failures.push(
      `${name}: byte mismatch (sent ${sent.length} bytes, received ${received.length} bytes, ` +
        `first differing offset ${offset})`,
    );
  }
}

export async function run({ browser, pageUrl, server, arg, log }) {
  const smallBytes = Number(arg("small-bytes", "300"));
  const largeBytes = Number(arg("large-bytes", "20000"));
  const [tagA, tagB] = CANDIDATE_PARTICIPANT_IDS;

  log(`connecting 2 clients (${tagA}, ${tagB})`);
  const clientA = await joinClient(browser, pageUrl, server.certHash, tagA);
  const clientB = await joinClient(browser, pageUrl, server.certHash, tagB);

  const failures = [];
  const report = { cases: {} };
  try {
    log(`case small: ${smallBytes} bytes, A -> B`);
    await runCase(clientA, clientB, "small", smallBytes, failures, report);

    log(`case large: ${largeBytes} bytes, B -> A`);
    await runCase(clientB, clientA, "large", largeBytes, failures, report);

    for (const client of [clientA, clientB]) {
      if (client.errors.length > 0) {
        failures.push(`client ${client.tag} page errors: ${client.errors.join("; ")}`);
      }
    }
  } finally {
    await clientA.ctx.close().catch(() => {});
    await clientB.ctx.close().catch(() => {});
  }

  return { report, failures };
}
