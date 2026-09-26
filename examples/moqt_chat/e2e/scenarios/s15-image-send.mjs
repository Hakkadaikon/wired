// S15 image-send: 2 clients exercising the chat compose's attachment +
// text wire format (moqtAttachmentWire.ts / moqtClient.ts) through a real
// connection, not just unit tests of the encode/decode functions in
// isolation. Cases: single small/large image, multiple mixed attachments
// (images + a video) in one message, text-only, and attachment-only.
//
// DOM injection follows loadTest.mjs's sendOneMessage style (native setter +
// dispatchEvent) rather than Puppeteer's uploadFile/native file dialog, which
// is unreliable in headless CI: File objects are synthesized inside the page
// via page.evaluate, attached to a DataTransfer, assigned to the hidden
// <input data-testid="attachment-file">, and a change event is dispatched.
// Compose (page.tsx) holds picked files as an uncommitted draft until Send is
// pressed, so every send path here also dispatches the same Enter keydown
// loadTest.mjs uses to submit.

import { CANDIDATE_PARTICIPANT_IDS } from "../lib/loadTest.mjs";
import { startUdpProxy } from "../lib/udpProxy.mjs";
import { joinStabilityClient, closeClient } from "../lib/stabilityClient.mjs";

const JOIN_TIMEOUT_MS = 20000;
const IMAGE_TIMEOUT_MS = 30000;
const PROXY_BASE = 25433; // distinct from s13 (24433)
const SERVER_PORT = 4433;

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

// Submits the current draft (text + any picked files) the same way
// loadTest.mjs's sendOneMessage does: a keydown on the text input, since
// Compose (page.tsx) submits on Enter's onKeyDown rather than a form submit
// event.
async function submitDraft(page) {
  await page.evaluate(() => {
    const input = document.querySelector('input[data-testid="text"]');
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  });
}

async function setText(page, text) {
  await page.waitForSelector('input[data-testid="text"]', { timeout: JOIN_TIMEOUT_MS });
  await page.evaluate((value) => {
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, text);
}

// Picks one or more files into the hidden attachment-file input (multiple)
// via a DataTransfer, mirroring how a real file-picker selection lands.
// Each entry is { base64, mimeType, fileName }. Compose's onChange handler
// (page.tsx's pickFiles) reads each file via the async File.arrayBuffer()
// before committing draftAttachments, so this waits for that many
// draft-remove chips to actually mount -- dispatching Enter immediately
// after the change event races that async state update and finds an empty,
// unsendable draft (canSend still false).
async function pickFiles(page, files) {
  await page.waitForSelector('input[data-testid="attachment-file"]', { timeout: JOIN_TIMEOUT_MS });
  const previousChips = await page.evaluate(
    () => document.querySelectorAll('[data-testid="draft-remove"]').length,
  );
  await page.evaluate((entries) => {
    const dt = new DataTransfer();
    for (const { base64, mimeType, fileName } of entries) {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      dt.items.add(new File([bytes], fileName, { type: mimeType }));
    }
    const input = document.querySelector('input[data-testid="attachment-file"]');
    input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, files);
  await page.waitForFunction(
    (count, added) => document.querySelectorAll('[data-testid="draft-remove"]').length >= count + added,
    { timeout: JOIN_TIMEOUT_MS },
    previousChips,
    files.length,
  );
}

async function sendImageFromPage(page, base64, mimeType) {
  // The room view (and its Compose/file-input) mounts asynchronously after
  // joinClient's "connected" status check resolves -- back-to-back cases on
  // the same page (this scenario's second case reuses a client that was
  // only a receiver until now) can hit this evaluate before that mount
  // commits, so wait for the element rather than assuming it's already there.
  await pickFiles(page, [{ base64, mimeType, fileName: "test.bin" }]);
  await submitDraft(page);
}

function countAttachments(page) {
  return page.evaluate(() => ({
    images: document.querySelectorAll('[data-testid="message-image"]').length,
    videos: document.querySelectorAll('[data-testid="message-video"]').length,
  }));
}

// Waits for message-image/message-video counts to each grow past their
// previous values rather than matching "any": the sender also gets an
// optimistic local echo in their own timeline (useMoqtChat.ts's sendMessage),
// so a receiver who previously sent their own attachment already has one or
// more matching elements in their DOM before this call.
async function waitForCounts(page, prev, wantImages, wantVideos) {
  await page.waitForFunction(
    (prevImages, prevVideos, wantImg, wantVid) => {
      const images = document.querySelectorAll('[data-testid="message-image"]').length;
      const videos = document.querySelectorAll('[data-testid="message-video"]').length;
      return images - prevImages >= wantImg && videos - prevVideos >= wantVid;
    },
    { timeout: IMAGE_TIMEOUT_MS },
    prev.images,
    prev.videos,
    wantImages,
    wantVideos,
  );
}

async function readBytesFromElements(page, selector, fromIndex) {
  return page.evaluate(
    async (sel, from) => {
      const els = document.querySelectorAll(sel);
      const out = [];
      for (let i = from; i < els.length; i++) {
        const buf = await fetch(els[i].src).then((r) => r.arrayBuffer());
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let j = 0; j < bytes.length; j++) binary += String.fromCharCode(bytes[j]);
        out.push(btoa(binary));
      }
      return out;
    },
    selector,
    fromIndex,
  );
}

function firstDiffOffset(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return i;
  }
  return a.length === b.length ? -1 : len;
}

function bytesEqual(a, b) {
  return a.length === b.length && firstDiffOffset(a, b) === -1;
}

async function runCase(sender, receiver, name, byteLength, failures, report) {
  const sent = makePattern(byteLength);
  const previousCount = await receiver.page.evaluate(
    () => document.querySelectorAll('[data-testid="message-image"]').length,
  );
  // attachmentValidation.ts only allows image/* or video/* (Task 5's
  // multi-attachment rewrite added this check) -- an arbitrary MIME type
  // like application/octet-stream is now silently rejected before it ever
  // reaches draftAttachments.
  await sendImageFromPage(sender.page, toBase64(sent), "image/png");
  let received;
  try {
    await waitForCounts(receiver.page, { images: previousCount, videos: 0 }, 1, 0);
    const [b64] = await readBytesFromElements(receiver.page, '[data-testid="message-image"]', previousCount);
    received = Buffer.from(b64, "base64");
  } catch (err) {
    failures.push(`${name}: receiver never showed message-image: ${err}`);
    report.cases[name] = { sentBytes: sent.length, received: false };
    return;
  }
  const match = bytesEqual(sent, received);
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

// Multiple attachments (images + a video) in a single message: proves
// multi-attachment compose end to end, not just a single-file send.
async function runMultiAttachmentCase(sender, receiver, failures, report) {
  const name = "multi-attachment";
  const images = [makePattern(300), makePattern(450)];
  const videos = [makePattern(600)];
  const files = [
    ...images.map((bytes, i) => ({ base64: toBase64(bytes), mimeType: "image/png", fileName: `img${i}.png` })),
    ...videos.map((bytes, i) => ({ base64: toBase64(bytes), mimeType: "video/mp4", fileName: `vid${i}.mp4` })),
  ];

  const previous = await countAttachments(receiver.page);
  await pickFiles(sender.page, files);
  await submitDraft(sender.page);

  try {
    await waitForCounts(receiver.page, previous, images.length, videos.length);
  } catch (err) {
    failures.push(`${name}: receiver never showed all ${images.length} images + ${videos.length} videos: ${err}`);
    report.cases[name] = { sent: files.length, received: false };
    return;
  }

  const receivedImages = await readBytesFromElements(receiver.page, '[data-testid="message-image"]', previous.images);
  const receivedVideos = await readBytesFromElements(receiver.page, '[data-testid="message-video"]', previous.videos);

  let allMatch = true;
  images.forEach((sent, i) => {
    const received = Buffer.from(receivedImages[i] ?? "", "base64");
    if (!bytesEqual(sent, received)) {
      allMatch = false;
      failures.push(`${name}: image[${i}] byte mismatch (sent ${sent.length}, received ${received.length})`);
    }
  });
  videos.forEach((sent, i) => {
    const received = Buffer.from(receivedVideos[i] ?? "", "base64");
    if (!bytesEqual(sent, received)) {
      allMatch = false;
      failures.push(`${name}: video[${i}] byte mismatch (sent ${sent.length}, received ${received.length})`);
    }
  });

  report.cases[name] = { images: images.length, videos: videos.length, match: allMatch };
}

// Text-only: no attachments, receiver's message list gets a new bubble
// whose message__text contains the sent text.
async function runTextOnlyCase(sender, receiver, failures, report) {
  const name = "text-only";
  const text = `text-only:${Date.now()}`;
  const previousCount = await receiver.page.evaluate(() => document.querySelectorAll('[data-testid="message"]').length);
  const previousAttachments = await countAttachments(receiver.page);

  await setText(sender.page, text);
  await submitDraft(sender.page);

  try {
    await receiver.page.waitForFunction(
      (count, expected) => {
        const messages = document.querySelectorAll('[data-testid="message"]');
        if (messages.length <= count) return false;
        return Array.from(messages).some((m) => m.textContent.includes(expected));
      },
      { timeout: IMAGE_TIMEOUT_MS },
      previousCount,
      text,
    );
    // A text-only send must not grow the receiver's attachment count --
    // attachmentCount was sent as 0, so no message-image/message-video
    // should appear for this message.
    const afterAttachments = await countAttachments(receiver.page);
    const grewAttachments =
      afterAttachments.images !== previousAttachments.images ||
      afterAttachments.videos !== previousAttachments.videos;
    if (grewAttachments) {
      failures.push(
        `${name}: attachment count grew on a text-only send (before ${JSON.stringify(previousAttachments)}, after ${JSON.stringify(afterAttachments)})`,
      );
    }
    report.cases[name] = { received: true, attachmentsGrew: grewAttachments };
  } catch (err) {
    failures.push(`${name}: receiver never showed the text message: ${err}`);
    report.cases[name] = { received: false };
  }
}

// Attachment-only: empty text, one image attachment; receiver must show the
// image with no message__text sibling holding stray content.
async function runAttachmentOnlyCase(sender, receiver, failures, report) {
  const name = "attachment-only";
  const sent = makePattern(320);
  const previousCount = await receiver.page.evaluate(
    () => document.querySelectorAll('[data-testid="message-image"]').length,
  );

  await pickFiles(sender.page, [{ base64: toBase64(sent), mimeType: "image/png", fileName: "only.png" }]);
  await submitDraft(sender.page);

  try {
    await waitForCounts(receiver.page, { images: previousCount, videos: 0 }, 1, 0);
    const [b64] = await readBytesFromElements(receiver.page, '[data-testid="message-image"]', previousCount);
    const received = Buffer.from(b64, "base64");
    const match = bytesEqual(sent, received);
    // Attachment-only: text was sent empty, so the receiver's newest
    // message bubble must render no message__text span at all
    // (page.tsx's `{m.text && <span className="message__text">}` skips it
    // for an empty string).
    const hasTextSpan = await receiver.page.evaluate(() => {
      const messages = document.querySelectorAll('[data-testid="message"]');
      const newest = messages[messages.length - 1];
      return newest ? newest.querySelector(".message__text") !== null : null;
    });
    if (hasTextSpan) {
      failures.push(`${name}: receiver's newest message rendered a message__text span for an empty-text send`);
    }
    report.cases[name] = { sentBytes: sent.length, receivedBytes: received.length, match, hasTextSpan };
    if (!match) failures.push(`${name}: byte mismatch (sent ${sent.length}, received ${received.length})`);
  } catch (err) {
    failures.push(`${name}: receiver never showed message-image: ${err}`);
    report.cases[name] = { received: false };
  }
}

export async function run({ pageUrl, server, arg, log }) {
  const smallBytes = Number(arg("small-bytes", "300"));
  const largeBytes = Number(arg("large-bytes", "20000"));
  // RTT/loss injection through the same per-flow UDP proxy s13 uses; the
  // defaults (0/0) forward untouched, so the plain run behaves as before.
  const jitterMs = Number(arg("jitter-ms", "0"));
  const lossRate = Number(arg("loss-rate", "0"));
  const [tagA, tagB] = CANDIDATE_PARTICIPANT_IDS;

  const proxy = await startUdpProxy({
    listenBase: PROXY_BASE,
    upstreamPort: SERVER_PORT,
    flowCount: 2,
    profile: { lossRate, seed: 1, jitterBaseMs: jitterMs },
  });

  const failures = [];
  const report = { cases: {}, jitterMs, lossRate };
  const clients = [];
  try {
    log(`connecting 2 clients (${tagA}, ${tagB}) via proxy (jitter ${jitterMs}ms, loss ${lossRate})`);
    for (const [i, tag] of [tagA, tagB].entries()) {
      clients.push(
        await joinStabilityClient({
          pageUrl,
          serverUrl: `https://127.0.0.1:${proxy.port(i)}/`,
          certHash: server.certHash,
          participantId: tag,
        }),
      );
    }
    const [clientA, clientB] = clients;

    log(`case small: ${smallBytes} bytes, A -> B`);
    await runCase(clientA, clientB, "small", smallBytes, failures, report);

    log(`case large: ${largeBytes} bytes, B -> A`);
    await runCase(clientB, clientA, "large", largeBytes, failures, report);

    log("case multi-attachment: 2 images + 1 video, A -> B");
    await runMultiAttachmentCase(clientA, clientB, failures, report);

    log("case text-only: B -> A");
    await runTextOnlyCase(clientB, clientA, failures, report);

    log("case attachment-only: A -> B");
    await runAttachmentOnlyCase(clientA, clientB, failures, report);

    for (const client of clients) {
      if (client.errors.length > 0) {
        failures.push(`client ${client.tag} page errors: ${client.errors.join("; ")}`);
      }
    }
    report.proxyStats = proxy.stats();
  } finally {
    for (const client of clients) await closeClient(client);
    proxy.close();
  }

  return { report, failures };
}
