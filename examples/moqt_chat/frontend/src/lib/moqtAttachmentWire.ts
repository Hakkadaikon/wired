// Multi-attachment chat Object wire framing on top of moqtWire.ts's generic
// MOQT codec. Same shape as moqtImageWire.ts, extended so one text message
// can carry several attachments (messageId + attachmentIdx identify which
// attachment a chunk belongs to) plus a separate text-part message.

import { concatBytes, encodeVarint, MoqtDecodeError } from "./moqtWire";
import { SUBGROUP_HEADER_TYPE } from "./moqtClient";

/** Max bytes of attachment data per chunk; same budget as moqtImageWire.ts's
 * MAX_IMAGE_CHUNK_BYTES (stays under the relay's 512-byte fragment limit
 * once framing overhead is added). */
export const MAX_ATTACHMENT_CHUNK_BYTES = 480;

/** First byte of every Object payload carrying an attachment chunk. */
export const ATTACHMENT_CHUNK_MARKER = 0xfd;

/** First byte of every Object payload carrying a text part. */
export const TEXT_PART_MARKER = 0xfe;

const CHUNK_HEADER_LEN = 4 + 1 + 4 + 2 + 2; // messageId u32 | attachmentIdx u8 | seq u32 | idx u16 | count u16

export interface AttachmentChunk {
  messageId: number;
  attachmentIdx: number;
  seq: number;
  idx: number;
  count: number;
  /** Present only when idx===0. */
  mimeType?: string;
  totalBytes?: number;
  data: Uint8Array;
}

/** Builds the SUBGROUP_HEADER an attachment stream opens with (once), before
 * any Objects. Identical shape to buildImageSubgroupHeader. */
export function buildAttachmentSubgroupHeader(trackAlias: bigint, groupId: bigint): Uint8Array {
  return concatBytes([
    encodeVarint(SUBGROUP_HEADER_TYPE),
    encodeVarint(trackAlias),
    encodeVarint(groupId),
  ]);
}

function putU32(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value, false);
}

function putU16(view: DataView, offset: number, value: number): void {
  view.setUint16(offset, value, false);
}

/** Encodes one attachment chunk as a MoQT Object body: marker u8 |
 * messageId u32 BE | attachmentIdx u8 | seq u32 BE | idx u16 BE |
 * count u16 BE, then (idx===0 only) mimeType len u8 + mimeType UTF-8 bytes +
 * totalBytes u32 BE, then the raw chunk data. */
export function encodeAttachmentChunkMessage(chunk: AttachmentChunk): Uint8Array {
  const hasMeta = chunk.idx === 0;
  const mimeBytes = hasMeta ? new TextEncoder().encode(chunk.mimeType ?? "") : undefined;
  const metaLen = hasMeta ? 1 + (mimeBytes?.length ?? 0) + 4 : 0;
  const out = new Uint8Array(1 + CHUNK_HEADER_LEN + metaLen + chunk.data.length);
  const view = new DataView(out.buffer);

  out[0] = ATTACHMENT_CHUNK_MARKER;
  putU32(view, 1, chunk.messageId);
  out[5] = chunk.attachmentIdx;
  putU32(view, 6, chunk.seq);
  putU16(view, 10, chunk.idx);
  putU16(view, 12, chunk.count);

  let pos = 1 + CHUNK_HEADER_LEN;
  if (hasMeta && mimeBytes) {
    out[pos] = mimeBytes.length;
    out.set(mimeBytes, pos + 1);
    pos += 1 + mimeBytes.length;
    putU32(view, pos, chunk.totalBytes ?? 0);
    pos += 4;
  }
  out.set(chunk.data, pos);
  return out;
}

/** Decodes one attachment chunk from a MoQT Object body; the inverse of
 * encodeAttachmentChunkMessage. */
export function decodeAttachmentChunkMessage(bytes: Uint8Array): AttachmentChunk {
  if (bytes.length < 1 + CHUNK_HEADER_LEN) {
    throw new MoqtDecodeError("attachment Object payload shorter than chunk header");
  }
  if (bytes[0] !== ATTACHMENT_CHUNK_MARKER) {
    throw new MoqtDecodeError("attachment Object payload missing marker byte");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messageId = view.getUint32(1, false);
  const attachmentIdx = bytes[5];
  const seq = view.getUint32(6, false);
  const idx = view.getUint16(10, false);
  const count = view.getUint16(12, false);

  let pos = 1 + CHUNK_HEADER_LEN;
  let mimeType: string | undefined;
  let totalBytes: number | undefined;
  if (idx === 0) {
    if (pos + 1 > bytes.length) {
      throw new MoqtDecodeError("attachment Object metadata truncated");
    }
    const mimeLen = bytes[pos];
    pos += 1;
    if (pos + mimeLen + 4 > bytes.length) {
      throw new MoqtDecodeError("attachment Object metadata truncated");
    }
    mimeType = new TextDecoder().decode(bytes.slice(pos, pos + mimeLen));
    pos += mimeLen;
    totalBytes = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getUint32(0, false);
    pos += 4;
  }

  return { messageId, attachmentIdx, seq, idx, count, mimeType, totalBytes, data: bytes.slice(pos) };
}

/** Lightweight marker check used by moqtClient.ts's receive-side dispatch. */
export function isAttachmentChunkPayload(bytes: Uint8Array): boolean {
  return bytes[0] === ATTACHMENT_CHUNK_MARKER;
}

/** Splits `data` into MAX_ATTACHMENT_CHUNK_BYTES-sized chunks for one
 * attachment. Pure function; a 0-byte attachment still yields one empty
 * chunk (count=1, idx=0). */
export function splitAttachmentIntoChunks(
  messageId: number,
  attachmentIdx: number,
  mimeType: string,
  data: Uint8Array,
): AttachmentChunk[] {
  const count = Math.max(1, Math.ceil(data.length / MAX_ATTACHMENT_CHUNK_BYTES));
  const chunks: AttachmentChunk[] = [];
  for (let idx = 0; idx < count; idx++) {
    const start = idx * MAX_ATTACHMENT_CHUNK_BYTES;
    const end = Math.min(start + MAX_ATTACHMENT_CHUNK_BYTES, data.length);
    chunks.push({
      messageId,
      attachmentIdx,
      seq: 0,
      idx,
      count,
      mimeType: idx === 0 ? mimeType : undefined,
      totalBytes: idx === 0 ? data.length : undefined,
      data: data.slice(start, end),
    });
  }
  return chunks;
}

/** Encodes a text-part message: marker u8 | messageId u32 BE |
 * attachmentCount u8 | textLen u16 BE | text UTF-8 bytes. */
export function encodeTextPartMessage(
  messageId: number,
  attachmentCount: number,
  text: string,
): Uint8Array {
  const textBytes = new TextEncoder().encode(text);
  const out = new Uint8Array(1 + 4 + 1 + 2 + textBytes.length);
  const view = new DataView(out.buffer);

  out[0] = TEXT_PART_MARKER;
  putU32(view, 1, messageId);
  out[5] = attachmentCount;
  putU16(view, 6, textBytes.length);
  out.set(textBytes, 8);
  return out;
}

/** Decodes a text-part message; the inverse of encodeTextPartMessage. */
export function decodeTextPartMessage(
  bytes: Uint8Array,
): { messageId: number; attachmentCount: number; text: string } {
  if (bytes.length < 8) {
    throw new MoqtDecodeError("text part payload shorter than header");
  }
  if (bytes[0] !== TEXT_PART_MARKER) {
    throw new MoqtDecodeError("text part payload missing marker byte");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messageId = view.getUint32(1, false);
  const attachmentCount = bytes[5];
  const textLen = view.getUint16(6, false);
  if (8 + textLen > bytes.length) {
    throw new MoqtDecodeError("text part payload truncated");
  }
  const text = new TextDecoder().decode(bytes.slice(8, 8 + textLen));
  return { messageId, attachmentCount, text };
}

/** Lightweight marker check used by moqtClient.ts's receive-side dispatch. */
export function isTextPartPayload(bytes: Uint8Array): boolean {
  return bytes[0] === TEXT_PART_MARKER;
}

// Attachment reassembly: collects chunks by `messageId:attachmentIdx` key and
// only emits once every idx in [0, count) has arrived for that key. A
// pending frame older than ATTACHMENT_TIMEOUT_MS is silently dropped (no
// log) the next time any chunk is pushed, and the key starts a fresh cycle.
const ATTACHMENT_TIMEOUT_MS = 30_000;

interface PendingAttachment {
  count: number;
  mimeType: string;
  chunks: (Uint8Array | undefined)[];
  received: number;
  startedAt: number;
}

export interface AttachmentReassembler {
  pending: Map<string, PendingAttachment>;
}

export function attachmentReassemblerInit(): AttachmentReassembler {
  return { pending: new Map() };
}

function keyOf(chunk: AttachmentChunk): string {
  return `${chunk.messageId}:${chunk.attachmentIdx}`;
}

function pruneExpired(pending: Map<string, PendingAttachment>, now: number): void {
  for (const [key, frame] of pending) {
    if (now - frame.startedAt >= ATTACHMENT_TIMEOUT_MS) {
      pending.delete(key);
    }
  }
}

/** Feeds one chunk into the reassembler. Returns the reassembled attachment
 * bytes once `count` distinct chunks for the same messageId+attachmentIdx
 * key have all arrived, else null. A pending frame stale for more than
 * ATTACHMENT_TIMEOUT_MS is dropped silently before being fed further. */
export function attachmentReassemblerPush(
  reassembler: AttachmentReassembler,
  chunk: AttachmentChunk,
): Uint8Array | null {
  const now = Date.now();
  pruneExpired(reassembler.pending, now);

  const key = keyOf(chunk);
  let frame = reassembler.pending.get(key);
  if (!frame) {
    frame = {
      count: chunk.count,
      mimeType: chunk.idx === 0 ? (chunk.mimeType ?? "") : "",
      chunks: new Array(chunk.count),
      received: 0,
      startedAt: now,
    };
    reassembler.pending.set(key, frame);
  }
  if (chunk.idx === 0 && chunk.mimeType !== undefined) {
    frame.mimeType = chunk.mimeType;
  }
  if (chunk.idx < frame.count && frame.chunks[chunk.idx] === undefined) {
    frame.chunks[chunk.idx] = chunk.data;
    frame.received++;
  }
  if (frame.received < frame.count) return null;

  reassembler.pending.delete(key);
  return concatBytes(frame.chunks as Uint8Array[]);
}
