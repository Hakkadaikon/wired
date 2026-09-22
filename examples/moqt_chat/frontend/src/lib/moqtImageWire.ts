// Image chat-attachment Object wire framing on top of moqtWire.ts's generic
// MOQT codec. Same "one message, one uni stream" shape as moqtScreenWire.ts,
// but stripped of every video-specific field: an image chunk carries only
// seq/idx/count plus (on idx===0) mimeType + totalBytes.

import { concatBytes, encodeVarint, MoqtDecodeError } from "./moqtWire";
import { SUBGROUP_HEADER_TYPE } from "./moqtClient";

/** Max bytes of image data per chunk, chosen to stay under the relay's
 * 512-byte fragment limit once framing overhead is added. */
export const MAX_IMAGE_CHUNK_BYTES = 480;

/** First byte of every Object payload carrying an image chunk. */
export const IMAGE_CHUNK_MARKER = 0xff;

const CHUNK_HEADER_LEN = 4 + 2 + 2; // seq u32 | idx u16 | count u16

export interface ImageChunk {
  seq: number;
  idx: number;
  count: number;
  /** Present only when idx===0. */
  mimeType?: string;
  totalBytes?: number;
  data: Uint8Array;
}

/** Builds the SUBGROUP_HEADER an image stream opens with (once), before any
 * Objects. Identical shape to buildScreenSubgroupHeader. */
export function buildImageSubgroupHeader(trackAlias: bigint, groupId: bigint): Uint8Array {
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

/** Encodes one image chunk as a MoQT Object body: marker u8 | seq u32 BE |
 * idx u16 BE | count u16 BE, then (idx===0 only) mimeType len u8 + mimeType
 * UTF-8 bytes + totalBytes u32 BE, then the raw chunk data. */
export function encodeImageChunkMessage(chunk: ImageChunk): Uint8Array {
  const hasMeta = chunk.idx === 0;
  const mimeBytes = hasMeta ? new TextEncoder().encode(chunk.mimeType ?? "") : undefined;
  const metaLen = hasMeta ? 1 + (mimeBytes?.length ?? 0) + 4 : 0;
  const out = new Uint8Array(1 + CHUNK_HEADER_LEN + metaLen + chunk.data.length);
  const view = new DataView(out.buffer);

  out[0] = IMAGE_CHUNK_MARKER;
  putU32(view, 1, chunk.seq);
  putU16(view, 5, chunk.idx);
  putU16(view, 7, chunk.count);

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

/** Decodes one image chunk from a MoQT Object body; the inverse of
 * encodeImageChunkMessage. */
export function decodeImageChunkMessage(bytes: Uint8Array): { chunk: ImageChunk } {
  if (bytes.length < 1 + CHUNK_HEADER_LEN) {
    throw new MoqtDecodeError("image Object payload shorter than chunk header");
  }
  if (bytes[0] !== IMAGE_CHUNK_MARKER) {
    throw new MoqtDecodeError("image Object payload missing marker byte");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const seq = view.getUint32(1, false);
  const idx = view.getUint16(5, false);
  const count = view.getUint16(7, false);

  let pos = 1 + CHUNK_HEADER_LEN;
  let mimeType: string | undefined;
  let totalBytes: number | undefined;
  if (idx === 0) {
    if (pos + 1 > bytes.length) {
      throw new MoqtDecodeError("image Object metadata truncated");
    }
    const mimeLen = bytes[pos];
    pos += 1;
    if (pos + mimeLen + 4 > bytes.length) {
      throw new MoqtDecodeError("image Object metadata truncated");
    }
    mimeType = new TextDecoder().decode(bytes.slice(pos, pos + mimeLen));
    pos += mimeLen;
    totalBytes = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getUint32(0, false);
    pos += 4;
  }

  return {
    chunk: { seq, idx, count, mimeType, totalBytes, data: bytes.slice(pos) },
  };
}

/** Lightweight marker check used by moqtClient.ts's receive-side dispatch. */
export function isImageChunkPayload(bytes: Uint8Array): boolean {
  return bytes[0] === IMAGE_CHUNK_MARKER;
}

/** Splits `data` into MAX_IMAGE_CHUNK_BYTES-sized chunks. Pure function; a
 * 0-byte image still yields one empty chunk (count=1, idx=0). */
export function splitImageIntoChunks(seq: number, data: Uint8Array, mimeType: string): ImageChunk[] {
  const count = Math.max(1, Math.ceil(data.length / MAX_IMAGE_CHUNK_BYTES));
  const chunks: ImageChunk[] = [];
  for (let idx = 0; idx < count; idx++) {
    const start = idx * MAX_IMAGE_CHUNK_BYTES;
    const end = Math.min(start + MAX_IMAGE_CHUNK_BYTES, data.length);
    chunks.push({
      seq,
      idx,
      count,
      mimeType: idx === 0 ? mimeType : undefined,
      totalBytes: idx === 0 ? data.length : undefined,
      data: data.slice(start, end),
    });
  }
  return chunks;
}

// Frame reassembly: collects chunks by `seq` and only emits once every idx
// in [0, count) has arrived. A new seq starting always means the previous
// (incomplete) frame is abandoned -- same semantics as screenFrameReassembler.
interface PendingImageFrame {
  seq: number;
  count: number;
  mimeType: string;
  chunks: (Uint8Array | undefined)[];
  received: number;
}

export interface ImageFrameReassembler {
  pending: PendingImageFrame | null;
}

export function imageFrameReassemblerInit(): ImageFrameReassembler {
  return { pending: null };
}

/** Feeds one chunk into the reassembler. Returns the reassembled image bytes
 * plus its mimeType once `count` distinct chunks for the same `seq` have all
 * arrived, else null. Starting a new `seq` drops any incomplete frame still
 * pending for the previous one. */
export function imageFrameReassemblerPush(
  reassembler: ImageFrameReassembler,
  chunk: ImageChunk,
): { bytes: Uint8Array; mimeType: string } | null {
  if (!reassembler.pending || reassembler.pending.seq !== chunk.seq) {
    reassembler.pending = {
      seq: chunk.seq,
      count: chunk.count,
      mimeType: chunk.idx === 0 ? (chunk.mimeType ?? "") : "",
      chunks: new Array(chunk.count),
      received: 0,
    };
  }
  const frame = reassembler.pending;
  if (chunk.idx === 0 && chunk.mimeType !== undefined) {
    frame.mimeType = chunk.mimeType;
  }
  if (chunk.idx < frame.count && frame.chunks[chunk.idx] === undefined) {
    frame.chunks[chunk.idx] = chunk.data;
    frame.received++;
  }
  if (frame.received < frame.count) return null;

  reassembler.pending = null;
  return { bytes: concatBytes(frame.chunks as Uint8Array[]), mimeType: frame.mimeType };
}
