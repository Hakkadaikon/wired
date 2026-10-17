// Screen-share Object wire framing on top of moqtWire.ts's generic MOQT
// codec. Same "one message, one uni stream" shape as moqtVoiceWire.ts (see
// its own doc for why); each Object carries one video chunk.
//
// Unlike voice, which tolerates a missing sample (drops it and keeps
// going), a screen-share frame is useless if any chunk is missing --
// partial video data cannot be handed to a decoder. So the frame
// reassembler here discards the whole frame the moment a later frame
// (`seq`) starts before the previous one collected all `count` chunks.

import { SUBGROUP_HEADER_TYPE } from "./moqtClient";
import { concatBytes, encodeVarint, MoqtDecodeError } from "./moqtWire";

const CHUNK_HEADER_LEN = 2 + 2 + 2 + 1 + 4; // seq | idx | count | flags | ts
const KEYFRAME_FLAG = 0x01;

export interface ScreenChunk {
	seq: number;
	idx: number;
	count: number;
	keyframe: boolean;
	timestampUs: number;
	/** Present only when keyframe && idx===0. */
	width?: number;
	height?: number;
	codec?: string;
	data: Uint8Array;
}

/** Builds the SUBGROUP_HEADER a screen-share stream opens with (once),
 * before any Objects. Mirrors buildVoiceSubgroupHeader. */
export function buildScreenSubgroupHeader(
	trackAlias: bigint,
	groupId: bigint,
): Uint8Array {
	return concatBytes([
		encodeVarint(SUBGROUP_HEADER_TYPE),
		encodeVarint(trackAlias),
		encodeVarint(groupId),
	]);
}

function putU16(out: Uint8Array, offset: number, value: number): void {
	out[offset] = (value >> 8) & 0xff;
	out[offset + 1] = value & 0xff;
}

function getU16(bytes: Uint8Array, offset: number): number {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

/** Encodes one screen-share chunk as a MoQT Object body (chunk-header
 * codec: seq u16 | idx u16 | count u16 | flags u8 (bit0=keyframe) | ts u32,
 * with width u16 | height u16 | codec len u8 + bytes appended only for the
 * keyframe's idx=0 chunk). */
export function encodeScreenObjectMessage(chunk: ScreenChunk): Uint8Array {
	const meta = screenChunkMeta(chunk);
	const out = new Uint8Array(
		CHUNK_HEADER_LEN + meta.length + chunk.data.length,
	);

	putU16(out, 0, chunk.seq);
	putU16(out, 2, chunk.idx);
	putU16(out, 4, chunk.count);
	out[6] = chunk.keyframe ? KEYFRAME_FLAG : 0;
	new DataView(out.buffer).setUint32(7, chunk.timestampUs, false);

	out.set(meta, CHUNK_HEADER_LEN);
	out.set(chunk.data, CHUNK_HEADER_LEN + meta.length);
	return out;
}

/** width u16 | height u16 | codec len u8 + bytes, only for the keyframe's
 * idx=0 chunk; empty for every other chunk. */
function screenChunkMeta(chunk: ScreenChunk): Uint8Array {
	if (!chunk.keyframe || chunk.idx !== 0) return new Uint8Array(0);
	const codecBytes = new TextEncoder().encode(chunk.codec ?? "");
	const meta = new Uint8Array(5 + codecBytes.length);
	putU16(meta, 0, chunk.width ?? 0);
	putU16(meta, 2, chunk.height ?? 0);
	meta[4] = codecBytes.length;
	meta.set(codecBytes, 5);
	return meta;
}

/** Decodes one screen-share chunk from a MoQT Object body; the inverse of
 * encodeScreenObjectMessage. Returns the chunk plus how many bytes it
 * consumed (always the full input, since a chunk is the whole body). */
export function decodeScreenObjectMessage(bytes: Uint8Array): {
	chunk: ScreenChunk;
} {
	if (bytes.length < CHUNK_HEADER_LEN) {
		throw new MoqtDecodeError(
			"screen Object payload shorter than chunk header",
		);
	}
	const seq = getU16(bytes, 0);
	const idx = getU16(bytes, 2);
	const count = getU16(bytes, 4);
	const keyframe = (bytes[6] & KEYFRAME_FLAG) !== 0;
	const timestampUs = new DataView(
		bytes.buffer,
		bytes.byteOffset,
		bytes.byteLength,
	).getUint32(7, false);

	let pos = CHUNK_HEADER_LEN;
	let width: number | undefined;
	let height: number | undefined;
	let codec: string | undefined;
	if (keyframe && idx === 0) {
		if (pos + 5 > bytes.length) {
			throw new MoqtDecodeError("screen Object keyframe metadata truncated");
		}
		width = getU16(bytes, pos);
		height = getU16(bytes, pos + 2);
		const codecLen = bytes[pos + 4];
		pos += 5;
		if (pos + codecLen > bytes.length) {
			throw new MoqtDecodeError("screen Object codec name truncated");
		}
		codec = new TextDecoder().decode(bytes.slice(pos, pos + codecLen));
		pos += codecLen;
	}

	return {
		chunk: {
			seq,
			idx,
			count,
			keyframe,
			timestampUs,
			width,
			height,
			codec,
			data: bytes.slice(pos),
		},
	};
}

// Frame reassembly: collects chunks by `seq` and only emits a frame once
// every idx in [0, count) has arrived. Unlike voice (which just forwards
// whatever samples show up), a frame missing even one chunk is discarded
// entirely -- a video decoder cannot use a frame with a hole in it. A new
// seq starting always means the previous (incomplete) frame is abandoned.
interface PendingFrame {
	seq: number;
	count: number;
	chunks: (Uint8Array | undefined)[];
	received: number;
}

export interface ScreenFrameReassembler {
	pending: PendingFrame | null;
}

export function screenFrameReassemblerInit(): ScreenFrameReassembler {
	return { pending: null };
}

/** Feeds one chunk into the reassembler. Returns the reassembled frame
 * bytes (chunk data concatenated in idx order) once `count` distinct
 * chunks for the same `seq` have all arrived, else null. Starting a new
 * `seq` drops any incomplete frame still pending for the previous one. */
export function screenFrameReassemblerPush(
	reassembler: ScreenFrameReassembler,
	chunk: ScreenChunk,
): Uint8Array | null {
	if (!reassembler.pending || reassembler.pending.seq !== chunk.seq) {
		reassembler.pending = {
			seq: chunk.seq,
			count: chunk.count,
			chunks: new Array(chunk.count),
			received: 0,
		};
	}
	const frame = reassembler.pending;
	if (chunk.idx < frame.count && frame.chunks[chunk.idx] === undefined) {
		frame.chunks[chunk.idx] = chunk.data;
		frame.received++;
	}
	if (frame.received < frame.count) return null;

	reassembler.pending = null;
	return concatBytes(frame.chunks as Uint8Array[]);
}
