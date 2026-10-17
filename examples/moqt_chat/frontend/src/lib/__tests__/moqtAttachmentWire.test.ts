import { describe, expect, it, vi } from "vitest";
import {
	ATTACHMENT_MAX_BYTES,
	ATTACHMENT_MAX_COUNT,
} from "../attachmentValidation";
import {
	ATTACHMENT_CHUNK_MARKER,
	type AttachmentChunk,
	attachmentReassemblerInit,
	attachmentReassemblerPush,
	decodeAttachmentChunkMessage,
	decodeTextPartMessage,
	encodeAttachmentChunkMessage,
	encodeTextPartMessage,
	isAttachmentChunkPayload,
	isTextPartPayload,
	MAX_ATTACHMENT_CHUNK_BYTES,
	splitAttachmentIntoChunks,
	TEXT_PART_MARKER,
} from "../moqtAttachmentWire";
import { MoqtDecodeError } from "../moqtWire";

function bytes(...b: number[]): Uint8Array {
	return new Uint8Array(b);
}

describe("encodeTextPartMessage / decodeTextPartMessage", () => {
	it("round-trips an empty string", () => {
		const wire = encodeTextPartMessage(1, 0, "");
		expect(decodeTextPartMessage(wire)).toEqual({
			messageId: 1,
			attachmentCount: 0,
			text: "",
		});
	});

	it("round-trips a normal ASCII string", () => {
		const wire = encodeTextPartMessage(42, 2, "hello world");
		expect(decodeTextPartMessage(wire)).toEqual({
			messageId: 42,
			attachmentCount: 2,
			text: "hello world",
		});
	});

	it("round-trips multi-byte UTF-8 text", () => {
		const wire = encodeTextPartMessage(7, 1, "こんにちは🎉");
		expect(decodeTextPartMessage(wire)).toEqual({
			messageId: 7,
			attachmentCount: 1,
			text: "こんにちは🎉",
		});
	});

	// M2: textLen is a u16 field -- silently letting it wrap would truncate
	// the receiver's text mid-character instead of failing loudly at encode
	// time.
	it("M2: encodes text at exactly the u16 textLen boundary (65535 bytes)", () => {
		const text = "a".repeat(65535);
		const wire = encodeTextPartMessage(1, 0, text);
		expect(decodeTextPartMessage(wire).text).toBe(text);
	});

	it("M2: throws when the UTF-8 byte length exceeds the u16 textLen boundary (65536 bytes)", () => {
		const text = "a".repeat(65536);
		expect(() => encodeTextPartMessage(1, 0, text)).toThrow(MoqtDecodeError);
	});
});

describe("golden wire vectors (hand-computed, not copied from the encoder)", () => {
	it("text-part: marker | messageId u32 BE | attachmentCount u8 | textLen u16 BE | text", () => {
		// marker=0xFE, messageId u32 BE=1, attachmentCount=2, textLen u16 BE=2,
		// text="ab" (UTF-8: 0x61 0x62).
		const golden = bytes(
			0xfe, // marker
			0x00,
			0x00,
			0x00,
			0x01, // messageId u32 BE = 1
			0x02, // attachmentCount = 2
			0x00,
			0x02, // textLen u16 BE = 2
			0x61,
			0x62, // "ab"
		);

		expect(decodeTextPartMessage(golden)).toEqual({
			messageId: 1,
			attachmentCount: 2,
			text: "ab",
		});
		expect(encodeTextPartMessage(1, 2, "ab")).toEqual(golden);
	});

	it("attachment chunk idx=0: marker | messageId u32 | attachmentIdx u8 | seq u32 | idx u16 | count u16 | mimeLen u8 + mimeType + totalBytes u32 | data", () => {
		// marker=0xFD, messageId u32 BE=1, attachmentIdx=0, seq u32 BE=0,
		// idx u16 BE=0, count u16 BE=2, mimeLen=9, "image/png" (9 bytes),
		// totalBytes u32 BE=5, data=[0xAA,0xBB].
		const golden = bytes(
			0xfd, // marker
			0x00,
			0x00,
			0x00,
			0x01, // messageId u32 BE = 1
			0x00, // attachmentIdx = 0
			0x00,
			0x00,
			0x00,
			0x00, // seq u32 BE = 0
			0x00,
			0x00, // idx u16 BE = 0
			0x00,
			0x02, // count u16 BE = 2
			0x09, // mimeType len = 9
			0x69,
			0x6d,
			0x61,
			0x67,
			0x65,
			0x2f,
			0x70,
			0x6e,
			0x67, // "image/png"
			0x00,
			0x00,
			0x00,
			0x05, // totalBytes u32 BE = 5
			0xaa,
			0xbb, // chunk data
		);

		const expected: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 2,
			mimeType: "image/png",
			totalBytes: 5,
			data: bytes(0xaa, 0xbb),
		};
		expect(decodeAttachmentChunkMessage(golden)).toEqual(expected);
		expect(encodeAttachmentChunkMessage(expected)).toEqual(golden);
	});

	it("attachment chunk idx>0: marker | messageId u32 | attachmentIdx u8 | seq u32 | idx u16 | count u16 | data (no metadata)", () => {
		// marker=0xFD, messageId u32 BE=1, attachmentIdx=0, seq u32 BE=0,
		// idx u16 BE=1, count u16 BE=2, data=[0xCC,0xDD,0xEE] (no mimeType/
		// totalBytes -- those only ride on idx===0).
		const golden = bytes(
			0xfd, // marker
			0x00,
			0x00,
			0x00,
			0x01, // messageId u32 BE = 1
			0x00, // attachmentIdx = 0
			0x00,
			0x00,
			0x00,
			0x00, // seq u32 BE = 0
			0x00,
			0x01, // idx u16 BE = 1
			0x00,
			0x02, // count u16 BE = 2
			0xcc,
			0xdd,
			0xee, // chunk data
		);

		const expected: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 1,
			count: 2,
			mimeType: undefined,
			totalBytes: undefined,
			data: bytes(0xcc, 0xdd, 0xee),
		};
		expect(decodeAttachmentChunkMessage(golden)).toEqual(expected);
		expect(encodeAttachmentChunkMessage(expected)).toEqual(golden);
	});
});

describe("encodeAttachmentChunkMessage / decodeAttachmentChunkMessage", () => {
	it("round-trips a chunk with 0-byte data", () => {
		const chunk: AttachmentChunk = {
			messageId: 5,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: "image/png",
			totalBytes: 0,
			data: new Uint8Array(0),
		};
		const wire = encodeAttachmentChunkMessage(chunk);
		expect(decodeAttachmentChunkMessage(wire)).toEqual(chunk);
	});

	it("round-trips a chunk that fits exactly one chunk (idx>0, no metadata)", () => {
		const chunk: AttachmentChunk = {
			messageId: 5,
			attachmentIdx: 2,
			seq: 0,
			idx: 1,
			count: 2,
			mimeType: undefined,
			totalBytes: undefined,
			data: bytes(0xaa, 0xbb, 0xcc),
		};
		const wire = encodeAttachmentChunkMessage(chunk);
		expect(decodeAttachmentChunkMessage(wire)).toEqual(chunk);
	});

	it("a 1 MB attachment travels as ~15 KiB chunks (at most 70 Objects)", () => {
		const chunks = splitAttachmentIntoChunks(
			1,
			0,
			"image/png",
			new Uint8Array(1_000_000),
		);
		expect(chunks.length).toBeLessThanOrEqual(70);
	});

	it("the largest chunk Object (255-byte MIME type on idx 0) fits the hub's 16380-byte payload cap", () => {
		const payload = encodeAttachmentChunkMessage({
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: `image/${"x".repeat(249)}`,
			totalBytes: MAX_ATTACHMENT_CHUNK_BYTES,
			data: new Uint8Array(MAX_ATTACHMENT_CHUNK_BYTES),
		});
		expect(payload.length).toBeLessThanOrEqual(16380);
	});

	it("round-trips a chunk at the MAX_ATTACHMENT_CHUNK_BYTES boundary", () => {
		const data = new Uint8Array(MAX_ATTACHMENT_CHUNK_BYTES);
		data.fill(9);
		const chunk: AttachmentChunk = {
			messageId: 99,
			attachmentIdx: 3,
			seq: 0,
			idx: 0,
			count: 2,
			mimeType: "video/mp4",
			totalBytes: MAX_ATTACHMENT_CHUNK_BYTES * 2,
			data,
		};
		const wire = encodeAttachmentChunkMessage(chunk);
		expect(decodeAttachmentChunkMessage(wire)).toEqual(chunk);
	});

	it("throws MoqtDecodeError when the marker byte does not match", () => {
		expect(() => decodeAttachmentChunkMessage(bytes(0x00, 0x01, 0x02))).toThrow(
			MoqtDecodeError,
		);
	});

	it("throws MoqtDecodeError on truncated input", () => {
		expect(() =>
			decodeAttachmentChunkMessage(bytes(ATTACHMENT_CHUNK_MARKER, 0x00)),
		).toThrow(MoqtDecodeError);
	});
});

describe("isAttachmentChunkPayload / isTextPartPayload", () => {
	it("isAttachmentChunkPayload is true only for 0xFD-prefixed payloads", () => {
		expect(isAttachmentChunkPayload(bytes(ATTACHMENT_CHUNK_MARKER, 0x01))).toBe(
			true,
		);
		expect(isAttachmentChunkPayload(bytes(TEXT_PART_MARKER, 0x01))).toBe(false);
		expect(isAttachmentChunkPayload(bytes(0x00, 0x01))).toBe(false);
	});

	it("isTextPartPayload is true only for 0xFE-prefixed payloads", () => {
		expect(isTextPartPayload(bytes(TEXT_PART_MARKER, 0x01))).toBe(true);
		expect(isTextPartPayload(bytes(ATTACHMENT_CHUNK_MARKER, 0x01))).toBe(false);
		expect(isTextPartPayload(bytes(0x00, 0x01))).toBe(false);
	});

	it("markers do not collide with the existing nickname marker (0x00)", () => {
		expect(ATTACHMENT_CHUNK_MARKER).not.toBe(0x00);
		expect(TEXT_PART_MARKER).not.toBe(0x00);
		expect(ATTACHMENT_CHUNK_MARKER).not.toBe(TEXT_PART_MARKER);
	});
});

describe("splitAttachmentIntoChunks + attachmentReassemblerPush", () => {
	it("reassembles all chunks fed in shuffled order, emitting exactly once", () => {
		const data = new Uint8Array(MAX_ATTACHMENT_CHUNK_BYTES * 2 + 10);
		for (let i = 0; i < data.length; i++) data[i] = i % 256;
		const chunks = splitAttachmentIntoChunks(11, 0, "video/mp4", data);
		expect(chunks.length).toBe(3);

		// shuffle: reverse order
		const shuffled = [...chunks].reverse();
		const state = attachmentReassemblerInit();
		const results: (Uint8Array | null)[] = shuffled.map((c) =>
			attachmentReassemblerPush(state, c),
		);

		const nonNull = results.filter((r) => r !== null);
		expect(nonNull.length).toBe(1);
		expect(nonNull[0]).toEqual(data);
	});
});

describe("attachmentReassemblerPush timeout", () => {
	it("silently drops a pending frame after 30s with no completion", () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(0);
			const state = attachmentReassemblerInit();
			const chunks = splitAttachmentIntoChunks(
				1,
				0,
				"image/png",
				bytes(1, 2, 3),
			);
			// withhold the last chunk to keep it incomplete
			for (const c of chunks.slice(0, -1)) {
				expect(attachmentReassemblerPush(state, c)).toBeNull();
			}

			vi.setSystemTime(30_001);
			// pushing the same key after timeout starts a fresh cycle; feed all
			// chunks of a brand new frame and expect the OLD partial data not to
			// leak into it.
			const fresh = splitAttachmentIntoChunks(
				1,
				0,
				"image/png",
				bytes(9, 8, 7),
			);
			let result: Uint8Array | null = null;
			for (const c of fresh) {
				const r = attachmentReassemblerPush(state, c);
				if (r) result = r;
			}
			expect(result).toEqual(bytes(9, 8, 7));
		} finally {
			vi.useRealTimers();
		}
	});

	it("keeps a near-the-byte-limit pending frame alive well past 30s", () => {
		// A chunk's own declared count is all attachmentReassemblerPush ever
		// sees -- the deadline must come from that, not the bytes actually
		// delivered so far (seeing only the first few chunks must already
		// imply the long deadline the full count calls for).
		vi.useFakeTimers();
		try {
			vi.setSystemTime(0);
			const state = attachmentReassemblerInit();
			const count = Math.floor(
				ATTACHMENT_MAX_BYTES / MAX_ATTACHMENT_CHUNK_BYTES,
			);
			const first: AttachmentChunk = {
				messageId: 1,
				attachmentIdx: 0,
				seq: 0,
				idx: 0,
				count,
				mimeType: "image/png",
				totalBytes: ATTACHMENT_MAX_BYTES,
				data: new Uint8Array([1]),
			};
			expect(attachmentReassemblerPush(state, first)).toBeNull();

			// 30s and 60s, both well under a max-size frame's deadline, must
			// not have pruned it.
			vi.setSystemTime(30_001);
			expect(attachmentReassemblerPush(state, first)).toBeNull();
			expect(state.pending.size).toBe(1);
			vi.setSystemTime(60_001);
			expect(attachmentReassemblerPush(state, first)).toBeNull();
			expect(state.pending.size).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("attachmentReassemblerPush trust-boundary guards (I1)", () => {
	it("I1(c): a chunk with count===0 is dropped, never emitted as an empty attachment", () => {
		const state = attachmentReassemblerInit();
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 0,
			mimeType: "image/png",
			totalBytes: 0,
			data: new Uint8Array(0),
		};
		expect(attachmentReassemblerPush(state, chunk)).toBeNull();
		expect(state.pending.size).toBe(0);
	});

	it("I1(b1): attachmentIdx at the boundary (ATTACHMENT_MAX_COUNT - 1) is accepted", () => {
		const state = attachmentReassemblerInit();
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: ATTACHMENT_MAX_COUNT - 1,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: "image/png",
			totalBytes: 1,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toEqual(
			new Uint8Array([1]),
		);
	});

	it("I1(b1): attachmentIdx === ATTACHMENT_MAX_COUNT is dropped", () => {
		const state = attachmentReassemblerInit();
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: ATTACHMENT_MAX_COUNT,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: "image/png",
			totalBytes: 1,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toBeNull();
		expect(state.pending.size).toBe(0);
	});

	it("I1(e): an unsupported mimeType on the idx===0 chunk is dropped", () => {
		const state = attachmentReassemblerInit();
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: "application/octet-stream",
			totalBytes: 1,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toBeNull();
		expect(state.pending.size).toBe(0);
	});

	it("I1(e): an allowed image/* mimeType on idx===0 is accepted", () => {
		const state = attachmentReassemblerInit();
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 1,
			mimeType: "image/png",
			totalBytes: 1,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toEqual(
			new Uint8Array([1]),
		);
	});

	it("I1(d): count at the boundary (count * MAX_ATTACHMENT_CHUNK_BYTES === ATTACHMENT_MAX_BYTES) is accepted", () => {
		const state = attachmentReassemblerInit();
		const maxCount = Math.floor(
			ATTACHMENT_MAX_BYTES / MAX_ATTACHMENT_CHUNK_BYTES,
		);
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: maxCount,
			mimeType: "image/png",
			totalBytes: maxCount * MAX_ATTACHMENT_CHUNK_BYTES,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toBeNull(); // incomplete, but not dropped
		expect(state.pending.size).toBe(1);
	});

	it("I1(d): count one past the boundary is dropped before any chunk is buffered", () => {
		const state = attachmentReassemblerInit();
		const maxCount =
			Math.floor(ATTACHMENT_MAX_BYTES / MAX_ATTACHMENT_CHUNK_BYTES) + 1;
		const chunk: AttachmentChunk = {
			messageId: 1,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: maxCount,
			mimeType: "image/png",
			totalBytes: maxCount * MAX_ATTACHMENT_CHUNK_BYTES,
			data: new Uint8Array([1]),
		};
		expect(attachmentReassemblerPush(state, chunk)).toBeNull();
		expect(state.pending.size).toBe(0);
	});
});

describe("attachmentReassemblerPush key reuse across independent cycles", () => {
	it("does not mix stale chunks from a completed cycle into a new cycle with the same key", () => {
		const state = attachmentReassemblerInit();
		const first = splitAttachmentIntoChunks(1, 0, "image/png", bytes(1, 2, 3));
		let firstResult: Uint8Array | null = null;
		for (const c of first) {
			const r = attachmentReassemblerPush(state, c);
			if (r) firstResult = r;
		}
		expect(firstResult).toEqual(bytes(1, 2, 3));

		// Same messageId+attachmentIdx key, new cycle (e.g. resend/replace).
		const second = splitAttachmentIntoChunks(1, 0, "image/png", bytes(4, 5));
		let secondResult: Uint8Array | null = null;
		for (const c of second) {
			const r = attachmentReassemblerPush(state, c);
			if (r) secondResult = r;
		}
		expect(secondResult).toEqual(bytes(4, 5));
	});
});

describe("attachmentReassemblerPush duplicate / out-of-range / late-metadata chunks", () => {
	it("ignores a duplicate and an idx >= count, and takes the idx 0 mimeType once it arrives", () => {
		const state = attachmentReassemblerInit();
		const chunk = (idx: number, data: Uint8Array): AttachmentChunk => ({
			messageId: 7,
			attachmentIdx: 0,
			seq: 0,
			idx,
			count: 2,
			mimeType: idx === 0 ? "image/png" : undefined,
			data,
		});
		expect(attachmentReassemblerPush(state, chunk(1, bytes(2)))).toBeNull();
		expect(state.pending.get("7:0")?.mimeType).toBe("");
		expect(attachmentReassemblerPush(state, chunk(1, bytes(9)))).toBeNull();
		expect(attachmentReassemblerPush(state, chunk(5, bytes(9)))).toBeNull();
		expect(state.pending.get("7:0")?.received).toBe(1);
		expect(attachmentReassemblerPush(state, chunk(0, bytes(1)))).toEqual(
			bytes(1, 2),
		);
	});

	it("records the mimeType when idx 0 opens the frame", () => {
		const state = attachmentReassemblerInit();
		attachmentReassemblerPush(state, {
			messageId: 8,
			attachmentIdx: 0,
			seq: 0,
			idx: 0,
			count: 2,
			mimeType: "image/png",
			data: bytes(1),
		});
		expect(state.pending.get("8:0")?.mimeType).toBe("image/png");
	});
});

describe("encodeAttachmentChunkMessage idx=0 without metadata", () => {
	it("writes an empty MIME type and totalBytes 0", () => {
		const out = encodeAttachmentChunkMessage({
			messageId: 1,
			attachmentIdx: 2,
			seq: 3,
			idx: 0,
			count: 1,
			data: bytes(0xaa),
		});
		expect(out).toEqual(
			bytes(0xfd, 0, 0, 0, 1, 2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0xaa),
		);
	});
});
