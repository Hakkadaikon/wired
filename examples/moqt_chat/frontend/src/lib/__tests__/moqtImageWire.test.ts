import { describe, expect, it } from "vitest";
import { concatBytes, decodeSubgroupHeader, decodeSubgroupObject, encodeVarint } from "../moqtWire";
import { MoqtDecodeError } from "../moqtWire";
import {
  buildImageSubgroupHeader,
  decodeImageChunkMessage,
  encodeImageChunkMessage,
  imageFrameReassemblerInit,
  imageFrameReassemblerPush,
  isImageChunkPayload,
  splitImageIntoChunks,
  MAX_IMAGE_CHUNK_BYTES,
  IMAGE_CHUNK_MARKER,
  type ImageChunk,
} from "../moqtImageWire";

function bytes(...b: number[]): Uint8Array {
  return new Uint8Array(b);
}

describe("buildImageSubgroupHeader", () => {
  it("round-trips through decodeSubgroupHeader", () => {
    const wire = buildImageSubgroupHeader(9n, 3n);
    const { header } = decodeSubgroupHeader(wire);
    expect(header.trackAlias).toBe(9n);
    expect(header.groupId).toBe(3n);
    expect(header.flags.firstObject).toBe(true);
  });
});

describe("encodeImageChunkMessage / decodeImageChunkMessage", () => {
  it("golden round-trip: idx=0 chunk with mimeType + totalBytes", () => {
    // marker=0xff, seq u32 BE=1, idx u16 BE=0, count u16 BE=2,
    // mimeType len=9, "image/png", totalBytes u32 BE=5, data=[0xAA,0xBB]
    const golden = bytes(
      0xff, // marker
      0x00,
      0x00,
      0x00,
      0x01, // seq u32 BE = 1
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

    const decoded = decodeImageChunkMessage(golden);
    expect(decoded.chunk).toEqual<ImageChunk>({
      seq: 1,
      idx: 0,
      count: 2,
      mimeType: "image/png",
      totalBytes: 5,
      data: bytes(0xaa, 0xbb),
    });

    expect(encodeImageChunkMessage(decoded.chunk)).toEqual(golden);
  });

  it("golden round-trip: idx>0 chunk carries no metadata", () => {
    const golden = bytes(
      0xff, // marker
      0x00,
      0x00,
      0x00,
      0x01, // seq = 1
      0x00,
      0x01, // idx = 1
      0x00,
      0x02, // count = 2
      0xcc,
      0xdd,
      0xee, // chunk data
    );

    const decoded = decodeImageChunkMessage(golden);
    expect(decoded.chunk).toEqual<ImageChunk>({
      seq: 1,
      idx: 1,
      count: 2,
      mimeType: undefined,
      totalBytes: undefined,
      data: bytes(0xcc, 0xdd, 0xee),
    });

    expect(encodeImageChunkMessage(decoded.chunk)).toEqual(golden);
  });

  it("throws MoqtDecodeError when the marker byte does not match", () => {
    const bad = bytes(0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb);
    expect(() => decodeImageChunkMessage(bad)).toThrow(MoqtDecodeError);
  });

  it("throws MoqtDecodeError on truncated input", () => {
    expect(() => decodeImageChunkMessage(bytes(0xff, 0x00, 0x01))).toThrow(MoqtDecodeError);
  });

  it("throws MoqtDecodeError when idx=0 metadata is truncated before the mimeLen byte", () => {
    // marker + seq u32 + idx u16=0 + count u16, then nothing: the mimeLen
    // byte itself is missing.
    const truncated = bytes(0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02);
    expect(() => decodeImageChunkMessage(truncated)).toThrow(MoqtDecodeError);
  });

  it("throws MoqtDecodeError when idx=0 metadata is truncated after mimeLen", () => {
    // Same 9-byte header, then mimeLen=3 claiming 3 mimeType bytes + 4
    // totalBytes bytes that never follow.
    const truncated = bytes(0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x03);
    expect(() => decodeImageChunkMessage(truncated)).toThrow(MoqtDecodeError);
  });
});

describe("isImageChunkPayload", () => {
  it("returns true when the first byte is the image chunk marker", () => {
    expect(isImageChunkPayload(bytes(0xff, 0x01, 0x02))).toBe(true);
  });

  it("returns false when the first byte is not the image chunk marker", () => {
    expect(isImageChunkPayload(bytes(0x00, 0x01, 0x02))).toBe(false);
  });
});

describe("splitImageIntoChunks", () => {
  it("splits data that divides evenly by MAX_IMAGE_CHUNK_BYTES", () => {
    const data = new Uint8Array(MAX_IMAGE_CHUNK_BYTES * 2);
    data.fill(7);
    const chunks = splitImageIntoChunks(1, data, "image/png");

    expect(chunks).toHaveLength(2);
    expect(chunks[0].idx).toBe(0);
    expect(chunks[0].count).toBe(2);
    expect(chunks[0].seq).toBe(1);
    expect(chunks[0].mimeType).toBe("image/png");
    expect(chunks[0].totalBytes).toBe(data.length);
    expect(chunks[0].data).toHaveLength(MAX_IMAGE_CHUNK_BYTES);
    expect(chunks[1].idx).toBe(1);
    expect(chunks[1].count).toBe(2);
    expect(chunks[1].mimeType).toBeUndefined();
    expect(chunks[1].totalBytes).toBeUndefined();
    expect(chunks[1].data).toHaveLength(MAX_IMAGE_CHUNK_BYTES);
  });

  it("splits data with a remainder chunk", () => {
    const data = new Uint8Array(MAX_IMAGE_CHUNK_BYTES + 10);
    data.fill(3);
    const chunks = splitImageIntoChunks(2, data, "image/jpeg");

    expect(chunks).toHaveLength(2);
    expect(chunks[0].count).toBe(2);
    expect(chunks[0].data).toHaveLength(MAX_IMAGE_CHUNK_BYTES);
    expect(chunks[1].count).toBe(2);
    expect(chunks[1].idx).toBe(1);
    expect(chunks[1].data).toHaveLength(10);
  });

  it("returns a single chunk when data fits within one chunk", () => {
    const data = bytes(1, 2, 3);
    const chunks = splitImageIntoChunks(3, data, "image/gif");

    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual<ImageChunk>({
      seq: 3,
      idx: 0,
      count: 1,
      mimeType: "image/gif",
      totalBytes: 3,
      data: bytes(1, 2, 3),
    });
  });

  it("returns a single empty chunk for a 0-byte image", () => {
    const chunks = splitImageIntoChunks(4, new Uint8Array(0), "image/png");

    expect(chunks).toHaveLength(1);
    expect(chunks[0].count).toBe(1);
    expect(chunks[0].idx).toBe(0);
    expect(chunks[0].data).toHaveLength(0);
  });
});

describe("image frame reassembly", () => {
  it("emits the reconstructed bytes and mimeType once all chunks arrive", () => {
    const state = imageFrameReassemblerInit();
    const chunks: ImageChunk[] = [
      { seq: 5, idx: 0, count: 2, mimeType: "image/png", totalBytes: 4, data: bytes(1, 2) },
      { seq: 5, idx: 1, count: 2, data: bytes(3, 4) },
    ];

    let result: { bytes: Uint8Array; mimeType: string } | null = null;
    for (const chunk of chunks) {
      const r = imageFrameReassemblerPush(state, chunk);
      if (r) result = r;
    }

    expect(result).toEqual({ bytes: bytes(1, 2, 3, 4), mimeType: "image/png" });
  });

  it("returns null and drops the previous incomplete frame when a new seq arrives", () => {
    const state = imageFrameReassemblerInit();
    const first: ImageChunk = {
      seq: 1,
      idx: 0,
      count: 2,
      mimeType: "image/png",
      totalBytes: 2,
      data: bytes(1),
    };
    const next: ImageChunk = {
      seq: 2,
      idx: 0,
      count: 1,
      mimeType: "image/gif",
      totalBytes: 1,
      data: bytes(9),
    };

    expect(imageFrameReassemblerPush(state, first)).toBeNull();
    const result = imageFrameReassemblerPush(state, next);
    expect(result).toEqual({ bytes: bytes(9), mimeType: "image/gif" });
  });
});

describe("buildImageSubgroupHeader + encodeImageChunkMessage as Object body", () => {
  it("embeds inside a MoQT Object and decodes back", () => {
    const header = buildImageSubgroupHeader(4n, 1n);
    const chunk: ImageChunk = {
      seq: 2,
      idx: 0,
      count: 1,
      mimeType: "image/webp",
      totalBytes: 2,
      data: bytes(0x11, 0x22),
    };
    const body = encodeImageChunkMessage(chunk);
    const objectMsg = concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    const wire = concatBytes([header, objectMsg]);

    const { object } = decodeSubgroupObject(wire, header.length, false, 0n, true);
    expect(decodeImageChunkMessage(object.payload).chunk).toEqual(chunk);
  });
});
