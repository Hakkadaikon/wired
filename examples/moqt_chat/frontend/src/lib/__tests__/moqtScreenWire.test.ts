import { describe, expect, it } from "vitest";
import { concatBytes, decodeSubgroupHeader } from "../moqtWire";
import {
  buildScreenSubgroupHeader,
  decodeScreenObjectMessage,
  encodeScreenObjectMessage,
  screenFrameReassemblerInit,
  screenFrameReassemblerPush,
  type ScreenChunk,
} from "../moqtScreenWire";

function bytes(...b: number[]): Uint8Array {
  return new Uint8Array(b);
}

describe("buildScreenSubgroupHeader", () => {
  it("round-trips through decodeSubgroupHeader", () => {
    const wire = buildScreenSubgroupHeader(9n, 3n);
    const { header } = decodeSubgroupHeader(wire);
    expect(header.trackAlias).toBe(9n);
    expect(header.groupId).toBe(3n);
    expect(header.flags.firstObject).toBe(true);
  });
});

describe("encodeScreenObjectMessage / decodeScreenObjectMessage", () => {
  it("golden round-trip: keyframe idx=0 chunk with codec metadata", () => {
    // seq=1, idx=0, count=2, flags=0x01 (keyframe), ts=1000000us,
    // width=1920, height=1080, codec="vp8" (len 3), data=[0xAA,0xBB]
    const golden = bytes(
      0x00,
      0x01, // seq u16 BE = 1
      0x00,
      0x00, // idx u16 BE = 0
      0x00,
      0x02, // count u16 BE = 2
      0x01, // flags = keyframe
      0x00,
      0x0f,
      0x42,
      0x40, // ts u32 BE = 1_000_000
      0x07,
      0x80, // width u16 BE = 1920
      0x04,
      0x38, // height u16 BE = 1080
      0x03, // codec len = 3
      0x76,
      0x70,
      0x38, // "vp8"
      0xaa,
      0xbb, // chunk data
    );

    const decoded = decodeScreenObjectMessage(golden);
    expect(decoded.chunk).toEqual<ScreenChunk>({
      seq: 1,
      idx: 0,
      count: 2,
      keyframe: true,
      timestampUs: 1_000_000,
      width: 1920,
      height: 1080,
      codec: "vp8",
      data: bytes(0xaa, 0xbb),
    });

    const reEncoded = encodeScreenObjectMessage(decoded.chunk);
    expect(reEncoded).toEqual(golden);
  });

  it("golden round-trip: non-keyframe idx>0 chunk carries no codec metadata", () => {
    const golden = bytes(
      0x00,
      0x01, // seq = 1
      0x00,
      0x01, // idx = 1
      0x00,
      0x02, // count = 2
      0x00, // flags = 0 (not keyframe)
      0x00,
      0x0f,
      0x42,
      0x40, // ts = 1_000_000
      0xcc,
      0xdd,
      0xee, // chunk data
    );

    const decoded = decodeScreenObjectMessage(golden);
    expect(decoded.chunk).toEqual<ScreenChunk>({
      seq: 1,
      idx: 1,
      count: 2,
      keyframe: false,
      timestampUs: 1_000_000,
      width: undefined,
      height: undefined,
      codec: undefined,
      data: bytes(0xcc, 0xdd, 0xee),
    });

    expect(encodeScreenObjectMessage(decoded.chunk)).toEqual(golden);
  });
});

describe("screen frame reassembly", () => {
  it("emits a frame once all chunks for a seq have arrived", () => {
    const reassembler = screenFrameReassemblerInit();
    const chunks: ScreenChunk[] = [
      {
        seq: 5,
        idx: 0,
        count: 3,
        keyframe: true,
        timestampUs: 42,
        width: 640,
        height: 480,
        codec: "vp8",
        data: bytes(1, 2),
      },
      { seq: 5, idx: 1, count: 3, keyframe: false, timestampUs: 42, data: bytes(3, 4) },
      { seq: 5, idx: 2, count: 3, keyframe: false, timestampUs: 42, data: bytes(5, 6) },
    ];

    let emitted: Uint8Array | null = null;
    for (const chunk of chunks) {
      const frame = screenFrameReassemblerPush(reassembler, chunk);
      if (frame) emitted = frame;
    }

    expect(emitted).toEqual(bytes(1, 2, 3, 4, 5, 6));
  });

  it("discards the entire frame when a chunk (idx) is missing", () => {
    const reassembler = screenFrameReassemblerInit();
    // 3-chunk frame, idx=1 never arrives.
    const chunks: ScreenChunk[] = [
      {
        seq: 7,
        idx: 0,
        count: 3,
        keyframe: true,
        timestampUs: 1,
        width: 320,
        height: 240,
        codec: "vp8",
        data: bytes(1),
      },
      { seq: 7, idx: 2, count: 3, keyframe: false, timestampUs: 1, data: bytes(3) },
    ];

    let emitted: Uint8Array | null = null;
    for (const chunk of chunks) {
      const frame = screenFrameReassemblerPush(reassembler, chunk);
      if (frame) emitted = frame;
    }

    expect(emitted).toBeNull();
  });

  it("drops a partial frame once a later seq starts, without emitting it", () => {
    const reassembler = screenFrameReassemblerInit();
    const first = {
      seq: 1,
      idx: 0,
      count: 2,
      keyframe: true,
      timestampUs: 1,
      width: 10,
      height: 10,
      codec: "vp8",
      data: bytes(1),
    };
    const next = {
      seq: 2,
      idx: 0,
      count: 1,
      keyframe: true,
      timestampUs: 2,
      width: 10,
      height: 10,
      codec: "vp8",
      data: bytes(9),
    };

    expect(screenFrameReassemblerPush(reassembler, first)).toBeNull();
    const frame = screenFrameReassemblerPush(reassembler, next);
    expect(frame).toEqual(bytes(9));
  });
});

describe("encodeScreenObjectMessage validation", () => {
  it("throws MoqtDecodeError on truncated input", async () => {
    const { MoqtDecodeError } = await import("../moqtWire");
    expect(() => decodeScreenObjectMessage(bytes(0x00, 0x01))).toThrow(MoqtDecodeError);
  });
});

describe("buildScreenSubgroupHeader + encodeScreenObjectMessage as Object body", () => {
  it("embeds inside a MoQT Object with ID delta 0 and decodes back", async () => {
    const { decodeSubgroupObject } = await import("../moqtWire");
    const header = buildScreenSubgroupHeader(4n, 1n);
    const chunk: ScreenChunk = {
      seq: 2,
      idx: 0,
      count: 1,
      keyframe: true,
      timestampUs: 5,
      width: 100,
      height: 50,
      codec: "vp9",
      data: bytes(0x11, 0x22),
    };
    const body = encodeScreenObjectMessage(chunk);
    const { encodeVarint } = await import("../moqtWire");
    const objectMsg = concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    const wire = concatBytes([header, objectMsg]);

    const { object } = decodeSubgroupObject(wire, header.length, false, 0n, true);
    expect(decodeScreenObjectMessage(object.payload).chunk).toEqual(chunk);
  });
});
