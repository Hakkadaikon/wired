import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  concatBytes,
  decodeKvp,
  decodeVarint,
  encodeKvp,
  encodeVarint,
  hexToBytes,
  bytesToUtf8,
  classifyStreamType,
  decodeControlFrame,
  decodeSubgroupHeader,
  decodeSubgroupObject,
  decodeSubgroupTypeFlags,
  decodeFullTrackName,
  decodeGoaway,
  decodeNamespace,
  decodePublish,
  decodePublishDone,
  decodeRequestError,
  decodeRequestOk,
  decodeSetup,
  decodeSubscribe,
  decodeSubscribeOk,
  encodeControlFrame,
  encodeGoaway,
  encodePublish,
  encodePublishDone,
  encodeRequestError,
  encodeRequestOk,
  encodeSetup,
  encodeSubscribe,
  encodeSubscribeOk,
  MoqtDecodeError,
  utf8ToBytes,
} from "../moqtWire";

const goldenPath = path.resolve(
  import.meta.dirname,
  "../../../../testvectors/moqt_golden.json",
);
const golden = JSON.parse(readFileSync(goldenPath, "utf8"));

interface VarintVector {
  name: string;
  op: "decode" | "encode" | "reject";
  hex?: string;
  value?: string;
  len?: number;
  pad_len?: number;
  error?: string;
}

describe("varint", () => {
  const vectors = golden.varint as VarintVector[];

  for (const v of vectors) {
    if (v.op === "decode") {
      it(`decode ${v.name}`, () => {
        const { value, len } = decodeVarint(hexToBytes(v.hex!));
        expect(value).toBe(BigInt(v.value!));
        expect(len).toBe(v.len);
      });
    } else if (v.op === "encode") {
      it(`encode ${v.name}`, () => {
        const out = encodeVarint(BigInt(v.value!), v.pad_len ?? 1);
        expect(bytesToHex(out)).toBe(v.hex);
      });
    } else if (v.op === "reject") {
      it(`reject ${v.name}`, () => {
        expect(() => decodeVarint(hexToBytes(v.hex!))).toThrow(MoqtDecodeError);
      });
    }
  }
});

interface KvpPairVector {
  delta: string;
  type: string;
  num?: string;
  raw_hex?: string;
}

interface KvpVector {
  name: string;
  op: "decode" | "encode" | "reject" | "decode_varint";
  start_type: string;
  hex: string;
  pairs?: KvpPairVector[];
  error?: string;
  value?: string;
  len?: number;
}

describe("kvp", () => {
  const vectors = golden.kvp as KvpVector[];

  for (const v of vectors) {
    if (v.op === "decode") {
      it(`decode ${v.name}`, () => {
        const bytes = hexToBytes(v.hex);
        let offset = 0;
        let prevType = BigInt(v.start_type);
        for (const expected of v.pairs!) {
          const { pair, len } = decodeKvp(bytes, offset, prevType);
          expect(pair.type).toBe(prevType + BigInt(expected.delta));
          if (expected.num !== undefined) {
            expect(pair.num).toBe(BigInt(expected.num));
          } else {
            expect(bytesToHex(pair.raw!)).toBe(expected.raw_hex);
          }
          offset += len;
          prevType = pair.type;
        }
      });
    } else if (v.op === "encode") {
      it(`encode ${v.name}`, () => {
        const chunks: Uint8Array[] = [];
        let prevType = BigInt(v.start_type);
        for (const p of v.pairs!) {
          const type = prevType + BigInt(p.delta);
          const pair =
            p.num !== undefined
              ? { type, num: BigInt(p.num) }
              : { type, raw: hexToBytes(p.raw_hex!) };
          chunks.push(encodeKvp(pair, prevType));
          prevType = type;
        }
        expect(bytesToHex(concatBytes(chunks))).toBe(v.hex);
      });
    } else if (v.op === "reject") {
      it(`reject ${v.name}`, () => {
        expect(() =>
          decodeKvp(hexToBytes(v.hex), 0, BigInt(v.start_type)),
        ).toThrow(MoqtDecodeError);
      });
    } else if (v.op === "decode_varint") {
      it(`decode_varint ${v.name}`, () => {
        const { value, len } = decodeVarint(hexToBytes(v.hex));
        expect(value).toBe(BigInt(v.value!));
        expect(len).toBe(v.len);
      });
    }
  }
});

interface CtlVector {
  name: string;
  type: string;
  msg_len: number;
  hex: string;
  fields: Record<string, unknown>;
}

describe("ctl", () => {
  const vectors = golden.ctl as CtlVector[];
  const byName = new Map(vectors.map((v) => [v.name, v]));

  function checkFraming(v: CtlVector) {
    const { frame, len } = decodeControlFrame(hexToBytes(v.hex));
    expect(frame.type).toBe(BigInt(v.type));
    expect(frame.body.length).toBe(v.msg_len);
    expect(len).toBe(hexToBytes(v.hex).length);
    return frame.body;
  }

  it("decode setup_impl", () => {
    const v = byName.get("setup_impl")!;
    const body = checkFraming(v);
    const msg = decodeSetup(body);
    expect(msg.setupOptions).toEqual([
      { type: 7n, raw: utf8ToBytes("wired/0") },
    ]);
  });

  it("encode setup_impl", () => {
    const v = byName.get("setup_impl")!;
    const body = encodeSetup({ setupOptions: [{ type: 7n, raw: utf8ToBytes("wired/0") }] });
    const out = encodeControlFrame(BigInt(v.type), body);
    expect(bytesToHex(out)).toBe(v.hex);
  });

  it("decode subscribe_basic", () => {
    const v = byName.get("subscribe_basic")!;
    const body = checkFraming(v);
    const msg = decodeSubscribe(body);
    expect(msg.requestId).toBe(0n);
    expect(msg.trackNamespace.map(bytesToUtf8)).toEqual(["chat", "room1"]);
    expect(bytesToUtf8(msg.trackName)).toBe("alice");
    expect(msg.parameters).toEqual([]);
  });

  it("encode subscribe_basic", () => {
    const v = byName.get("subscribe_basic")!;
    const body = encodeSubscribe({
      requestId: 0n,
      trackNamespace: ["chat", "room1"].map(utf8ToBytes),
      trackName: utf8ToBytes("alice"),
      parameters: [],
    });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode subscribe_ok_basic", () => {
    const v = byName.get("subscribe_ok_basic")!;
    const body = checkFraming(v);
    const msg = decodeSubscribeOk(body);
    expect(msg.trackAlias).toBe(1n);
    expect(msg.parameters).toEqual([]);
    expect(msg.trackProperties).toEqual([]);
  });

  it("encode subscribe_ok_basic", () => {
    const v = byName.get("subscribe_ok_basic")!;
    const body = encodeSubscribeOk({ trackAlias: 1n, parameters: [], trackProperties: [] });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode publish_basic", () => {
    const v = byName.get("publish_basic")!;
    const body = checkFraming(v);
    const msg = decodePublish(body);
    expect(msg.requestId).toBe(0n);
    expect(msg.trackNamespace.map(bytesToUtf8)).toEqual(["chat", "room1"]);
    expect(bytesToUtf8(msg.trackName)).toBe("alice");
    expect(msg.trackAlias).toBe(1n);
    expect(msg.parameters).toEqual([]);
    expect(msg.trackProperties).toEqual([]);
  });

  it("encode publish_basic", () => {
    const v = byName.get("publish_basic")!;
    const body = encodePublish({
      requestId: 0n,
      trackNamespace: ["chat", "room1"].map(utf8ToBytes),
      trackName: utf8ToBytes("alice"),
      trackAlias: 1n,
      parameters: [],
      trackProperties: [],
    });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode request_ok_basic", () => {
    const v = byName.get("request_ok_basic")!;
    const body = checkFraming(v);
    const msg = decodeRequestOk(body);
    expect(msg.parameters).toEqual([]);
    expect(msg.trackProperties).toEqual([]);
  });

  it("encode request_ok_basic", () => {
    const v = byName.get("request_ok_basic")!;
    const body = encodeRequestOk({ parameters: [], trackProperties: [] });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode request_error_not_supported", () => {
    const v = byName.get("request_error_not_supported")!;
    const body = checkFraming(v);
    const msg = decodeRequestError(body);
    expect(msg.errorCode).toBe(3n);
    expect(msg.retryInterval).toBe(0n);
    expect(bytesToUtf8(msg.errorReason)).toBe("not supported");
  });

  it("encode request_error_not_supported", () => {
    const v = byName.get("request_error_not_supported")!;
    const body = encodeRequestError({
      errorCode: 3n,
      retryInterval: 0n,
      errorReason: utf8ToBytes("not supported"),
    });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode publish_done_track_ended", () => {
    const v = byName.get("publish_done_track_ended")!;
    const body = checkFraming(v);
    const msg = decodePublishDone(body);
    expect(msg.statusCode).toBe(2n);
    expect(msg.streamCount).toBe(2n);
    expect(bytesToUtf8(msg.errorReason)).toBe("");
  });

  it("encode publish_done_track_ended", () => {
    const v = byName.get("publish_done_track_ended")!;
    const body = encodePublishDone({
      statusCode: 2n,
      streamCount: 2n,
      errorReason: utf8ToBytes(""),
    });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });

  it("decode goaway_empty", () => {
    const v = byName.get("goaway_empty")!;
    const body = checkFraming(v);
    const msg = decodeGoaway(body);
    expect(bytesToUtf8(msg.newSessionUri)).toBe("");
    expect(msg.timeout).toBe(0n);
  });

  it("encode goaway_empty", () => {
    const v = byName.get("goaway_empty")!;
    const body = encodeGoaway({ newSessionUri: utf8ToBytes(""), timeout: 0n });
    expect(bytesToHex(encodeControlFrame(BigInt(v.type), body))).toBe(v.hex);
  });
});

interface DataVector {
  kind: "subgroup_stream" | "subgroup_type" | "stream_type";
  name: string;
  hex?: string;
  fin?: boolean;
  header?: {
    type: string;
    track_alias: string;
    group_id: string;
    subgroup_id: string;
    subgroup_id_mode: number;
    first_object: boolean;
    end_of_group: boolean;
    default_priority: boolean;
    publisher_priority?: string;
    properties: boolean;
  };
  objects?: Array<{
    object_id_delta: string;
    object_id: string;
    payload_hex: string;
    payload_utf8?: string;
    object_status?: string;
  }>;
  type?: string;
  op?: "accept" | "reject";
  fields?: {
    properties: boolean;
    subgroup_id_mode: number;
    end_of_group: boolean;
    default_priority: boolean;
    first_object: boolean;
  };
  error?: string;
  value?: string;
  classify?: StreamClassName;
}

type StreamClassName = "control" | "fetch" | "subgroup" | "padding" | "unknown";

describe("data", () => {
  const vectors = golden.data as DataVector[];

  for (const v of vectors) {
    if (v.kind === "subgroup_stream") {
      it(`decode ${v.name}`, () => {
        const bytes = hexToBytes(v.hex!);
        const { header, len: headerLen } = decodeSubgroupHeader(bytes);
        expect(header.trackAlias).toBe(BigInt(v.header!.track_alias));
        expect(header.groupId).toBe(BigInt(v.header!.group_id));
        expect(header.subgroupId).toBe(BigInt(v.header!.subgroup_id));
        expect(header.flags.subgroupIdMode).toBe(v.header!.subgroup_id_mode);
        expect(header.flags.firstObject).toBe(v.header!.first_object);
        expect(header.flags.endOfGroup).toBe(v.header!.end_of_group);
        expect(header.flags.defaultPriority).toBe(v.header!.default_priority);
        expect(header.flags.properties).toBe(v.header!.properties);
        if (v.header!.publisher_priority !== undefined) {
          expect(header.publisherPriority).toBe(Number(v.header!.publisher_priority));
        }

        let pos = headerLen;
        let prevObjectId = 0n;
        v.objects!.forEach((expected, i) => {
          const { object, len } = decodeSubgroupObject(
            bytes,
            pos,
            header.flags.properties,
            prevObjectId,
            i === 0,
          );
          expect(object.objectId).toBe(BigInt(expected.object_id));
          expect(bytesToHex(object.payload)).toBe(expected.payload_hex);
          if (expected.object_status !== undefined) {
            expect(object.objectStatus).toBe(BigInt(expected.object_status));
          }
          prevObjectId = object.objectId;
          pos += len;
        });
        expect(pos).toBe(bytes.length);
      });
    } else if (v.kind === "subgroup_type" && v.op === "accept") {
      it(`accept ${v.name}`, () => {
        const flags = decodeSubgroupTypeFlags(BigInt(v.type!));
        expect(flags).toEqual({
          properties: v.fields!.properties,
          subgroupIdMode: v.fields!.subgroup_id_mode,
          endOfGroup: v.fields!.end_of_group,
          defaultPriority: v.fields!.default_priority,
          firstObject: v.fields!.first_object,
        });
      });
    } else if (v.kind === "subgroup_type" && v.op === "reject") {
      it(`reject ${v.name}`, () => {
        expect(() => decodeSubgroupTypeFlags(BigInt(v.type!))).toThrow(MoqtDecodeError);
      });
    } else if (v.kind === "stream_type") {
      it(`classify ${v.name}`, () => {
        expect(classifyStreamType(BigInt(v.value!))).toBe(v.classify);
      });
    }
  }
});

interface NameVector {
  name: string;
  kind: "namespace" | "full_track_name";
  op: "decode" | "reject";
  hex: string;
  namespace_fields?: string[];
  track_name?: string;
  error?: string;
}

describe("name", () => {
  const vectors = golden.name as NameVector[];

  for (const v of vectors) {
    if (v.op === "decode" && v.kind === "namespace") {
      it(`decode ${v.name}`, () => {
        const { fields } = decodeNamespace(hexToBytes(v.hex));
        expect(fields.map(bytesToUtf8)).toEqual(v.namespace_fields);
      });
    } else if (v.op === "decode" && v.kind === "full_track_name") {
      it(`decode ${v.name}`, () => {
        const { namespace, trackName } = decodeFullTrackName(hexToBytes(v.hex));
        expect(namespace.map(bytesToUtf8)).toEqual(v.namespace_fields);
        expect(bytesToUtf8(trackName)).toBe(v.track_name);
      });
    } else if (v.op === "reject" && v.kind === "namespace") {
      it(`reject ${v.name}`, () => {
        expect(() => decodeNamespace(hexToBytes(v.hex))).toThrow(MoqtDecodeError);
      });
    } else if (v.op === "reject" && v.kind === "full_track_name") {
      it(`reject ${v.name}`, () => {
        expect(() => decodeFullTrackName(hexToBytes(v.hex))).toThrow(
          MoqtDecodeError,
        );
      });
    }
  }
});
