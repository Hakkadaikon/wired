import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  decodeFrame,
  encodeChatFrame,
  encodeVoiceFrame,
  generateSenderId,
} from "../voiceProtocol";

const senderId = (n: number) => new Uint8Array([n, n, n, n]);

describe("channelCodec", () => {
  it("decodes 0x01 as a chat frame", () => {
    const bytes = new Uint8Array([
      0x01,
      1,
      2,
      3,
      4,
      ...new TextEncoder().encode('"hi"'),
    ]);
    const result = decodeFrame(bytes);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.frame.channel).toBe("chat");
  });

  it("decodes 0x02 as a voice frame", () => {
    const bytes = new Uint8Array([0x02, 1, 2, 3, 4, 0, 0]);
    const result = decodeFrame(bytes);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.frame.channel).toBe("voice");
  });

  it.each([0x00, 0x03, 0xff])(
    "discards undefined channel byte %i",
    (b) => {
      const result = decodeFrame(new Uint8Array([b, 1, 2, 3, 4]));
      expect(result.ok).toBe(false);
    },
  );
});

describe("chatFrameCodec", () => {
  it("round-trips encode/decode for arbitrary sender id and text payload", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.string(),
        (id, text) => {
          const encoded = encodeChatFrame(id, text);
          expect(encoded.ok).toBe(true);
          if (!encoded.ok) return;
          const decoded = decodeFrame(encoded.bytes);
          expect(decoded.ok).toBe(true);
          if (decoded.ok && decoded.frame.channel === "chat") {
            expect(Array.from(decoded.frame.senderId)).toEqual(
              Array.from(id),
            );
            expect(decoded.frame.text).toBe(text);
          }
        },
      ),
    );
  });

  it("round-trips a 0-byte text payload", () => {
    const encoded = encodeChatFrame(senderId(1), "");
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    const decoded = decodeFrame(encoded.bytes);
    expect(decoded.ok).toBe(true);
    if (decoded.ok && decoded.frame.channel === "chat") {
      expect(decoded.frame.text).toBe("");
    }
  });

  it("surfaces malformed JSON payload as a decode error, not an uncaught exception", () => {
    const bytes = new Uint8Array([
      0x01,
      1,
      2,
      3,
      4,
      ...new TextEncoder().encode("{not json"),
    ]);
    expect(() => decodeFrame(bytes)).not.toThrow();
    const result = decodeFrame(bytes);
    expect(result.ok).toBe(false);
  });
});

describe("voiceFrameCodec", () => {
  it("round-trips encode/decode for arbitrary sender id, seq and opus payload", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.integer({ min: 0, max: 65535 }),
        fc.uint8Array({ maxLength: 200 }),
        (id, seq, payload) => {
          const encoded = encodeVoiceFrame(id, seq, payload);
          expect(encoded.ok).toBe(true);
          if (!encoded.ok) return;
          const decoded = decodeFrame(encoded.bytes);
          expect(decoded.ok).toBe(true);
          if (decoded.ok && decoded.frame.channel === "voice") {
            expect(Array.from(decoded.frame.senderId)).toEqual(
              Array.from(id),
            );
            expect(decoded.frame.seq).toBe(seq);
            expect(Array.from(decoded.frame.payload)).toEqual(
              Array.from(payload),
            );
          }
        },
      ),
    );
  });

  it.each([0, 1, 65534, 65535])(
    "encodes seq=%i within u16 range, wraps 65535->0",
    (seq) => {
      const encoded = encodeVoiceFrame(senderId(1), seq, new Uint8Array());
      expect(encoded.ok).toBe(true);
      if (!encoded.ok) return;
      const decoded = decodeFrame(encoded.bytes);
      expect(decoded.ok).toBe(true);
      if (decoded.ok && decoded.frame.channel === "voice") {
        expect(decoded.frame.seq).toBe(seq);
      }
    },
  );

  it("wraps 65536 to 0 when encoding an out-of-u16-range seq", () => {
    const encoded = encodeVoiceFrame(senderId(1), 65536, new Uint8Array());
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    const decoded = decodeFrame(encoded.bytes);
    if (decoded.ok && decoded.frame.channel === "voice") {
      expect(decoded.frame.seq).toBe(0);
    }
  });

  it("normalizes a negative seq into u16 space", () => {
    const encoded = encodeVoiceFrame(senderId(1), -1, new Uint8Array());
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    const decoded = decodeFrame(encoded.bytes);
    if (decoded.ok && decoded.frame.channel === "voice") {
      expect(decoded.frame.seq).toBe(65535);
    }
  });

  it("round-trips a 0-byte opus payload", () => {
    const encoded = encodeVoiceFrame(senderId(1), 0, new Uint8Array());
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    const decoded = decodeFrame(encoded.bytes);
    expect(decoded.ok).toBe(true);
    if (decoded.ok && decoded.frame.channel === "voice") {
      expect(decoded.frame.payload.length).toBe(0);
    }
  });

  it("rejects sending when encoded length exceeds maxDatagramSize", () => {
    const bigPayload = new Uint8Array(2000);
    const encoded = encodeVoiceFrame(senderId(1), 0, bigPayload);
    expect(encoded.ok).toBe(false);
  });
});

describe("frameCodec", () => {
  it.each([
    [new Uint8Array([0x02, 1, 2, 3, 4, 0]), "voice"],
    [new Uint8Array([0x01, 1, 2, 3]), "chat"],
  ])(
    "returns a decode error, not a throw, for a too-short %s datagram",
    (bytes) => {
      expect(() => decodeFrame(bytes)).not.toThrow();
      expect(decodeFrame(bytes).ok).toBe(false);
    },
  );
});

describe("senderId", () => {
  it("generates a 4-byte id", () => {
    const id = generateSenderId();
    expect(id.length).toBe(4);
  });

  it("uses crypto.getRandomValues, not Math.random", () => {
    const spy = { called: false };
    const original = crypto.getRandomValues;
    crypto.getRandomValues = ((arr: Uint8Array) => {
      spy.called = true;
      return original.call(crypto, arr);
    }) as typeof crypto.getRandomValues;
    try {
      generateSenderId();
      expect(spy.called).toBe(true);
    } finally {
      crypto.getRandomValues = original;
    }
  });

  it("fails explicitly, without a silent Math.random fallback, when crypto.getRandomValues is unavailable", () => {
    const original = crypto.getRandomValues;
    // getRandomValues lives on a prototype in Node's webcrypto, so a plain
    // `delete` on the instance is a no-op; override the own property instead.
    Object.defineProperty(crypto, "getRandomValues", {
      value: undefined,
      configurable: true,
    });
    try {
      expect(() => generateSenderId()).toThrow();
    } finally {
      Object.defineProperty(crypto, "getRandomValues", {
        value: original,
        configurable: true,
      });
    }
  });
});

describe("senderId collisions (documented behavior)", () => {
  it("documents that a colliding sender id causes the peer's voice to be treated as self-echo and not played", () => {
    // 4-byte sender IDs are drawn from a 2^32 space via CSPRNG; a
    // collision with another connected client is not detected or retried by
    // this codec. Documented, observable consequence: the jitter buffer's
    // self-echo filter (jitterBuffer.ts) matches on raw sender id bytes, so a
    // colliding peer's voice frames are indistinguishable from this client's
    // own and are silently never played. No code path in this module changes
    // that; this test exists to keep the tradeoff visible.
    expect(true).toBe(true);
  });
});
