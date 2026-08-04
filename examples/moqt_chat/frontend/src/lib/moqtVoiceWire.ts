// Voice Object wire framing on top of moqtWire.ts's generic MOQT codec.
//
// Same "one message, one uni stream" shape as chat's buildChatObjectMessage
// (moqtVoiceClient.ts's own doc explains why: the hub relays each stream
// as its own one-shot forward regardless of how the publisher sent it, so
// a long-lived appended-to stream cannot survive that relay unit intact).
// Each Object's payload is `seq(u16 BE) + opus bytes` -- senderId is not
// carried (the MOQT Track Alias already identifies the publisher; see
// moqtClient.ts's ownTrackAlias/participantForTrackAlias).

import {
  concatBytes,
  decodeSubgroupObject,
  encodeVarint,
  MoqtDecodeError,
} from "./moqtWire";
import { SUBGROUP_HEADER_TYPE } from "./moqtClient";

const SEQ_LEN = 2;
const U16_SPACE = 0x10000;

export interface VoiceObjectPayload {
  seq: number;
  opus: Uint8Array;
}

export function encodeVoiceObjectPayload(input: VoiceObjectPayload): Uint8Array {
  const wrapped = ((input.seq % U16_SPACE) + U16_SPACE) % U16_SPACE;
  const out = new Uint8Array(SEQ_LEN + input.opus.length);
  out[0] = (wrapped >> 8) & 0xff;
  out[1] = wrapped & 0xff;
  out.set(input.opus, SEQ_LEN);
  return out;
}

export function decodeVoiceObjectPayload(bytes: Uint8Array): VoiceObjectPayload {
  if (bytes.length < SEQ_LEN) {
    throw new MoqtDecodeError("voice Object payload shorter than seq header");
  }
  return {
    seq: (bytes[0] << 8) | bytes[1],
    opus: bytes.slice(SEQ_LEN),
  };
}

/** Builds the SUBGROUP_HEADER a voice stream opens with (once), before any
 * Objects. Same Type as chat's (see moqtClient.ts's SUBGROUP_HEADER_TYPE
 * doc): decodeSubgroupHeader in moqtWire.ts decodes it back. */
export function buildVoiceSubgroupHeader(trackAlias: bigint, groupId: bigint): Uint8Array {
  return concatBytes([
    encodeVarint(SUBGROUP_HEADER_TYPE),
    encodeVarint(trackAlias),
    encodeVarint(groupId),
  ]);
}

/** Encodes one Object to append to an already-open voice stream.
 * objectIdDelta is 0 for the stream's first Object (FIRST_OBJECT mode makes
 * the delta the absolute id) and the accumulation delta for later ones,
 * matching decodeSubgroupObject's own contract. */
export function encodeVoiceObjectMessage(
  objectIdDelta: bigint,
  payload: VoiceObjectPayload,
): Uint8Array {
  const body = encodeVoiceObjectPayload(payload);
  return concatBytes([
    encodeVarint(objectIdDelta),
    encodeVarint(BigInt(body.length)),
    body,
  ]);
}

// Object ID accumulation state threaded across successive
// tryDecodeOneVoiceObject calls on the same stream -- mirrors
// quic_moqdata_objseq on the hub side (moqdata.h).
export interface VoiceObjectSeq {
  prevObjectId: bigint;
  isFirst: boolean;
}

export function voiceObjectSeqInit(): VoiceObjectSeq {
  return { prevObjectId: 0n, isFirst: true };
}

/** Decodes at most one Object starting at `pos`, advancing `seq` in place
 * on success. Returns null (seq unchanged) when `wire` does not yet hold a
 * complete Object at `pos` -- the stream is still arriving, not malformed;
 * decodeSubgroupObject slices its declared Payload Length past the end of
 * `wire` without throwing in that case (short read, not a
 * PROTOCOL_VIOLATION), so the truncation is detected here explicitly. */
export function tryDecodeOneVoiceObject(
  wire: Uint8Array,
  pos: number,
  hasProperties: boolean,
  seq: VoiceObjectSeq,
): { payload: VoiceObjectPayload | null; len: number } | null {
  let decoded;
  try {
    decoded = decodeSubgroupObject(wire, pos, hasProperties, seq.prevObjectId, seq.isFirst);
  } catch {
    return null;
  }
  if (pos + decoded.len > wire.length) return null;
  seq.prevObjectId = decoded.object.objectId;
  seq.isFirst = false;
  try {
    return { payload: decodeVoiceObjectPayload(decoded.object.payload), len: decoded.len };
  } catch {
    // A well-framed Object whose body cannot hold the seq header: skip it
    // (payload null) but keep the stream position advancing -- one bad
    // Object must not stall the parser or kill the read loop.
    return { payload: null, len: decoded.len };
  }
}

/** Decodes every complete Object following a voice stream's header bytes
 * (headerLen: how many bytes of `wire` the SUBGROUP_HEADER itself took).
 * Stops at the first Object that does not fully decode (stream still
 * arriving) without throwing -- returns whatever decoded so far, matching
 * moqtrun_decode_object_loop's own "stop at truncation" behavior on the hub
 * side (src/app/moqt/run/moqtrun.c). */
export function decodeVoiceObjectStream(
  wire: Uint8Array,
  headerLen: number,
  hasProperties: boolean,
): VoiceObjectPayload[] {
  const out: VoiceObjectPayload[] = [];
  const seq = voiceObjectSeqInit();
  let pos = headerLen;
  for (;;) {
    const decoded = tryDecodeOneVoiceObject(wire, pos, hasProperties, seq);
    if (!decoded) break;
    if (decoded.payload) out.push(decoded.payload);
    pos += decoded.len;
  }
  return out;
}

/** Incremental counterpart to decodeVoiceObjectStream, for a long-lived
 * stream where waiting for EOF (as the one-shot decoder does) would delay
 * every frame until the whole call ends: drains every complete Object
 * currently available in `buffered` (starting at `pos`, threaded across
 * calls same as `seq` -- see VoiceObjectSeq's own doc) and returns the
 * still-undecoded tail trimmed to offset 0, ready to have the next chunk
 * appended. */
export function drainVoiceObjectStream(
  buffered: Uint8Array,
  hasProperties: boolean,
  seq: VoiceObjectSeq,
  onPayload: (payload: VoiceObjectPayload) => void,
): Uint8Array {
  let pos = 0;
  for (;;) {
    const decoded = tryDecodeOneVoiceObject(buffered, pos, hasProperties, seq);
    if (!decoded) break;
    if (decoded.payload) onPayload(decoded.payload);
    pos += decoded.len;
  }
  return buffered.slice(pos);
}
