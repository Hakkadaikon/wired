// Voice Object wire framing on top of moqtWire.ts's generic MOQT codec.
//
// Unlike chat (moqtClient.ts's buildChatObjectMessage: one uni stream per
// message), the audio track keeps ONE long-lived uni stream open per
// publish and appends one Object per Opus frame to it (M5's
// MoqtVoiceClient): a single SUBGROUP_HEADER, then N Objects with
// accumulating Object ID deltas. This module only encodes/decodes the
// pieces of that shape; MoqtVoiceClient owns the stream lifecycle.
//
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
  let pos = headerLen;
  let prevObjectId = 0n;
  let isFirst = true;
  while (pos < wire.length) {
    let decoded;
    try {
      decoded = decodeSubgroupObject(wire, pos, hasProperties, prevObjectId, isFirst);
    } catch {
      break;
    }
    // decodeSubgroupObject slices its declared Payload Length past the end
    // of `wire` without throwing when the stream is still arriving (short
    // read, not a protocol violation) -- that yields a truncated payload
    // rather than a decode error, so it must be detected here explicitly.
    if (pos + decoded.len > wire.length) break;
    out.push(decodeVoiceObjectPayload(decoded.object.payload));
    prevObjectId = decoded.object.objectId;
    isFirst = false;
    pos += decoded.len;
  }
  return out;
}
