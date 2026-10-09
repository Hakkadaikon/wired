// MOQT wire codec: draft-ietf-moq-transport-22, plus the draft-19 forms the
// legacy (no WebTransport subprotocol) session still speaks. Only a few
// wire forms differ between the two -- LOCATION_FILTER's encoding,
// FILL_PARAMETERS and the End of Timed-Out Range marker -- so those
// functions take a `draft` argument (default 19, the legacy form); every
// other message is byte-identical in both drafts.
//
// BigInt is used throughout for wire integers: MOQT varints and several
// message fields (e.g. Stream Count) can exceed Number.MAX_SAFE_INTEGER
// (2^53-1), so `number` would silently lose precision.

export class MoqtDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MoqtDecodeError";
  }
}

function fail(message: string): never {
  throw new MoqtDecodeError(message);
}

/** The draft a session speaks: 22 when the WebTransport subprotocol
 * "moqt-22" was negotiated, else the draft-19 legacy session. */
export type MoqtDraft = 19 | 22;

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 8.1 (draft-19 1.4.1): Variable-Length Integers
// ---------------------------------------------------------------------

const VARINT_LEN_BY_PREFIX = ((): Uint8Array => {
  // Number of leading 1 bits in the first byte, plus 1, gives the total
  // encoded length in bytes (1..9). Table indexed by the first byte's
  // top bits: count leading ones directly per byte value.
  const table = new Uint8Array(256);
  for (let b = 0; b < 256; b++) {
    let ones = 0;
    while (ones < 8 && (b & (0x80 >> ones)) !== 0) ones++;
    table[b] = ones + 1;
  }
  return table;
})();

export interface DecodedVarint {
  value: bigint;
  len: number;
}

/** Decode a single MOQT varint starting at `offset`. Non-minimal encodings are accepted. */
export function decodeVarint(bytes: Uint8Array, offset = 0): DecodedVarint {
  if (offset >= bytes.length) fail("truncated varint: no data");
  const len = VARINT_LEN_BY_PREFIX[bytes[offset]];
  if (offset + len > bytes.length) fail("truncated varint: insufficient bytes");

  const usableBits = 8 - len; // for len==9, this is -1 and unused below
  let value =
    len === 9 ? 0n : BigInt(bytes[offset] & ((1 << usableBits) - 1));
  for (let i = 1; i < len; i++) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return { value, len };
}

const VARINT_MAX_BY_LEN: readonly bigint[] = [
  0n,
  127n,
  16383n,
  2097151n,
  268435455n,
  34359738367n,
  4398046511103n,
  562949953421311n,
  72057594037927935n,
  18446744073709551615n,
];

/** Encode `value` as a MOQT varint. `minLen` pads to at least that many bytes (non-minimal encoding). */
export function encodeVarint(value: bigint, minLen = 1): Uint8Array {
  if (value < 0n || value > 18446744073709551615n) {
    fail(`varint value out of range: ${value}`);
  }
  let len = 1;
  while (len < 9 && value > VARINT_MAX_BY_LEN[len]) len++;
  if (minLen > len) len = minLen;

  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 1; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (len === 9) {
    out[0] = 0xff;
  } else {
    const prefixOnes = len - 1;
    const prefixMask = ((1 << prefixOnes) - 1) << (8 - prefixOnes);
    out[0] = prefixMask | Number(value & 0xffn);
  }
  return out;
}

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 8.3 (draft-19 1.4.3): Key-Value-Pair Structure
// ---------------------------------------------------------------------

const KVP_VALUE_MAX_LEN = 65535n;
const U64_MAX = 18446744073709551615n;

export interface KeyValuePair {
  type: bigint;
  /** Present when type is even (numeric value). */
  num?: bigint;
  /** Present when type is odd (raw bytes value). */
  raw?: Uint8Array;
}

export interface DecodedKvp {
  pair: KeyValuePair;
  len: number;
}

/** Decode one Key-Value-Pair starting at `offset`. `prevType` is the running Type accumulator (0 initially). */
export function decodeKvp(
  bytes: Uint8Array,
  offset: number,
  prevType: bigint,
): DecodedKvp {
  const delta = decodeVarint(bytes, offset);
  if (delta.value > U64_MAX - prevType) fail("PROTOCOL_VIOLATION: kvp type delta overflow");
  const type = prevType + delta.value;
  let pos = offset + delta.len;

  if (type % 2n === 0n) {
    const num = decodeVarint(bytes, pos);
    pos += num.len;
    return { pair: { type, num: num.value }, len: pos - offset };
  }

  const length = decodeVarint(bytes, pos);
  if (length.value > KVP_VALUE_MAX_LEN) fail("PROTOCOL_VIOLATION: kvp length exceeds 65535");
  pos += length.len;
  const end = pos + Number(length.value);
  if (end > bytes.length) fail("PROTOCOL_VIOLATION: kvp value truncated");
  const raw = bytes.slice(pos, end);
  return { pair: { type, raw }, len: end - offset };
}

/** Encode one Key-Value-Pair. `prevType` is the running Type accumulator (0 initially). */
export function encodeKvp(pair: KeyValuePair, prevType: bigint): Uint8Array {
  const delta = pair.type - prevType;
  const parts: Uint8Array[] = [encodeVarint(delta)];
  if (pair.type % 2n === 0n) {
    parts.push(encodeVarint(pair.num ?? 0n));
  } else {
    const raw = pair.raw ?? new Uint8Array(0);
    parts.push(encodeVarint(BigInt(raw.length)));
    parts.push(raw);
  }
  return concatBytes(parts);
}

// ---------------------------------------------------------------------
// shared byte helpers
// ---------------------------------------------------------------------

export function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/** Reads `reader` to EOF and returns everything, with `firstChunk` (bytes
 * a caller already pulled off the same stream) in front. */
export async function readToEof(
  firstChunk: Uint8Array,
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [firstChunk];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  return concatBytes(chunks);
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 8.7-8.8 (draft-19 1.5): Track Namespace /
// Full Track Name
// ---------------------------------------------------------------------

const NAMESPACE_MAX_FIELDS = 32;
const FULL_TRACK_NAME_MAX_LEN = 4096;

export interface DecodedNamespace {
  fields: Uint8Array[];
  len: number;
}

function decodeLenPrefixedBytes(
  bytes: Uint8Array,
  offset: number,
  errorLabel: string,
): { value: Uint8Array; len: number } {
  const length = decodeVarint(bytes, offset);
  const start = offset + length.len;
  const end = start + Number(length.value);
  if (end > bytes.length) fail(`PROTOCOL_VIOLATION: ${errorLabel} truncated`);
  return { value: bytes.slice(start, end), len: end - offset };
}

/** Decode a Track Namespace (field count + length-prefixed fields). */
export function decodeNamespace(bytes: Uint8Array, offset = 0): DecodedNamespace {
  const count = decodeVarint(bytes, offset);
  if (count.value > BigInt(NAMESPACE_MAX_FIELDS)) {
    fail("PROTOCOL_VIOLATION: namespace field count exceeds 32");
  }
  let pos = offset + count.len;
  const fields: Uint8Array[] = [];
  let totalLen = 0;
  for (let i = 0n; i < count.value; i++) {
    const field = decodeLenPrefixedBytes(bytes, pos, "namespace field");
    if (field.value.length === 0) {
      fail("PROTOCOL_VIOLATION: namespace field length is 0");
    }
    fields.push(field.value);
    totalLen += field.value.length;
    pos += field.len;
  }
  if (totalLen > FULL_TRACK_NAME_MAX_LEN) {
    fail("PROTOCOL_VIOLATION: namespace exceeds 4096 bytes");
  }
  return { fields, len: pos - offset };
}

export function encodeNamespace(fields: Uint8Array[]): Uint8Array {
  const parts = [encodeVarint(BigInt(fields.length))];
  for (const f of fields) {
    parts.push(encodeVarint(BigInt(f.length)), f);
  }
  return concatBytes(parts);
}

export interface DecodedFullTrackName {
  namespace: Uint8Array[];
  trackName: Uint8Array;
  len: number;
}

/** Decode a Full Track Name: Track Namespace followed by a length-prefixed Track Name. */
export function decodeFullTrackName(
  bytes: Uint8Array,
  offset = 0,
): DecodedFullTrackName {
  const ns = decodeNamespace(bytes, offset);
  const nsLen = ns.fields.reduce((sum, f) => sum + f.length, 0);
  const name = decodeLenPrefixedBytes(bytes, offset + ns.len, "track name");
  if (nsLen + name.value.length > FULL_TRACK_NAME_MAX_LEN) {
    fail("PROTOCOL_VIOLATION: full track name exceeds 4096 bytes");
  }
  return {
    namespace: ns.fields,
    trackName: name.value,
    len: ns.len + name.len,
  };
}

export function encodeFullTrackName(
  namespace: Uint8Array[],
  trackName: Uint8Array,
): Uint8Array {
  return concatBytes([
    encodeNamespace(namespace),
    encodeVarint(BigInt(trackName.length)),
    trackName,
  ]);
}

export function utf8ToBytes(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 9 (draft-19 10): Control Messages
// ---------------------------------------------------------------------


/** Decode Key-Value-Pairs spanning the bytes up to `end` (exclusive). */
function decodeKvpSpan(
  bytes: Uint8Array,
  offset: number,
  end: number,
): KeyValuePair[] {
  let pos = offset;
  let prevType = 0n;
  const pairs: KeyValuePair[] = [];
  while (pos < end) {
    const { pair, len } = decodeKvp(bytes, pos, prevType);
    pairs.push(pair);
    pos += len;
    prevType = pair.type;
  }
  return pairs;
}

function encodeKvpList(pairs: KeyValuePair[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let prevType = 0n;
  for (const pair of pairs) {
    parts.push(encodeKvp(pair, prevType));
    prevType = pair.type;
  }
  return concatBytes(parts);
}

// --- Message Parameters (d22 9.20, d19 10.2) --------------------------------
//
// Not Key-Value-Pairs: each Type fixes its value encoding (9.20.x), Types
// ascend (Type Delta), and an unknown Type is a PROTOCOL_VIOLATION. The
// tables differ by draft: d22 adds FILL_PARAMETERS (0x23, Length-prefixed)
// and INCLUDE_PROPERTIES (0x35, uint8), and its LOCATION_FILTER (0x21)
// carries no Length (see encodeLocationFilter22).

export interface Location {
  group: bigint;
  object: bigint;
}

export interface MessageParam {
  type: bigint;
  /** uint8 / varint -> bigint; LARGEST_OBJECT -> Location; Length-prefixed
   * (and TRACK_NAMESPACE_PREFIX's raw namespace) -> bytes. LOCATION_FILTER
   * is bytes in both drafts: the filter (Type + fields) without any Length
   * -- d19 adds the Length on the wire, d22 does not. */
  value: bigint | Location | Uint8Array;
}

export const PARAM_LARGEST_OBJECT = 0x09n;
export const PARAM_LOCATION_FILTER = 0x21n;
export const PARAM_FILL_PARAMETERS = 0x23n;
const PARAM_TRACK_NAMESPACE_PREFIX = 0x34n;
const PARAM_UINT8: Record<MoqtDraft, Set<bigint>> = {
  19: new Set([0x10n, 0x20n, 0x22n]),
  22: new Set([0x10n, 0x20n, 0x22n, 0x35n]),
};
const PARAM_VARINT = new Set([0x02n, 0x04n, 0x06n, 0x08n, 0x0an, 0x32n]);
const PARAM_BYTES: Record<MoqtDraft, Set<bigint>> = {
  19: new Set([0x03n, 0x21n, 0x25n, 0x26n, 0x27n, 0x28n, 0x29n]),
  // 0x24 SWITCH_FROM / 0x41 SWITCHING_SET_ASSIGNMENT: the experimental
  // track switching extension, draft-22 sessions only (see below). Accepted
  // inbound whatever was negotiated (this client never receives them from
  // the hub); sending is gated on MoqtChatClient.trackSwitching instead.
  22: new Set([0x03n, 0x23n, 0x24n, 0x25n, 0x26n, 0x27n, 0x28n, 0x29n, 0x41n]),
};

/** A draft-22 Location Filter (9.20.9): Type 0x00 None, 0x01 Relative
 * Start {StartGroup}, 0x02 Absolute Start {StartGroup, StartObject}, 0x03
 * Absolute Start + Group End {.., EndGroupDelta}, 0x04 Absolute Range
 * {.., EndGroupDelta, EndObject}, 0x05 Next Object. */
export interface LocationFilter22 {
  type: bigint;
  fields: bigint[];
}

// Number of vi64 fields each Location Filter Type carries (9.20.9).
const LOCATION_FILTER_FIELDS = [0, 1, 2, 3, 4, 0];

function locationFilterFieldCount(type: bigint): number {
  if (type >= BigInt(LOCATION_FILTER_FIELDS.length)) {
    fail(`PROTOCOL_VIOLATION: unknown Location Filter Type 0x${type.toString(16)}`);
  }
  return LOCATION_FILTER_FIELDS[Number(type)];
}

/** The draft-22 LOCATION_FILTER value: Type, then its fields; no Length. */
export function encodeLocationFilter22(f: LocationFilter22): Uint8Array {
  if (f.fields.length !== locationFilterFieldCount(f.type)) {
    fail(`Location Filter Type 0x${f.type.toString(16)} takes ${locationFilterFieldCount(f.type)} fields`);
  }
  return concatBytes([f.type, ...f.fields].map((v) => encodeVarint(v)));
}

/** Decodes a draft-22 LOCATION_FILTER value at offset; its Type alone says
 * where it ends. */
export function decodeLocationFilter22(
  bytes: Uint8Array,
  offset: number,
): { filter: LocationFilter22; len: number } {
  const type = decodeVarint(bytes, offset);
  let pos = offset + type.len;
  const fields: bigint[] = [];
  for (let i = locationFilterFieldCount(type.value); i > 0; i--) {
    const v = decodeVarint(bytes, pos);
    fields.push(v.value);
    pos += v.len;
  }
  return { filter: { type: type.value, fields }, len: pos - offset };
}

/** The FILL_PARAMETERS value (d22 9.20.15): the fill fetch stream's own
 * parameter list (Number of Parameters + Type-delta Parameters, a scope of
 * its own). encodeParams adds the outer Length when it is sent as 0x23. */
export function encodeFillParameters(params: MessageParam[]): Uint8Array {
  return encodeParams(params, 22);
}

function decodeLocation(bytes: Uint8Array, offset: number): { value: Location; len: number } {
  const group = decodeVarint(bytes, offset);
  const object = decodeVarint(bytes, offset + group.len);
  return { value: { group: group.value, object: object.value }, len: group.len + object.len };
}

function decodeParamValue(
  type: bigint,
  bytes: Uint8Array,
  pos: number,
  draft: MoqtDraft,
): { value: MessageParam["value"]; len: number } {
  if (PARAM_UINT8[draft].has(type)) {
    if (pos >= bytes.length) fail("truncated uint8 parameter");
    return { value: BigInt(bytes[pos]), len: 1 };
  }
  if (PARAM_VARINT.has(type)) return decodeVarint(bytes, pos);
  if (type === PARAM_LARGEST_OBJECT) return decodeLocation(bytes, pos);
  if (PARAM_BYTES[draft].has(type)) {
    const v = decodeLenPrefixedBytes(bytes, pos, "parameter");
    PARAM_VALUE_CHECK.get(type)?.(v.value);
    return v;
  }
  if (type === PARAM_LOCATION_FILTER) {
    const { len } = decodeLocationFilter22(bytes, pos);
    return { value: bytes.slice(pos, pos + len), len };
  }
  if (type === PARAM_TRACK_NAMESPACE_PREFIX) {
    const { len } = decodeNamespace(bytes, pos);
    return { value: bytes.slice(pos, pos + len), len };
  }
  fail(`PROTOCOL_VIOLATION: unknown parameter type 0x${type.toString(16)}`);
}

function encodeParamValue(p: MessageParam, draft: MoqtDraft): Uint8Array {
  if (PARAM_UINT8[draft].has(p.type)) return Uint8Array.of(Number(p.value));
  if (p.value instanceof Uint8Array) {
    if (p.type === PARAM_TRACK_NAMESPACE_PREFIX) return p.value;
    if (draft === 22 && p.type === PARAM_LOCATION_FILTER) return p.value;
    return concatBytes([encodeVarint(BigInt(p.value.length)), p.value]);
  }
  if (typeof p.value === "bigint") return encodeVarint(p.value);
  return concatBytes([encodeVarint(p.value.group), encodeVarint(p.value.object)]);
}

/** Decode `Number of Parameters` and the parameters that follow it. */
export function decodeParams(
  bytes: Uint8Array,
  offset: number,
  draft: MoqtDraft = 19,
): { params: MessageParam[]; len: number } {
  const count = decodeVarint(bytes, offset);
  let pos = offset + count.len;
  let type = 0n;
  const params: MessageParam[] = [];
  for (let i = 0n; i < count.value; i++) {
    const delta = decodeVarint(bytes, pos);
    type += delta.value;
    if (type > U64_MAX) fail("PROTOCOL_VIOLATION: parameter type overflow");
    const value = decodeParamValue(type, bytes, pos + delta.len, draft);
    params.push({ type, value: value.value });
    pos += delta.len + value.len;
  }
  return { params, len: pos - offset };
}

/** Encode `Number of Parameters` plus the parameters (ascending Type). */
export function encodeParams(params: MessageParam[], draft: MoqtDraft = 19): Uint8Array {
  const parts = [encodeVarint(BigInt(params.length))];
  let prev = 0n;
  for (const p of params) {
    parts.push(encodeVarint(p.type - prev), encodeParamValue(p, draft));
    prev = p.type;
  }
  return concatBytes(parts);
}

// --- Track switching extension (draft-22 sessions only) -----------------------
//
// Experimental values shared with moqtail (tasks/moqt-trackswitch-plan.md 1);
// draft-22 leaves 0x24, 0x41 (parameters) and 0x09 (Setup Option)
// unassigned. A draft-19 session never carries them: there they stay unknown
// parameters, i.e. a PROTOCOL_VIOLATION.

/** SWITCH_FROM (SUBSCRIBE / REQUEST_UPDATE): activate this subscription and
 * stop Request ID's. Value: Length + {RequestID vi, Mode vi, Flags u8}. */
export const PARAM_SWITCH_FROM = 0x24n;
/** SWITCHING_SET_ASSIGNMENT (SUBSCRIBE / REQUEST_UPDATE): put this
 * subscription in a sender-side switching set. Value: Length + {SetID,
 * AlgorithmID, ThresholdKbps, Weight 1..10, Activate (all vi), [Rank u8]}. */
export const PARAM_SWITCHING_SET_ASSIGNMENT = 0x41n;
/** SSTS_ALGORITHMS Setup Option (odd: Length + bytes): concatenated varint
 * algorithm ids, no count. Negotiated = the intersection of both SETUPs. */
export const SETUP_OPTION_SSTS_ALGORITHMS = 0x09n;
export const SSTS_ALGORITHM_DEFAULT = 0n;
export const SSTS_ALGORITHM_BACKPRESSURE = 0xff01n;
/** Hard: reset the old subscription's streams when the new one's boundary
 * Group opens. Soft: let the old one finish the Groups before it. */
export const SWITCH_MODE_HARD = 0n;
export const SWITCH_MODE_SOFT = 1n;
const SWITCH_FLAG_PUBLISH_DONE = 0x80;
const SSA_WEIGHT_MIN = 1n;
const SSA_WEIGHT_MAX = 10n;

export interface SwitchFrom {
  requestId: bigint;
  mode: bigint;
  /** Flags bit 0x80: end the old subscription with PUBLISH_DONE. */
  publishDone: boolean;
}

export interface SwitchingSetAssignment {
  setId: bigint;
  algorithmId: bigint;
  thresholdKbps: bigint;
  weight: bigint;
  activate: bigint;
  rank?: number;
}

/** Reads consecutive varints off `bytes` from `pos`, returning the values
 * and the position after the last one. */
function takeVarints(bytes: Uint8Array, pos: number, n: number): { values: bigint[]; pos: number } {
  const values: bigint[] = [];
  for (let i = 0; i < n; i++) {
    const v = decodeVarint(bytes, pos);
    values.push(v.value);
    pos += v.len;
  }
  return { values, pos };
}

// `what` prefixes the error: "PROTOCOL_VIOLATION" when decoding received
// bytes, "invalid" when refusing to encode a caller's value.
type CheckKind = "PROTOCOL_VIOLATION" | "invalid";

function checkSwitchMode(mode: bigint, what: CheckKind): void {
  if (mode !== SWITCH_MODE_HARD && mode !== SWITCH_MODE_SOFT) {
    fail(`${what}: SWITCH_FROM Mode ${mode}`);
  }
}

/** The SWITCH_FROM value (without its Length; encodeParams adds it). */
export function encodeSwitchFrom(s: SwitchFrom): Uint8Array {
  checkSwitchMode(s.mode, "invalid");
  return concatBytes([
    encodeVarint(s.requestId),
    encodeVarint(s.mode),
    Uint8Array.of(s.publishDone ? SWITCH_FLAG_PUBLISH_DONE : 0),
  ]);
}

/** Decodes a whole SWITCH_FROM value: an unknown Mode, a Flags bit other
 * than 0x80, or a byte after Flags is a PROTOCOL_VIOLATION. */
export function decodeSwitchFrom(bytes: Uint8Array): SwitchFrom {
  const { values, pos } = takeVarints(bytes, 0, 2);
  const [requestId, mode] = values;
  checkSwitchMode(mode, "PROTOCOL_VIOLATION");
  if (pos >= bytes.length) fail("truncated SWITCH_FROM: no Flags");
  const flags = bytes[pos];
  if ((flags & ~SWITCH_FLAG_PUBLISH_DONE) !== 0) fail(`PROTOCOL_VIOLATION: SWITCH_FROM Flags 0x${flags.toString(16)}`);
  if (pos + 1 !== bytes.length) fail("PROTOCOL_VIOLATION: bytes after SWITCH_FROM Flags");
  return { requestId, mode, publishDone: flags !== 0 };
}

function checkSsaWeight(weight: bigint, what: CheckKind): void {
  if (weight < SSA_WEIGHT_MIN || weight > SSA_WEIGHT_MAX) {
    fail(`${what}: SWITCHING_SET_ASSIGNMENT Weight ${weight} outside 1..10`);
  }
}

/** The SWITCHING_SET_ASSIGNMENT value (without its Length). */
export function encodeSwitchingSetAssignment(a: SwitchingSetAssignment): Uint8Array {
  checkSsaWeight(a.weight, "invalid");
  if (a.rank !== undefined && !(Number.isInteger(a.rank) && a.rank >= 0 && a.rank <= 255)) {
    fail(`invalid: SWITCHING_SET_ASSIGNMENT Rank ${a.rank} is not a u8`);
  }
  const fields = [a.setId, a.algorithmId, a.thresholdKbps, a.weight, a.activate].map((v) => encodeVarint(v));
  if (a.rank !== undefined) fields.push(Uint8Array.of(a.rank));
  return concatBytes(fields);
}

/** Decodes a whole SWITCHING_SET_ASSIGNMENT value: Weight outside 1..10 or
 * more than the one optional Rank byte after Activate is a
 * PROTOCOL_VIOLATION. */
export function decodeSwitchingSetAssignment(bytes: Uint8Array): SwitchingSetAssignment {
  const { values, pos } = takeVarints(bytes, 0, 5);
  const [setId, algorithmId, thresholdKbps, weight, activate] = values;
  checkSsaWeight(weight, "PROTOCOL_VIOLATION");
  const rest = bytes.length - pos;
  if (rest > 1) fail("PROTOCOL_VIOLATION: bytes after SWITCHING_SET_ASSIGNMENT Rank");
  const out: SwitchingSetAssignment = { setId, algorithmId, thresholdKbps, weight, activate };
  if (rest === 1) out.rank = bytes[pos];
  return out;
}

// Length-prefixed parameters whose value has a structure of its own: the
// decoder validates it so a malformed one fails the whole message.
const PARAM_VALUE_CHECK = new Map<bigint, (v: Uint8Array) => void>([
  [PARAM_SWITCH_FROM, (v) => void decodeSwitchFrom(v)],
  [PARAM_SWITCHING_SET_ASSIGNMENT, (v) => void decodeSwitchingSetAssignment(v)],
]);

export function switchFromParam(s: SwitchFrom): MessageParam {
  return { type: PARAM_SWITCH_FROM, value: encodeSwitchFrom(s) };
}

export function switchingSetAssignmentParam(a: SwitchingSetAssignment): MessageParam {
  return { type: PARAM_SWITCHING_SET_ASSIGNMENT, value: encodeSwitchingSetAssignment(a) };
}

/** The SSTS_ALGORITHMS option value: the ids as concatenated varints. */
export function encodeSstsAlgorithms(ids: bigint[]): Uint8Array {
  return concatBytes(ids.map((id) => encodeVarint(id)));
}

export function decodeSstsAlgorithms(raw: Uint8Array): bigint[] {
  const ids: bigint[] = [];
  for (let pos = 0; pos < raw.length; ) {
    const v = decodeVarint(raw, pos);
    ids.push(v.value);
    pos += v.len;
  }
  return ids;
}

/** The SSTS_ALGORITHMS a SETUP advertised; undefined when it carries none
 * (an extension-less peer) or the value does not decode. */
export function sstsAlgorithmsOf(options: KeyValuePair[]): bigint[] | undefined {
  const opt = options.find((o) => o.type === SETUP_OPTION_SSTS_ALGORITHMS);
  if (!opt?.raw) return undefined;
  try {
    return decodeSstsAlgorithms(opt.raw);
  } catch {
    return undefined;
  }
}

/** SUBSCRIBE_OK's LARGEST_OBJECT (d22 9.20.17, d19 10.2.16): the largest
 * Location published so far, absent while nothing has been. */
export function largestObjectOf(params: MessageParam[]): Location | undefined {
  const p = params.find((x) => x.type === PARAM_LARGEST_OBJECT);
  return p ? (p.value as Location) : undefined;
}

export interface ControlFrame {
  type: bigint;
  body: Uint8Array;
}

/** Decode the Type/Length/Body framing shared by every control message. */
export function decodeControlFrame(bytes: Uint8Array, offset = 0): {
  frame: ControlFrame;
  len: number;
} {
  const type = decodeVarint(bytes, offset);
  const lenOffset = offset + type.len;
  if (lenOffset + 2 > bytes.length) fail("truncated control message: no Length field");
  const bodyLen = (bytes[lenOffset] << 8) | bytes[lenOffset + 1];
  const bodyStart = lenOffset + 2;
  const bodyEnd = bodyStart + bodyLen;
  if (bodyEnd > bytes.length) fail("truncated control message: body shorter than Length");
  return {
    frame: { type: type.value, body: bytes.slice(bodyStart, bodyEnd) },
    len: bodyEnd - offset,
  };
}

export function encodeControlFrame(type: bigint, body: Uint8Array): Uint8Array {
  if (body.length > 0xffff) fail(`control message body exceeds 65535 bytes: ${body.length}`);
  const header = new Uint8Array(2);
  header[0] = (body.length >> 8) & 0xff;
  header[1] = body.length & 0xff;
  return concatBytes([encodeVarint(type), header, body]);
}

// --- SETUP (0x2F00; d22 9.1, d19 10.3) ---------------------------------------------------

export interface SetupMessage {
  setupOptions: KeyValuePair[];
}

export function decodeSetup(body: Uint8Array): SetupMessage {
  return { setupOptions: decodeKvpSpan(body, 0, body.length) };
}

export function encodeSetup(msg: SetupMessage): Uint8Array {
  return encodeKvpList(msg.setupOptions);
}

// --- SUBSCRIBE (0x3; d22 9.6, d19 10.7) ----------------------------------------------------

export interface SubscribeMessage {
  requestId: bigint;
  trackNamespace: Uint8Array[];
  trackName: Uint8Array;
  parameters: MessageParam[];
}

export function decodeSubscribe(body: Uint8Array, draft: MoqtDraft = 19): SubscribeMessage {
  const requestId = decodeVarint(body, 0);
  let pos = requestId.len;
  const ns = decodeNamespace(body, pos);
  pos += ns.len;
  const name = decodeLenPrefixedBytes(body, pos, "track name");
  pos += name.len;
  return {
    requestId: requestId.value,
    trackNamespace: ns.fields,
    trackName: name.value,
    parameters: decodeParams(body, pos, draft).params,
  };
}

export function encodeSubscribe(msg: SubscribeMessage, draft: MoqtDraft = 19): Uint8Array {
  return concatBytes([
    encodeVarint(msg.requestId),
    encodeNamespace(msg.trackNamespace),
    encodeVarint(BigInt(msg.trackName.length)),
    msg.trackName,
    encodeParams(msg.parameters, draft),
  ]);
}

// --- SUBSCRIBE_OK (0x4; d22 9.7, d19 10.8) --------------------------------------------------

export interface SubscribeOkMessage {
  trackAlias: bigint;
  parameters: MessageParam[];
  trackProperties: KeyValuePair[];
}

export function decodeSubscribeOk(body: Uint8Array, draft: MoqtDraft = 19): SubscribeOkMessage {
  const trackAlias = decodeVarint(body, 0);
  const params = decodeParams(body, trackAlias.len, draft);
  const trackProperties = decodeKvpSpan(body, trackAlias.len + params.len, body.length);
  return { trackAlias: trackAlias.value, parameters: params.params, trackProperties };
}

export function encodeSubscribeOk(msg: SubscribeOkMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.trackAlias),
    encodeParams(msg.parameters),
    encodeKvpList(msg.trackProperties),
  ]);
}

// --- PUBLISH (0x1D; d22 9.8, d19 10.10) -------------------------------------------------------

export interface PublishMessage {
  requestId: bigint;
  trackNamespace: Uint8Array[];
  trackName: Uint8Array;
  trackAlias: bigint;
  parameters: MessageParam[];
  trackProperties: KeyValuePair[];
}

export function decodePublish(body: Uint8Array): PublishMessage {
  const requestId = decodeVarint(body, 0);
  let pos = requestId.len;
  const ns = decodeNamespace(body, pos);
  pos += ns.len;
  const name = decodeLenPrefixedBytes(body, pos, "track name");
  pos += name.len;
  const trackAlias = decodeVarint(body, pos);
  pos += trackAlias.len;
  const params = decodeParams(body, pos);
  pos += params.len;
  const trackProperties = decodeKvpSpan(body, pos, body.length);
  return {
    requestId: requestId.value,
    trackNamespace: ns.fields,
    trackName: name.value,
    trackAlias: trackAlias.value,
    parameters: params.params,
    trackProperties,
  };
}

export function encodePublish(msg: PublishMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.requestId),
    encodeNamespace(msg.trackNamespace),
    encodeVarint(BigInt(msg.trackName.length)),
    msg.trackName,
    encodeVarint(msg.trackAlias),
    encodeParams(msg.parameters),
    encodeKvpList(msg.trackProperties),
  ]);
}

// --- REQUEST_OK (0x7; d22 9.3, d19 10.5) ------------------------------------------------------

export interface RequestOkMessage {
  parameters: MessageParam[];
  trackProperties: KeyValuePair[];
}

export function decodeRequestOk(body: Uint8Array): RequestOkMessage {
  const params = decodeParams(body, 0);
  const trackProperties = decodeKvpSpan(body, params.len, body.length);
  return { parameters: params.params, trackProperties };
}

export function encodeRequestOk(msg: RequestOkMessage): Uint8Array {
  return concatBytes([encodeParams(msg.parameters), encodeKvpList(msg.trackProperties)]);
}

// --- FETCH (0x16) / FETCH_OK (0x18), draft-19 legacy only -----------------

/** draft-19 Joining Fetch (10.12.2): Fetch Type 0x2 Relative, 0x3 Absolute.
 * The Standalone form (0x1) is not sent by this client. draft-22 removed
 * Joining Fetch (sending one closes the session); a d22 session asks for
 * history with SUBSCRIBE's FILL_PARAMETERS instead (d22 3.4), which has no
 * FETCH_OK either. */
export interface JoiningFetchMessage {
  requestId: bigint;
  fetchType: 2n | 3n;
  joiningRequestId: bigint;
  joiningStart: bigint;
  parameters: MessageParam[];
}

export function encodeFetch(msg: JoiningFetchMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.requestId),
    encodeVarint(msg.fetchType),
    encodeVarint(msg.joiningRequestId),
    encodeVarint(msg.joiningStart),
    encodeParams(msg.parameters),
  ]);
}

export interface FetchOkMessage {
  endOfTrack: boolean;
  /** draft-19: one past the last Object (Object 0 = the whole End group).
   * (draft-22 9.12 makes it inclusive; this client decodes FETCH_OK only on
   * a draft-19 session.) */
  endLocation: Location;
  parameters: MessageParam[];
  trackProperties: KeyValuePair[];
}

export function decodeFetchOk(body: Uint8Array): FetchOkMessage {
  if (body.length < 1) fail("truncated FETCH_OK");
  const end = decodeLocation(body, 1);
  const params = decodeParams(body, 1 + end.len);
  return {
    endOfTrack: body[0] === 1,
    endLocation: end.value,
    parameters: params.params,
    trackProperties: decodeKvpSpan(body, 1 + end.len + params.len, body.length),
  };
}

// --- PUBLISH_NAMESPACE (0x6) / SUBSCRIBE_NAMESPACE (0x50) / NAMESPACE (0x8)
// / NAMESPACE_DONE (0xE) ------------------------------------------------------

/** PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE share one body layout
 * (d22 9.14, 9.15; d19 10.15, 10.18): Request ID, Track Namespace (or
 * Prefix), parameters. */
export interface NamespaceRequestMessage {
  requestId: bigint;
  namespace: Uint8Array[];
  parameters: MessageParam[];
}

export function encodeNamespaceRequest(msg: NamespaceRequestMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.requestId),
    encodeNamespace(msg.namespace),
    encodeParams(msg.parameters),
  ]);
}

/** NAMESPACE / NAMESPACE_DONE body (d22 9.16, 9.17; d19 10.16, 10.17):
 * the Track Namespace Suffix, the fields after the subscribed prefix. */
export function decodeNamespaceSuffix(body: Uint8Array): Uint8Array[] {
  return decodeNamespace(body, 0).fields;
}

// --- REQUEST_ERROR (0x5; d22 9.4, d19 10.6) ---------------------------------------------------

export interface RequestErrorMessage {
  errorCode: bigint;
  retryInterval: bigint;
  errorReason: Uint8Array;
}

export function decodeRequestError(body: Uint8Array): RequestErrorMessage {
  const errorCode = decodeVarint(body, 0);
  let pos = errorCode.len;
  const retryInterval = decodeVarint(body, pos);
  pos += retryInterval.len;
  const reason = decodeLenPrefixedBytes(body, pos, "error reason");
  return {
    errorCode: errorCode.value,
    retryInterval: retryInterval.value,
    errorReason: reason.value,
  };
}

export function encodeRequestError(msg: RequestErrorMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.errorCode),
    encodeVarint(msg.retryInterval),
    encodeVarint(BigInt(msg.errorReason.length)),
    msg.errorReason,
  ]);
}

// --- PUBLISH_DONE (0xB; d22 9.9, d19 10.11) -----------------------------------------------------

export interface PublishDoneMessage {
  statusCode: bigint;
  streamCount: bigint;
  errorReason: Uint8Array;
}

export function decodePublishDone(body: Uint8Array): PublishDoneMessage {
  const statusCode = decodeVarint(body, 0);
  let pos = statusCode.len;
  const streamCount = decodeVarint(body, pos);
  pos += streamCount.len;
  const reason = decodeLenPrefixedBytes(body, pos, "error reason");
  return {
    statusCode: statusCode.value,
    streamCount: streamCount.value,
    errorReason: reason.value,
  };
}

export function encodePublishDone(msg: PublishDoneMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.statusCode),
    encodeVarint(msg.streamCount),
    encodeVarint(BigInt(msg.errorReason.length)),
    msg.errorReason,
  ]);
}

// --- GOAWAY (0x10; d22 9.2, d19 10.4) -----------------------------------------------------------

export interface GoawayMessage {
  newSessionUri: Uint8Array;
  timeout: bigint;
}

export function decodeGoaway(body: Uint8Array): GoawayMessage {
  const uri = decodeLenPrefixedBytes(body, 0, "new session uri");
  const timeout = decodeVarint(body, uri.len);
  return { newSessionUri: uri.value, timeout: timeout.value };
}

export function encodeGoaway(msg: GoawayMessage): Uint8Array {
  return concatBytes([
    encodeVarint(BigInt(msg.newSessionUri.length)),
    msg.newSessionUri,
    encodeVarint(msg.timeout),
  ]);
}

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 6.4.1/11.3.1 (draft-19 3.4/11.4.2):
// Unidirectional Streams, Subgroups, Objects
// ---------------------------------------------------------------------

const STREAM_TYPE_FETCH_HEADER = 0x05n;
const STREAM_TYPE_SETUP = 0x2f00n;
const STREAM_TYPE_PADDING = 0x132b3e28n;

export type StreamClass = "control" | "fetch" | "subgroup" | "padding" | "unknown";

/** Classify a stream given its leading Stream Type varint value. */
export function classifyStreamType(type: bigint): StreamClass {
  if (type === STREAM_TYPE_SETUP) return "control";
  if (type === STREAM_TYPE_FETCH_HEADER) return "fetch";
  if (type === STREAM_TYPE_PADDING) return "padding";
  if (isSubgroupHeaderType(type)) return "subgroup";
  return "unknown";
}

function isSubgroupHeaderType(type: bigint): boolean {
  if (type < 0x10n || type > 0x7fn) return false;
  const low = type & 0xffn;
  // Form 0b0XX1XXXX: bit4 set, bit7 clear.
  return (low & 0x80n) === 0n && (low & 0x10n) !== 0n;
}

export interface SubgroupHeaderFlags {
  properties: boolean;
  subgroupIdMode: 0 | 1 | 2 | 3;
  endOfGroup: boolean;
  defaultPriority: boolean;
  firstObject: boolean;
}

/** Decode the flag bits packed into a SUBGROUP_HEADER Type value. Rejects reserved/invalid forms. */
export function decodeSubgroupTypeFlags(type: bigint): SubgroupHeaderFlags {
  if (!isSubgroupHeaderType(type)) {
    fail(`PROTOCOL_VIOLATION: invalid SUBGROUP_HEADER type 0x${type.toString(16)}`);
  }
  const subgroupIdMode = Number((type >> 1n) & 0x3n) as 0 | 1 | 2 | 3;
  if (subgroupIdMode === 3) {
    fail(`PROTOCOL_VIOLATION: reserved SUBGROUP_ID_MODE in type 0x${type.toString(16)}`);
  }
  return {
    properties: (type & 0x01n) !== 0n,
    subgroupIdMode,
    endOfGroup: (type & 0x08n) !== 0n,
    defaultPriority: (type & 0x20n) !== 0n,
    firstObject: (type & 0x40n) !== 0n,
  };
}

export interface SubgroupHeader {
  type: bigint;
  flags: SubgroupHeaderFlags;
  trackAlias: bigint;
  groupId: bigint;
  subgroupId: bigint;
  publisherPriority?: number;
}

export function decodeSubgroupHeader(
  bytes: Uint8Array,
  offset = 0,
): { header: SubgroupHeader; len: number } {
  const type = decodeVarint(bytes, offset);
  const flags = decodeSubgroupTypeFlags(type.value);
  let pos = offset + type.len;

  const trackAlias = decodeVarint(bytes, pos);
  pos += trackAlias.len;
  const groupId = decodeVarint(bytes, pos);
  pos += groupId.len;

  let subgroupId = 0n;
  if (flags.subgroupIdMode === 2) {
    const sg = decodeVarint(bytes, pos);
    subgroupId = sg.value;
    pos += sg.len;
  }
  // mode 0 -> 0, mode 1 -> Object ID of the first object (filled in by the caller).

  let publisherPriority: number | undefined;
  if (!flags.defaultPriority) {
    if (pos >= bytes.length) fail("truncated SUBGROUP_HEADER: missing Publisher Priority");
    publisherPriority = bytes[pos];
    pos += 1;
  }

  return {
    header: { type: type.value, flags, trackAlias: trackAlias.value, groupId: groupId.value, subgroupId, publisherPriority },
    len: pos - offset,
  };
}

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 11.2.1 (draft-19 11.3.1): OBJECT_DATAGRAM
// ---------------------------------------------------------------------

const DGRAM_PROPERTIES = 0x01n;
const DGRAM_END_OF_GROUP = 0x02n;
const DGRAM_ZERO_OBJECT_ID = 0x04n;
const DGRAM_DEFAULT_PRIORITY = 0x08n;
const DGRAM_STATUS = 0x20n;

/** OBJECT_DATAGRAM Type form 0b00X0XXXX (11.2.1): only the low nibble and
 * the STATUS bit may be set -- Type is a varint, so a value >= 0x100 is
 * invalid whatever its low byte -- and STATUS + END_OF_GROUP together are
 * explicitly invalid. Mirrors moqdg_type_valid on the hub side. */
function objectDatagramTypeValid(type: bigint): boolean {
  if ((type & ~0x2fn) !== 0n) return false;
  const statusEog = DGRAM_STATUS | DGRAM_END_OF_GROUP;
  return (type & statusEog) !== statusEog;
}

/** Decoded OBJECT_DATAGRAM. The Type bits say which fields were on the
 * wire; absent fields read as their defaults here (same shape as the hub's
 * moqdg_obj, src/app/moqt/dgram/moqdg.h). */
export interface ObjectDatagram {
  type: bigint;
  trackAlias: bigint;
  groupId: bigint;
  /** 0n when the ZERO_OBJECT_ID bit (0x04) omits the field. */
  objectId: bigint;
  /** 0 when the DEFAULT_PRIORITY bit (0x08) omits the field. */
  priority: number;
  /** 0n (Normal) unless the STATUS bit (0x20) is set. */
  status: bigint;
  /** Properties bytes; empty when the PROPERTIES bit (0x01) is clear. */
  properties: Uint8Array;
  /** The rest of the datagram; empty when the STATUS bit is set. */
  payload: Uint8Array;
}

/** encodeObjectDatagram's input: fields whose Type bit omits them from the
 * wire may be left out. */
export type ObjectDatagramInit = Pick<
  ObjectDatagram,
  "type" | "trackAlias" | "groupId"
> &
  Partial<ObjectDatagram>;

/** Decodes one whole datagram as an OBJECT_DATAGRAM. Throws
 * MoqtDecodeError on a truncated datagram or a PROTOCOL_VIOLATION (invalid
 * Type, PROPERTIES bit with a Properties Length of 0, STATUS + PROPERTIES
 * with a non-Normal Status) -- the same rules as the hub's moqdg_take. */
export function decodeObjectDatagram(bytes: Uint8Array): ObjectDatagram {
  const type = decodeVarint(bytes, 0);
  const t = type.value;
  if (!objectDatagramTypeValid(t)) {
    fail(`PROTOCOL_VIOLATION: invalid OBJECT_DATAGRAM type 0x${t.toString(16)}`);
  }
  let pos = type.len;
  const trackAlias = decodeVarint(bytes, pos);
  pos += trackAlias.len;
  const groupId = decodeVarint(bytes, pos);
  pos += groupId.len;

  let objectId = 0n;
  if ((t & DGRAM_ZERO_OBJECT_ID) === 0n) {
    const oid = decodeVarint(bytes, pos);
    objectId = oid.value;
    pos += oid.len;
  }
  let priority = 0;
  if ((t & DGRAM_DEFAULT_PRIORITY) === 0n) {
    if (pos >= bytes.length) fail("truncated OBJECT_DATAGRAM: missing Publisher Priority");
    priority = bytes[pos];
    pos += 1;
  }
  let properties = new Uint8Array(0);
  if ((t & DGRAM_PROPERTIES) !== 0n) {
    const len = decodeVarint(bytes, pos);
    if (len.value === 0n) {
      fail("PROTOCOL_VIOLATION: OBJECT_DATAGRAM PROPERTIES bit with Properties Length 0");
    }
    pos += len.len;
    const end = pos + Number(len.value);
    if (end > bytes.length) fail("truncated OBJECT_DATAGRAM: properties");
    properties = bytes.slice(pos, end);
    pos = end;
  }
  let status = 0n;
  let payload = new Uint8Array(0);
  if ((t & DGRAM_STATUS) !== 0n) {
    status = decodeVarint(bytes, pos).value;
    if (properties.length > 0 && status !== 0n) {
      fail("PROTOCOL_VIOLATION: OBJECT_DATAGRAM properties with a non-Normal status");
    }
  } else {
    payload = bytes.slice(pos);
  }
  return {
    type: t,
    trackAlias: trackAlias.value,
    groupId: groupId.value,
    objectId,
    priority,
    status,
    properties,
    payload,
  };
}

/** Inverse of decodeObjectDatagram: one datagram's bytes, minimal varints.
 * Throws MoqtDecodeError on the same violations decodeObjectDatagram
 * rejects. */
export function encodeObjectDatagram(o: ObjectDatagramInit): Uint8Array {
  const t = o.type;
  const properties = o.properties ?? new Uint8Array(0);
  const status = o.status ?? 0n;
  if (!objectDatagramTypeValid(t)) {
    fail(`PROTOCOL_VIOLATION: invalid OBJECT_DATAGRAM type 0x${t.toString(16)}`);
  }
  if ((t & DGRAM_PROPERTIES) !== 0n && properties.length === 0) {
    fail("PROTOCOL_VIOLATION: OBJECT_DATAGRAM PROPERTIES bit with no properties");
  }
  if (properties.length > 0 && status !== 0n) {
    fail("PROTOCOL_VIOLATION: OBJECT_DATAGRAM properties with a non-Normal status");
  }
  const parts = [encodeVarint(t), encodeVarint(o.trackAlias), encodeVarint(o.groupId)];
  if ((t & DGRAM_ZERO_OBJECT_ID) === 0n) parts.push(encodeVarint(o.objectId ?? 0n));
  if ((t & DGRAM_DEFAULT_PRIORITY) === 0n) parts.push(Uint8Array.of(o.priority ?? 0));
  if ((t & DGRAM_PROPERTIES) !== 0n) {
    parts.push(encodeVarint(BigInt(properties.length)), properties);
  }
  if ((t & DGRAM_STATUS) !== 0n) parts.push(encodeVarint(status));
  else parts.push(o.payload ?? new Uint8Array(0));
  return concatBytes(parts);
}

export interface SubgroupObject {
  objectId: bigint;
  properties?: KeyValuePair[];
  payload: Uint8Array;
  objectStatus?: bigint;
}

/**
 * Decode one Subgroup Object. `prevObjectId` / `isFirst` drive the Object ID
 * Delta accumulation (draft-ietf-moq-transport-22 11.3.1): the first object's
 * ID is the delta itself, later ones are prevId + delta + 1.
 */
export function decodeSubgroupObject(
  bytes: Uint8Array,
  offset: number,
  hasProperties: boolean,
  prevObjectId: bigint,
  isFirst: boolean,
): { object: SubgroupObject; len: number } {
  const delta = decodeVarint(bytes, offset);
  const objectId = isFirst ? delta.value : prevObjectId + delta.value + 1n;
  let pos = offset + delta.len;

  let properties: KeyValuePair[] | undefined;
  if (hasProperties) {
    const propLen = decodeVarint(bytes, pos);
    pos += propLen.len;
    const propEnd = pos + Number(propLen.value);
    properties = decodeKvpSpan(bytes, pos, propEnd);
    pos = propEnd;
  }

  const payloadLen = decodeVarint(bytes, pos);
  pos += payloadLen.len;

  let objectStatus: bigint | undefined;
  if (payloadLen.value === 0n) {
    const status = decodeVarint(bytes, pos);
    objectStatus = status.value;
    pos += status.len;
  }

  const payloadEnd = pos + Number(payloadLen.value);
  const payload = bytes.slice(pos, payloadEnd);
  pos = payloadEnd;

  return { object: { objectId, properties, payload, objectStatus }, len: pos - offset };
}

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-22 11.4.1 (draft-19 11.4.4): FETCH data stream
// (FETCH_HEADER + fetch Objects). A draft-22 fill fetch stream (3.4) has
// the same shape; its FETCH_HEADER names the SUBSCRIBE's Request ID.
// ---------------------------------------------------------------------

export function decodeFetchHeader(bytes: Uint8Array, offset = 0): { requestId: bigint; len: number } {
  const type = decodeVarint(bytes, offset);
  if (type.value !== STREAM_TYPE_FETCH_HEADER) fail("not a FETCH_HEADER stream");
  const rid = decodeVarint(bytes, offset + type.len);
  return { requestId: rid.value, len: type.len + rid.len };
}

/** What a later fetch Object may inherit from the ones before it
 * (11.4.1.1). An End of Range sets group/object but not subgroup/priority. */
export interface FetchSeq {
  group?: bigint;
  object?: bigint;
  subgroup?: bigint;
  priority?: number;
}

export const newFetchSeq = (): FetchSeq => ({});

export interface FetchObject {
  group: bigint;
  object: bigint;
  priority?: number;
  payload: Uint8Array;
  /** Set on an End of Range marker (11.4.1.2) instead of an Object;
   * "timed_out" (0x20C) exists only on a draft-22 session. */
  endOfRange?: "non_existent" | "unknown" | "timed_out";
}

const FETCH_GROUP = 0x08n;
const FETCH_OBJECT = 0x04n;
const FETCH_PRIORITY = 0x10n;
const FETCH_PROPERTIES = 0x20n;
const FETCH_DATAGRAM = 0x40n;
const FETCH_EOR_NONE = 0x8cn;
const FETCH_EOR_UNKNOWN = 0x10cn;
const FETCH_EOR_TIMED_OUT = 0x20cn; // draft-22 only

const FETCH_EOR: Record<MoqtDraft, Map<bigint, NonNullable<FetchObject["endOfRange"]>>> = {
  19: new Map([
    [FETCH_EOR_NONE, "non_existent"],
    [FETCH_EOR_UNKNOWN, "unknown"],
  ]),
  22: new Map([
    [FETCH_EOR_NONE, "non_existent"],
    [FETCH_EOR_UNKNOWN, "unknown"],
    [FETCH_EOR_TIMED_OUT, "timed_out"],
  ]),
};

function inherited<T>(v: T | undefined, what: string): T {
  if (v === undefined) fail(`PROTOCOL_VIOLATION: fetch Object references a prior ${what}`);
  return v;
}

/** Decode one fetch Object (or End of Range) at `offset`, updating `seq`
 * only on success. Throws MoqtDecodeError when the bytes run out mid-item
 * (a stream reader waits for more) or on a PROTOCOL_VIOLATION. Groups are
 * taken as ascending (the hub's only order). An End of Range carries the
 * range end's absolute Group and Object, like a first Object; 0x20C (End of
 * Timed-Out Range) is one only on a draft-22 session. */
export function decodeFetchObject(
  bytes: Uint8Array,
  offset: number,
  seq: FetchSeq,
  draft: MoqtDraft = 19,
): { object: FetchObject; len: number } {
  const flags = decodeVarint(bytes, offset);
  let pos = offset + flags.len;
  const take = () => {
    const v = decodeVarint(bytes, pos);
    pos += v.len;
    return v.value;
  };
  const f = flags.value;
  const endOfRange = FETCH_EOR[draft].get(f);
  if (endOfRange) {
    const group = take();
    const object = take();
    Object.assign(seq, { group, object });
    return { object: { group, object, payload: new Uint8Array(0), endOfRange }, len: pos - offset };
  }
  if (f >= 128n) fail(`PROTOCOL_VIOLATION: fetch Serialization Flags 0x${f.toString(16)}`);
  const newGroup = (f & FETCH_GROUP) !== 0n;
  let group: bigint;
  if (!newGroup) group = inherited(seq.group, "Group");
  else if (seq.group === undefined) group = take();
  else group = seq.group + take() + 1n;
  let subgroup: bigint | undefined;
  if ((f & FETCH_DATAGRAM) === 0n) {
    const mode = f & 0x03n;
    if (mode === 0n) subgroup = 0n;
    else if (mode === 3n) subgroup = take();
    else subgroup = inherited(seq.subgroup, "Subgroup") + (mode - 1n);
  }
  let object: bigint;
  if ((f & FETCH_OBJECT) === 0n) object = inherited(seq.object, "Object") + 1n;
  else if (newGroup || seq.object === undefined) object = take();
  else object = seq.object + take();
  let priority: number;
  if ((f & FETCH_PRIORITY) === 0n) priority = inherited(seq.priority, "Priority");
  else {
    if (pos >= bytes.length) fail("truncated fetch Object: no Publisher Priority");
    priority = bytes[pos++];
  }
  if ((f & FETCH_PROPERTIES) !== 0n) pos += Number(take());
  const payloadLen = Number(take());
  if (pos + payloadLen > bytes.length) fail("truncated fetch Object payload");
  const payload = bytes.slice(pos, pos + payloadLen);
  pos += payloadLen;
  Object.assign(seq, { group, object, subgroup, priority });
  return { object: { group, object, priority, payload }, len: pos - offset };
}
