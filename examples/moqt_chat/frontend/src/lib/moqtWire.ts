// MOQT wire codec (draft-ietf-moq-transport-19).
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

// ---------------------------------------------------------------------
// draft-ietf-moq-transport-19 1.4.1: Variable-Length Integers
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
// draft-ietf-moq-transport-19 1.4.3: Key-Value-Pair Structure
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
// draft-ietf-moq-transport-19 3.1.1: Track Naming (Track Namespace / Full
// Track Name)
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
// draft-ietf-moq-transport-19 10: Control Messages
// ---------------------------------------------------------------------

/** Decode `count` consecutive Key-Value-Pairs starting at `offset`. */
function decodeKvpList(
  bytes: Uint8Array,
  offset: number,
  count: bigint,
): { pairs: KeyValuePair[]; len: number } {
  let pos = offset;
  let prevType = 0n;
  const pairs: KeyValuePair[] = [];
  for (let i = 0n; i < count; i++) {
    const { pair, len } = decodeKvp(bytes, pos, prevType);
    pairs.push(pair);
    pos += len;
    prevType = pair.type;
  }
  return { pairs, len: pos - offset };
}

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

// --- SETUP (0x2F00) ---------------------------------------------------

export interface SetupMessage {
  setupOptions: KeyValuePair[];
}

export function decodeSetup(body: Uint8Array): SetupMessage {
  return { setupOptions: decodeKvpSpan(body, 0, body.length) };
}

export function encodeSetup(msg: SetupMessage): Uint8Array {
  return encodeKvpList(msg.setupOptions);
}

// --- SUBSCRIBE (0x3) ----------------------------------------------------

export interface SubscribeMessage {
  requestId: bigint;
  trackNamespace: Uint8Array[];
  trackName: Uint8Array;
  parameters: KeyValuePair[];
}

export function decodeSubscribe(body: Uint8Array): SubscribeMessage {
  const requestId = decodeVarint(body, 0);
  let pos = requestId.len;
  const ns = decodeNamespace(body, pos);
  pos += ns.len;
  const name = decodeLenPrefixedBytes(body, pos, "track name");
  pos += name.len;
  const numParams = decodeVarint(body, pos);
  pos += numParams.len;
  const { pairs } = decodeKvpList(body, pos, numParams.value);
  return {
    requestId: requestId.value,
    trackNamespace: ns.fields,
    trackName: name.value,
    parameters: pairs,
  };
}

export function encodeSubscribe(msg: SubscribeMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.requestId),
    encodeNamespace(msg.trackNamespace),
    encodeVarint(BigInt(msg.trackName.length)),
    msg.trackName,
    encodeVarint(BigInt(msg.parameters.length)),
    encodeKvpList(msg.parameters),
  ]);
}

// --- SUBSCRIBE_OK (0x4) --------------------------------------------------

export interface SubscribeOkMessage {
  trackAlias: bigint;
  parameters: KeyValuePair[];
  trackProperties: KeyValuePair[];
}

export function decodeSubscribeOk(body: Uint8Array): SubscribeOkMessage {
  const trackAlias = decodeVarint(body, 0);
  let pos = trackAlias.len;
  const numParams = decodeVarint(body, pos);
  pos += numParams.len;
  const params = decodeKvpList(body, pos, numParams.value);
  pos += params.len;
  const trackProperties = decodeKvpSpan(body, pos, body.length);
  return { trackAlias: trackAlias.value, parameters: params.pairs, trackProperties };
}

export function encodeSubscribeOk(msg: SubscribeOkMessage): Uint8Array {
  return concatBytes([
    encodeVarint(msg.trackAlias),
    encodeVarint(BigInt(msg.parameters.length)),
    encodeKvpList(msg.parameters),
    encodeKvpList(msg.trackProperties),
  ]);
}

// --- PUBLISH (0x1D) -------------------------------------------------------

export interface PublishMessage {
  requestId: bigint;
  trackNamespace: Uint8Array[];
  trackName: Uint8Array;
  trackAlias: bigint;
  parameters: KeyValuePair[];
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
  const numParams = decodeVarint(body, pos);
  pos += numParams.len;
  const params = decodeKvpList(body, pos, numParams.value);
  pos += params.len;
  const trackProperties = decodeKvpSpan(body, pos, body.length);
  return {
    requestId: requestId.value,
    trackNamespace: ns.fields,
    trackName: name.value,
    trackAlias: trackAlias.value,
    parameters: params.pairs,
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
    encodeVarint(BigInt(msg.parameters.length)),
    encodeKvpList(msg.parameters),
    encodeKvpList(msg.trackProperties),
  ]);
}

// --- REQUEST_OK (0x7) ------------------------------------------------------

export interface RequestOkMessage {
  parameters: KeyValuePair[];
  trackProperties: KeyValuePair[];
}

export function decodeRequestOk(body: Uint8Array): RequestOkMessage {
  const numParams = decodeVarint(body, 0);
  let pos = numParams.len;
  const params = decodeKvpList(body, pos, numParams.value);
  pos += params.len;
  const trackProperties = decodeKvpSpan(body, pos, body.length);
  return { parameters: params.pairs, trackProperties };
}

export function encodeRequestOk(msg: RequestOkMessage): Uint8Array {
  return concatBytes([
    encodeVarint(BigInt(msg.parameters.length)),
    encodeKvpList(msg.parameters),
    encodeKvpList(msg.trackProperties),
  ]);
}

// --- REQUEST_ERROR (0x5) ---------------------------------------------------

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

// --- PUBLISH_DONE (0xB) -----------------------------------------------------

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

// --- GOAWAY (0x10) -----------------------------------------------------------

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
// draft-ietf-moq-transport-19 4/11.4.2: Unidirectional Streams, Subgroups,
// Objects
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

export interface SubgroupObject {
  objectId: bigint;
  properties?: KeyValuePair[];
  payload: Uint8Array;
  objectStatus?: bigint;
}

/**
 * Decode one Subgroup Object. `prevObjectId` / `isFirst` drive the Object ID
 * Delta accumulation (draft-ietf-moq-transport-19 11.4.2): the first object's
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
