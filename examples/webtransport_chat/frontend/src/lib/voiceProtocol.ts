// Datagram protocol codec for the WebTransport voice+chat multiplex.
// Wire layout:
//   chat:  0x01 | senderId(4) | JSON of {"name": string, "text": string} (utf-8)
//          (legacy: a bare JSON string is accepted on decode as name-less text)
//   voice: 0x02 | senderId(4) | seq(2, big-endian u16) | opus payload (opaque bytes)
//   presence: 0x03 | senderId(4) | JSON of {"kind": "join"|"leave", "name": string}

const CHANNEL_CHAT = 0x01;
const CHANNEL_VOICE = 0x02;
const CHANNEL_PRESENCE = 0x03;
const SENDER_ID_LEN = 4;
const SEQ_LEN = 2;
const CHAT_HEADER_LEN = 1 + SENDER_ID_LEN;
const VOICE_HEADER_LEN = 1 + SENDER_ID_LEN + SEQ_LEN;
const U16_SPACE = 0x10000;

export type ChatFrame = {
  channel: "chat";
  senderId: Uint8Array;
  name: string;
  text: string;
};

export type VoiceFrame = {
  channel: "voice";
  senderId: Uint8Array;
  seq: number;
  payload: Uint8Array;
};

export type PresenceFrame = {
  channel: "presence";
  senderId: Uint8Array;
  kind: "join" | "leave";
  name: string;
};

export type Frame = ChatFrame | VoiceFrame | PresenceFrame;

export type DecodeResult =
  | { ok: true; frame: Frame }
  | { ok: false; error: string };

function parseChatPayload(payload: unknown): { name: string; text: string } | null {
  if (typeof payload === "string") {
    return { name: "", text: payload }; // legacy bare-string form
  }
  if (
    typeof payload === "object" &&
    payload !== null &&
    typeof (payload as { name: unknown }).name === "string" &&
    typeof (payload as { text: unknown }).text === "string"
  ) {
    const { name, text } = payload as { name: string; text: string };
    return { name, text };
  }
  return null;
}

function decodeChat(bytes: Uint8Array): DecodeResult {
  if (bytes.length < CHAT_HEADER_LEN) {
    return { ok: false, error: "chat datagram shorter than header" };
  }
  const senderId = bytes.slice(1, CHAT_HEADER_LEN);
  const jsonBytes = bytes.slice(CHAT_HEADER_LEN);
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(jsonBytes));
  } catch {
    return { ok: false, error: "malformed chat JSON payload" };
  }
  const parsed = parseChatPayload(payload);
  if (parsed === null) {
    return { ok: false, error: "malformed chat JSON payload" };
  }
  return { ok: true, frame: { channel: "chat", senderId, ...parsed } };
}

function parsePresencePayload(payload: unknown): { kind: "join" | "leave"; name: string } | null {
  if (typeof payload !== "object" || payload === null) return null;
  const { kind, name } = payload as { kind: unknown; name: unknown };
  if (kind !== "join" && kind !== "leave") return null;
  if (typeof name !== "string") return null;
  return { kind, name };
}

function decodePresence(bytes: Uint8Array): DecodeResult {
  if (bytes.length < CHAT_HEADER_LEN) {
    return { ok: false, error: "presence datagram shorter than header" };
  }
  const senderId = bytes.slice(1, CHAT_HEADER_LEN);
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes.slice(CHAT_HEADER_LEN)));
  } catch {
    return { ok: false, error: "malformed presence JSON payload" };
  }
  const parsed = parsePresencePayload(payload);
  if (parsed === null) {
    return { ok: false, error: "malformed presence JSON payload" };
  }
  return { ok: true, frame: { channel: "presence", senderId, ...parsed } };
}

function decodeVoice(bytes: Uint8Array): DecodeResult {
  if (bytes.length < VOICE_HEADER_LEN) {
    return { ok: false, error: "voice datagram shorter than header" };
  }
  const senderId = bytes.slice(1, 1 + SENDER_ID_LEN);
  const seq = (bytes[1 + SENDER_ID_LEN] << 8) | bytes[2 + SENDER_ID_LEN];
  const payload = bytes.slice(VOICE_HEADER_LEN);
  return { ok: true, frame: { channel: "voice", senderId, seq, payload } };
}

export function decodeFrame(bytes: Uint8Array): DecodeResult {
  if (bytes.length < 1) {
    return { ok: false, error: "empty datagram" };
  }
  switch (bytes[0]) {
    case CHANNEL_CHAT:
      return decodeChat(bytes);
    case CHANNEL_VOICE:
      return decodeVoice(bytes);
    case CHANNEL_PRESENCE:
      return decodePresence(bytes);
    default:
      return { ok: false, error: `undefined channel byte ${bytes[0]}` };
  }
}

export type EncodeResult =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; error: string };

const MAX_DATAGRAM_SIZE = 1200; // ponytail: conservative PMTU-safe default; wire to negotiated maxDatagramSize when the transport layer exposes it.

function assembleFrame(header: number[], payload: Uint8Array): EncodeResult {
  const bytes = new Uint8Array(header.length + payload.length);
  bytes.set(header, 0);
  bytes.set(payload, header.length);
  if (bytes.length > MAX_DATAGRAM_SIZE) {
    return { ok: false, error: "encoded frame exceeds maxDatagramSize" };
  }
  return { ok: true, bytes };
}

export function encodeChatFrame(
  senderId: Uint8Array,
  name: string,
  text: string,
): EncodeResult {
  const payload = new TextEncoder().encode(JSON.stringify({ name, text }));
  return assembleFrame([CHANNEL_CHAT, ...senderId], payload);
}

export function encodePresenceFrame(
  senderId: Uint8Array,
  kind: "join" | "leave",
  name: string,
): EncodeResult {
  const payload = new TextEncoder().encode(JSON.stringify({ kind, name }));
  return assembleFrame([CHANNEL_PRESENCE, ...senderId], payload);
}

export function encodeVoiceFrame(
  senderId: Uint8Array,
  seq: number,
  payload: Uint8Array,
): EncodeResult {
  const wrapped = ((seq % U16_SPACE) + U16_SPACE) % U16_SPACE;
  const header = [
    CHANNEL_VOICE,
    ...senderId,
    (wrapped >> 8) & 0xff,
    wrapped & 0xff,
  ];
  return assembleFrame(header, payload);
}

export function generateSenderId(): Uint8Array {
  if (
    typeof crypto === "undefined" ||
    typeof crypto.getRandomValues !== "function"
  ) {
    throw new Error(
      "crypto.getRandomValues is unavailable; refusing a Math.random fallback",
    );
  }
  const id = new Uint8Array(SENDER_ID_LEN);
  crypto.getRandomValues(id);
  return id;
}
