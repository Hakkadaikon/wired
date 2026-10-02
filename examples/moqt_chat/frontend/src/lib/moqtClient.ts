// MOQT chat transport: wires the browser WebTransport API to the
// draft-ietf-moq-transport-19 codec in moqtWire.ts, matching the fixed hub
// protocol implemented by wired_server (examples/moqt_chat/wired_server.c,
// src/app/moqt/run/moqtrun.c):
//
//  - The hub opens ONE server-initiated bidirectional stream per session and
//    sends SETUP on it (draft 3.3); the client only drains it.
//  - Every request (PUBLISH, SUBSCRIBE, FETCH, PUBLISH_NAMESPACE,
//    SUBSCRIBE_NAMESPACE) opens its own bidirectional request stream (3.3)
//    with an even, client-chosen Request ID; its answer comes back on that
//    stream, so it is matched by stream, never by arrival order. Resetting
//    the stream cancels the request (3.3.3).
//  - Room membership is namespace discovery (6.1-6.2): each participant
//    announces wired/moqt_chat/<id> once its tracks are PUBLISHed and
//    watches the wired/moqt_chat prefix. A NAMESPACE subscribes that peer's
//    chat track (with a Joining FETCH for its history); a NAMESPACE_DONE
//    cancels every subscription to it. Nothing is polled.
//  - Chat messages are sent as one uni stream each: SUBGROUP_HEADER + one
//    Object (1 message = 1 Object = 1 Group = 1 Subgroup; an attachment
//    stream instead carries one Object per chunk in a Group of its own, see
//    sendMessage), matching moqdata.h's moqdata_msg_build layout on the
//    server side.

import {
  bytesToUtf8,
  concatBytes,
  decodeControlFrame,
  decodeFetchHeader,
  decodeGoaway,
  decodeFetchObject,
  decodeNamespaceSuffix,
  decodeSubgroupHeader,
  decodeSubgroupObject,
  decodeSubscribeOk,
  decodeVarint,
  encodeControlFrame,
  encodeFetch,
  encodeNamespaceRequest,
  encodePublish,
  encodeSubscribe,
  encodeVarint,
  hexToBytes,
  decodeObjectDatagram,
  largestObjectOf,
  newFetchSeq,
  PARAM_LOCATION_FILTER,
  readToEof,
  utf8ToBytes,
  type FetchObject,
  type FetchSeq,
  type Location,
  type ObjectDatagram,
  type SubgroupHeader,
} from "./moqtWire";
import {
  attachmentReassemblerInit,
  attachmentReassemblerPush,
  buildAttachmentSubgroupHeader,
  decodeAttachmentChunkMessage,
  decodeTextPartMessage,
  encodeAttachmentChunkMessage,
  encodeTextPartMessage,
  isAttachmentChunkPayload,
  isTextPartPayload,
  splitAttachmentIntoChunks,
  type AttachmentReassembler,
} from "./moqtAttachmentWire";
import { ATTACHMENT_MAX_COUNT } from "./attachmentValidation";

// draft-ietf-moq-transport-19 SS10 message type IDs used on the wire here.
const MSG_TYPE_PUBLISH = 0x1dn;
const MSG_TYPE_SUBSCRIBE = 0x3n;
const MSG_TYPE_SUBSCRIBE_OK = 0x4n;
const MSG_TYPE_REQUEST_OK = 0x7n;
const MSG_TYPE_FETCH = 0x16n;
const MSG_TYPE_FETCH_OK = 0x18n;
const MSG_TYPE_PUBLISH_NAMESPACE = 0x6n;
const MSG_TYPE_SUBSCRIBE_NAMESPACE = 0x50n;
const MSG_TYPE_NAMESPACE = 0x8n;
const MSG_TYPE_NAMESPACE_DONE = 0xen;
const MSG_TYPE_GOAWAY = 0x10n;
const STREAM_TYPE_FETCH_HEADER = 0x5n;

// LOCATION_FILTER (10.2.18) of type Largest Object (0x2): live delivery
// starts after the Largest Object, which a Joining FETCH ends at (10.12.2),
// so the two meet with no gap or overlap.
const LARGEST_OBJECT_FILTER = { type: PARAM_LOCATION_FILTER, value: Uint8Array.of(0x2) };

// Chat history a joiner asks for: the last CHAT_HISTORY_GROUPS Groups of
// each peer's chat track (one Group per message text, attachment or
// nickname), as far as the hub's cache still holds them.
const CHAT_HISTORY_GROUPS = 64n;

// SUBGROUP_HEADER Type (moqdata.h MOQDATA_MSG builder): PROPERTIES off,
// SUBGROUP_ID_MODE 0b00, no end-of-group, DEFAULT_PRIORITY on, FIRST_OBJECT
// on: 0x10 (base) | 0x40 (FIRST_OBJECT) | 0x20 (DEFAULT_PRIORITY) = 0x70.
// Exported for moqtVoiceWire.ts, which builds the same shape of header for
// the audio track's long-lived stream.
export const SUBGROUP_HEADER_TYPE = 0x70n;

// Fixed id pool: membership itself comes from namespace discovery, but each
// id's index is its Track Alias (ownTrackAlias below), so ids stay a small
// fixed list.
// ponytail: raise/replace with alias negotiation if the room needs more.
export const CANDIDATE_PARTICIPANT_IDS = ["user1", "user2", "user3", "user4"];

export function candidateParticipantIds(localId: string): string[] {
  return CANDIDATE_PARTICIPANT_IDS.filter((id) => id !== localId);
}

// moqtrun.c relays a publisher's SUBGROUP bytes unmodified: the
// Track Alias a subscriber sees on the wire is the PUBLISHER's own alias,
// not the alias the hub assigned that subscriber in its own SUBSCRIBE_OK
// (draft SS10.7/SS11.1 -- Track Alias is scoped per session, so a
// publisher and each of its subscribers can legitimately disagree on the
// number). Using the hub's per-subscriber SUBSCRIBE_OK alias to resolve an
// incoming Object's sender is therefore wrong; every client in this fixed
// room instead PUBLISHes under a deterministic alias derived from its own
// candidate-list index, and resolves an incoming Object's sender from that
// same fixed table rather than from SUBSCRIBE_OK.
export function ownTrackAlias(localId: string): bigint {
  const idx = CANDIDATE_PARTICIPANT_IDS.indexOf(localId);
  return BigInt(idx < 0 ? 0 : idx);
}

export function participantForTrackAlias(trackAlias: bigint): string | undefined {
  return CANDIDATE_PARTICIPANT_IDS[Number(trackAlias)];
}

// --- certificate fingerprint pinning (same recipe as webtransport_chat) ---

export interface WebTransportConnectOptions {
  serverCertificateHashes?: { algorithm: "sha-256"; value: ArrayBuffer }[];
}

/** Parses colon/whitespace-tolerant SHA-256 hex fingerprints into the
 * WebTransport constructor's serverCertificateHashes option. Empty input
 * means "no pinning" (browser falls back to the WebPKI CA check), matching
 * webtransport_chat's fallback behavior. */
export function certHashesToWebTransportOptions(
  hexList: string[],
): WebTransportConnectOptions {
  if (hexList.length === 0) return {};
  const serverCertificateHashes = hexList.map((hex) => {
    const bytes = hexToBytes(hex.replace(/[^0-9a-fA-F]/g, ""));
    if (bytes.length !== 32) {
      throw new Error(
        `certificate hash must be 32 bytes (SHA-256), got ${bytes.length}`,
      );
    }
    return { algorithm: "sha-256" as const, value: bytes.buffer as ArrayBuffer };
  });
  return { serverCertificateHashes };
}

// --- chat Object wire framing (SUBGROUP_HEADER + one Object) --------------

export interface ChatObjectInput {
  trackAlias: bigint;
  groupId: bigint;
  text: string;
}

/** Builds one complete SUBGROUP stream payload carrying a single chat
 * message: SUBGROUP_HEADER (Track Alias, Group ID) followed by one Object
 * (Object ID Delta 0 -- FIRST_OBJECT makes the delta the absolute id). */
export function buildChatObjectMessage(input: ChatObjectInput): Uint8Array {
  const payload = utf8ToBytes(input.text);
  return concatBytes([
    encodeVarint(SUBGROUP_HEADER_TYPE),
    encodeVarint(input.trackAlias),
    encodeVarint(input.groupId),
    encodeVarint(0n), // Object ID Delta (first object -> absolute id 0)
    encodeVarint(BigInt(payload.length)),
    payload,
  ]);
}

export interface ParsedChatObject {
  trackAlias: bigint;
  groupId: bigint;
  text: string;
}

/** Inverse of buildChatObjectMessage: decodes a full SUBGROUP wire message
 * back into the track alias and chat text. Throws MoqtDecodeError on
 * malformed/truncated input. */
export function parseChatObjectMessage(wire: Uint8Array): ParsedChatObject {
  const { header, len } = decodeSubgroupHeader(wire);
  const { object } = decodeSubgroupObject(
    wire,
    len,
    header.flags.properties,
    0n,
    true,
  );
  return {
    trackAlias: header.trackAlias,
    groupId: header.groupId,
    text: bytesToUtf8(object.payload),
  };
}

// --- nickname self-announce (rides the same Object channel as chat) -------

// Rides in the chat Object's text (buildChatObjectMessage's own wire, no hub
// change): a marker no real chat message can produce by hand (NUL is not
// valid input to Compose's <input>), so parseNicknameFromChatText tells an
// announce apart from a normal message without a new SUBGROUP header field.
const NICKNAME_MARKER = "\u0000nick:";

export interface NicknameObjectInput {
  trackAlias: bigint;
  groupId: bigint;
  nickname: string;
}

/** Builds one self-announce message: same SUBGROUP_HEADER + Object framing
 * as buildChatObjectMessage, with the nickname marked so the receiver never
 * shows it in the chat log. */
export function buildNicknameObjectMessage(input: NicknameObjectInput): Uint8Array {
  if (!input.nickname) throw new Error("nickname must not be empty");
  return buildChatObjectMessage({
    trackAlias: input.trackAlias,
    groupId: input.groupId,
    text: NICKNAME_MARKER + input.nickname,
  });
}

/** Extracts the nickname from a parsed chat Object's text, or undefined if
 * it is an ordinary chat message. */
export function parseNicknameFromChatText(text: string): string | undefined {
  return text.startsWith(NICKNAME_MARKER) ? text.slice(NICKNAME_MARKER.length) : undefined;
}

/** Classifies a raw chat-track Object payload before it is decoded any
 * further: an attachment chunk/text-part carries a binary marker byte
 * (0xFD/0xFE) that is not a valid UTF-8 lead byte (RFC 3629 caps lead bytes
 * at 0xF4), so neither can ever collide with real chat text; the nickname
 * marker (NUL, 0x00) is likewise not producible by hand in the chat input.
 * #readChatObjectStream uses this to pick a decode path without running
 * binary attachment bytes through the UTF-8 decoder. */
export function classifyChatPayload(
  payload: Uint8Array,
): "text" | "nickname" | "attachment-text" | "attachment-chunk" {
  if (isAttachmentChunkPayload(payload)) return "attachment-chunk";
  if (isTextPartPayload(payload)) return "attachment-text";
  if (bytesToUtf8(payload).startsWith(NICKNAME_MARKER)) return "nickname";
  return "text";
}

// --- MOQT session over one WebTransport connection -------------------------

const ROOM_NAMESPACE = [utf8ToBytes("wired"), utf8ToBytes("moqt_chat")];

export interface ChatAttachment {
  bytes: Uint8Array;
  mimeType: string;
}

export interface MoqtChatCallbacks {
  onStatusChange(status: "connecting" | "connected" | "disconnected"): void;
  // Fires once per message, whether it carries attachments or not (a
  // plain-text message fires with attachments: []) -- the text-part and
  // attachment-chunk streams are reassembled into one call by
  // #pendingMessages before this ever runs (see the class doc below).
  // key ("<sender>:<messageId>") names the message across sessions: a
  // rejoin's history FETCH re-delivers messages already shown.
  onMessage(participantId: string, text: string, attachments: ChatAttachment[], key?: string): void;
  // A nickname self-announce (buildNicknameObjectMessage) from participantId
  // -- never forwarded to onMessage, so it never appears in the chat log.
  onNickname?(participantId: string, nickname: string): void;
  // Fires for an incoming uni stream whose SUBGROUP_HEADER's Track Alias is
  // not this client's chat candidate-list mapping -- the audio track uses a
  // separate alias range (moqtVoiceClient.ts's ownAudioTrackAlias), the
  // screen-share track sits above it (moqtScreenClient.ts's
  // SCREEN_ALIAS_OFFSET), and neither is read to completion here (audio is a
  // long-lived stream the publisher keeps appending Objects to). The
  // header is already decoded (avoids re-parsing it); firstChunkTail is
  // whatever bytes followed the header in the SAME first chunk (often the
  // stream's first Object, since MoqtVoiceClient.sendOpusFrame writes the
  // header and first Object in one write() call) -- it must be handed to
  // the caller's own incremental reader before anything further pulled
  // from `reader`, or that Object's bytes are silently lost. reader lets
  // the caller keep consuming the same stream from exactly where this
  // class stopped -- no bytes are skipped or duplicated.
  onUnknownUniStream?(
    header: SubgroupHeader,
    firstChunkTail: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): void;
  // The datagram counterpart to onUnknownUniStream: fires for an incoming
  // OBJECT_DATAGRAM whose Track Alias is outside the chat range (only the
  // audio track sends datagrams -- moqtVoiceClient.ts's sendOpusFrame). A
  // datagram is one whole Object, already decoded here; a malformed one is
  // dropped before this fires.
  onUnknownDatagram?(datagram: ObjectDatagram): void;
  // A NAMESPACE (active) or NAMESPACE_DONE (!active) from the room watch
  // (announce()): the suffix after wired/moqt_chat, e.g. ["user2"] for a
  // peer joining/leaving or ["user2", "screen"] for its screen share. Own
  // and out-of-pool ids never fire. A peer's chat subscription is already
  // handled here; the caller adds its own tracks (audio, screen).
  onNamespace?(suffix: string[], active: boolean): void;
  // The session is going away (draft-ietf-moq-transport-19 3.6): a GOAWAY on
  // the hub's control stream (uri = its New Session URI, "" to reuse the
  // current one) or the WebTransport session draining (uri ""). Fires at
  // most once per session; the caller reconnects.
  onGoaway?(uri: string): void;
}

/** A subscription's Joining FETCH (draft-ietf-moq-transport-19 10.12.2):
 * Relative, joiningStart Groups before the Joining Location. onObject sees
 * every fetched Object (End of Range markers skipped); onDone fires once,
 * when the fetch stream ends or no fetch happens at all (nothing published
 * yet, refused, failed). */
export interface JoiningFetch {
  joiningStart: bigint;
  onObject(object: FetchObject): void;
  onDone(): void;
}

type Reply = { type: bigint; body: Uint8Array };

/** One request stream (3.3). */
interface Request {
  requestId: bigint;
  /** The first answer, undefined if the stream ended without one. */
  first: Promise<Reply | undefined>;
  /** FIN our side: the request stays alive (3.3.2). */
  close(): void;
  /** Reset our side and stop reading: cancels the request (3.3.3). */
  cancel(): void;
}

/** SUBSCRIBE_OK's Largest Object (undefined: nothing published yet), or
 * null when the body does not decode. */
function subscribeOkLargest(body: Uint8Array): Location | undefined | null {
  try {
    return largestObjectOf(decodeSubscribeOk(body).parameters);
  } catch {
    return null;
  }
}

/** Hands every whole fetch Object in buffered to onObject (End of Range
 * markers are skipped) and returns the undecoded rest. */
function drainFetchObjects(
  buffered: Uint8Array,
  seq: FetchSeq,
  onObject: (o: FetchObject) => void,
): Uint8Array {
  let pos = 0;
  for (;;) {
    let item;
    try {
      item = decodeFetchObject(buffered, pos, seq);
    } catch {
      return buffered.slice(pos); // incomplete: wait for more bytes
    }
    pos += item.len;
    if (!item.object.endOfRange) onObject(item.object);
  }
}

/** Feeds every whole control message the reader yields to onFrame, until
 * the stream ends or fails. */
async function readControlFrames(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  onFrame: (r: Reply) => void,
): Promise<void> {
  let buffered: Uint8Array = new Uint8Array(0);
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buffered = concatBytes([buffered, value]);
      let offset = 0;
      for (;;) {
        let decoded;
        try {
          decoded = decodeControlFrame(buffered, offset);
        } catch {
          break; // not enough bytes yet for the next message
        }
        onFrame(decoded.frame);
        offset += decoded.len;
      }
      buffered = buffered.slice(offset);
    }
  } catch {
    // reset or cancelled: the request is over
  }
}

// A message's text-part and attachment-chunk streams can arrive in either
// order (or interleaved with other messages), so one message's delivery is
// buffered here, keyed by `${participantId}:${messageId}`, until both the
// text and every attachment have arrived -- then onMessage fires once and
// the entry is removed. A PendingMessage stale for more than this long is
// dropped the next time any text-part/attachment-chunk is handled (no
// separate sweep timer -- see moqtAttachmentWire.ts's own per-chunk
// ATTACHMENT_TIMEOUT_MS, which this mirrors for the whole-message case).
const PENDING_MESSAGE_TIMEOUT_MS = 30_000;

interface PendingMessage {
  text?: string;
  attachmentCount: number;
  attachments: Map<number, ChatAttachment>;
  receivedAt: number;
}

// A fixed starting point (e.g. 1) collides across page reloads: a receiver
// can still hold a pending (attachment-only) entry keyed by a messageId the
// previous session used, and a fresh session restarting from the same value
// would have its own unrelated text-only send absorbed into that stale
// entry's leftover attachments. Seeding from crypto.getRandomValues instead
// makes a same-id collision between two independent sessions vanishingly
// unlikely, matching what #pendingKey's own doc assumes ("messageId re-use
// needs no explicit cleanup" -- true only if re-use is rare).
function randomMessageIdSeed(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0];
}

/** Drives one chat participant's MOQT session: connects, PUBLISHes its own
 * track, announces itself and follows the room through namespace discovery,
 * and relays incoming SUBGROUP / FETCH Objects to onMessage. */
export class MoqtChatClient {
  #wt?: WebTransport;
  #localId: string;
  #localTrackAlias: bigint;
  #groupId = 0n;
  #nextMessageId = randomMessageIdSeed();
  #attachmentReassemblers = new Map<string, AttachmentReassembler>();
  #pendingMessages = new Map<string, PendingMessage>();
  // Client-initiated Request IDs are even (draft-ietf-moq-transport-19 10.1).
  #nextRequestId = 0n;
  // Every SUBSCRIBE by its caller's label ("user2", "user2/audio", ...):
  // in flight or established. A label is never subscribed twice at once.
  #subs = new Map<string, Promise<Request | undefined>>();
  #subscribed = new Set<string>();
  // Joining FETCHes by Request ID, until their data stream ends.
  #fetches = new Map<bigint, JoiningFetch>();
  #callbacks: MoqtChatCallbacks;

  constructor(localId: string, callbacks: MoqtChatCallbacks) {
    this.#localId = localId;
    this.#localTrackAlias = ownTrackAlias(localId);
    this.#callbacks = callbacks;
  }

  async connect(url: string, certHashesHex: string[]): Promise<void> {
    this.#callbacks.onStatusChange("connecting");
    const opts = certHashesToWebTransportOptions(certHashesHex);
    const wt = new WebTransport(url, opts);
    this.#wt = wt;
    // On a failed attempt `closed` rejects alongside `ready`, and nothing
    // below ever subscribes to it (#onClosed is attached only once the
    // session is up) -- without this no-op handler every failed attempt
    // logs an uncaught WebTransportError in the browser.
    wt.closed.catch(() => {});
    try {
      await wt.ready;

      // Transport-level death detection (hub crash/restart, network loss):
      // both settle paths of `closed` funnel into #onClosed, which reports
      // "disconnected" exactly once per session (stale epochs are ignored).
      // Subscribed only once ready succeeded: a failed attempt's one
      // "disconnected" is the rejection below, and the browser promises no
      // order between the ready and closed rejections.
      wt.closed.then(
        () => this.#onClosed(wt),
        () => this.#onClosed(wt),
      );

      this.#nextRequestId = 0n;
      this.#subs.clear();
      this.#subscribed.clear();
      this.#fetches.clear();
      this.#readIncomingUniStreams();
      this.#readIncomingDatagrams();
      // WebTransport.draining (draft-ietf-webtrans-http3-15 4.7): the
      // server asked the session to wind down.
      void (wt as { draining?: Promise<void> }).draining?.then(() => this.#goAway(wt, ""));
      await this.#openControlStream();
      await this.publishTrack(utf8ToBytes(this.#localId), this.#localTrackAlias);

      this.#callbacks.onStatusChange("connected");
    } catch (err) {
      // A failed attempt reports "disconnected" through this rejection
      // (the caller's own failure handling); stale the transport first so
      // its closed settling does not report a second one for the session.
      if (this.#wt === wt) {
        this.#wt = undefined;
        wt.close();
      }
      throw err;
    }
  }

  /** The underlying WebTransport session, once connected -- exported so
   * moqtVoiceClient.ts can open its own long-lived uni stream for the audio
   * track's Objects without this class re-exposing a send/receive API for
   * every future track type. */
  get webTransport(): WebTransport | undefined {
    return this.#wt;
  }

  get localId(): string {
    return this.#localId;
  }

  /** Sends this client's nickname self-announce once, over the same Object
   * channel as chat -- see moqtClient.ts's own doc on why no hub change is
   * needed. No-op for an empty nickname (the "don't use the feature" case). */
  async sendNickname(nickname: string): Promise<void> {
    if (!this.#wt || !nickname) return;
    const wire = buildNicknameObjectMessage({
      trackAlias: this.#localTrackAlias,
      groupId: this.#groupId++,
      nickname,
    });
    await this.#sendUniStream(wire);
  }

  /** Sends one chat message: one text-part uni stream, then one uni stream
   * per attachment carrying every chunk as consecutive Objects
   * (splitAttachmentIntoChunks, moqtAttachmentWire.ts). All streams share
   * one messageId so the receiving end's #pendingMessages can regroup them
   * regardless of arrival order. */
  async sendMessage(text: string, attachments: ChatAttachment[]): Promise<void> {
    if (!this.#wt) return;
    const messageId = this.#nextMessageId++;
    await this.#sendTextPart(messageId, attachments.length, text);
    for (let i = 0; i < attachments.length; i++) {
      await this.#sendAttachment(messageId, i, attachments[i]);
    }
  }

  async #sendTextPart(messageId: number, attachmentCount: number, text: string): Promise<void> {
    const body = encodeTextPartMessage(messageId, attachmentCount, text);
    const wire = concatBytes([
      buildAttachmentSubgroupHeader(this.#localTrackAlias, this.#groupId++),
      concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]),
    ]);
    await this.#sendUniStream(wire);
  }

  async #sendAttachment(
    messageId: number,
    attachmentIdx: number,
    attachment: ChatAttachment,
  ): Promise<void> {
    const chunks = splitAttachmentIntoChunks(
      messageId,
      attachmentIdx,
      attachment.mimeType,
      attachment.bytes,
    );
    // One SUBGROUP_HEADER, then every chunk as its own Object: Object ID
    // Delta 0 on each (FIRST_OBJECT makes the first one absolute, the
    // decoder's prevId + delta + 1 rule increments the rest, exactly as
    // moqtScreenClient.ts's sendVideoChunk does) + Length + body --
    // encodeAttachmentChunkMessage only encodes the payload bytes.
    const objects = chunks.map((chunk) => {
      const body = encodeAttachmentChunkMessage(chunk);
      return concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    });
    await this.#sendUniStream(
      concatBytes([
        buildAttachmentSubgroupHeader(this.#localTrackAlias, this.#groupId++),
        ...objects,
      ]),
    );
  }

  async #sendUniStream(wire: Uint8Array): Promise<void> {
    if (!this.#wt) return;
    const stream = await this.#wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    try {
      await writer.write(wire);
    } finally {
      await writer.close();
    }
  }

  close(): void {
    const wt = this.#wt;
    if (!wt) return; // already down -- its "disconnected" was reported once
    this.#wt = undefined; // stale first: our own closed settling reports nothing
    wt.close();
    this.#callbacks.onStatusChange("disconnected");
  }

  // The transport died out from under us. A settling for anything but the
  // CURRENT transport is stale -- a close()d session's own wind-down or a
  // replaced epoch after a reconnect -- and reports nothing.
  #onClosed(wt: WebTransport): void {
    if (this.#wt !== wt) return;
    this.#wt = undefined;
    this.#callbacks.onStatusChange("disconnected");
  }

  // The hub opens this stream itself right after the session is
  // established (draft 3.3 / moqtrun.c wired_moqt_on_session) and sends
  // SETUP on it. Requests never ride it (each has its own stream); the one
  // message acted on is a session-wide GOAWAY (draft 10.4).
  async #openControlStream(): Promise<void> {
    const wt = this.#wt;
    if (!wt) return;
    const reader = wt.incomingBidirectionalStreams.getReader();
    const { value: stream, done } = await reader.read();
    reader.releaseLock();
    if (done || !stream) throw new Error("hub did not open a control stream");
    void readControlFrames(stream.readable.getReader(), ({ type, body }) => {
      if (type !== MSG_TYPE_GOAWAY) return;
      let uri = "";
      try {
        uri = bytesToUtf8(decodeGoaway(body).newSessionUri);
      } catch {
        // a malformed GOAWAY still means "go": reconnect to the same URI
      }
      this.#goAway(wt, uri);
    });
  }

  #goneAway?: WebTransport;

  // Reports the session's first going-away signal; a stale or closed
  // session's, or a second one, reports nothing.
  #goAway(wt: WebTransport, uri: string): void {
    if (this.#wt !== wt || this.#goneAway === wt) return;
    this.#goneAway = wt;
    this.#callbacks.onGoaway?.(uri);
  }

  // Opens one request stream (draft 3.3) and writes the request built for
  // its fresh even Request ID; fin also ends our side right away (a FETCH
  // has nothing more to say). The first answer resolves `first`; every
  // later message on the stream goes to onLater.
  async #request(
    type: bigint,
    build: (requestId: bigint) => Uint8Array,
    onLater: (r: Reply) => void = () => {},
    fin = false,
  ): Promise<Request | undefined> {
    const wt = this.#wt;
    if (!wt) return undefined;
    const requestId = this.#nextRequestId;
    this.#nextRequestId += 2n;
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    let resolveFirst: ((r: Reply | undefined) => void) | undefined;
    const first = new Promise<Reply | undefined>((resolve) => (resolveFirst = resolve));
    void readControlFrames(reader, (r) => {
      if (!resolveFirst) return onLater(r);
      resolveFirst(r);
      resolveFirst = undefined;
    }).finally(() => resolveFirst?.(undefined));
    await writer.write(encodeControlFrame(type, build(requestId)));
    if (fin) await writer.close();
    return {
      requestId,
      first,
      close: () => void writer.close().catch(() => {}),
      cancel: () => {
        void writer.abort().catch(() => {});
        void reader.cancel().catch(() => {});
      },
    };
  }

  /** PUBLISHes a track under this room's fixed namespace (moqtVoiceClient
   * and moqtScreenClient PUBLISH "<id>/audio" / "<id>/screen" through it).
   * Resolves true once the hub answers REQUEST_OK, so a namespace announced
   * after it only ever names tracks a subscriber can already find. */
  async publishTrack(trackName: Uint8Array, trackAlias: bigint): Promise<boolean> {
    const req = await this.#request(MSG_TYPE_PUBLISH, (requestId) =>
      encodePublish({
        requestId,
        trackNamespace: ROOM_NAMESPACE,
        trackName,
        trackAlias,
        parameters: [],
        trackProperties: [],
      }),
    );
    const reply = await req?.first;
    if (reply?.type === MSG_TYPE_REQUEST_OK) return true;
    req?.close();
    return false;
  }

  /** Whether the SUBSCRIBE sent under this label (a participant id for
   * chat, or "<id>/audio", "<id>/screen") has been answered SUBSCRIBE_OK on
   * this session. */
  isSubscribed(label: string): boolean {
    return this.#subscribed.has(label);
  }

  /** SUBSCRIBEs to a track under this room's namespace, once per label at
   * a time: a label already in flight or established is not sent again,
   * and a refused one (REQUEST_ERROR) may be. With history, the SUBSCRIBE
   * starts at the Largest Object and a Relative Joining FETCH fills in the
   * Groups before it (draft 10.12.2). */
  async subscribeTrack(trackName: Uint8Array, label: string, history?: JoiningFetch): Promise<void> {
    if (this.#subs.has(label)) return;
    const pending = this.#request(MSG_TYPE_SUBSCRIBE, (requestId) =>
      encodeSubscribe({
        requestId,
        trackNamespace: ROOM_NAMESPACE,
        trackName,
        parameters: history ? [LARGEST_OBJECT_FILTER] : [],
      }),
    );
    this.#subs.set(label, pending);
    const req = await pending;
    const reply = await req?.first;
    const largest = req && reply?.type === MSG_TYPE_SUBSCRIBE_OK ? subscribeOkLargest(reply.body) : null;
    if (largest === null) {
      if (this.#subs.get(label) === pending) this.#subs.delete(label);
      req?.close();
      history?.onDone();
      return;
    }
    this.#subscribed.add(label);
    if (!history) return;
    if (largest) void this.#joiningFetch(req!.requestId, history);
    else history.onDone();
  }

  async #joiningFetch(subscribeRequestId: bigint, history: JoiningFetch): Promise<void> {
    let fetchId = -1n;
    const req = await this.#request(
      MSG_TYPE_FETCH,
      (requestId) => {
        fetchId = requestId;
        // Registered before the request goes out: its Objects may arrive
        // before FETCH_OK (draft 10.13).
        this.#fetches.set(requestId, history);
        return encodeFetch({
          requestId,
          fetchType: 2n,
          joiningRequestId: subscribeRequestId,
          joiningStart: history.joiningStart,
          parameters: [],
        });
      },
      undefined,
      true,
    );
    const reply = await req?.first;
    if (reply?.type === MSG_TYPE_FETCH_OK) return;
    if (this.#fetches.delete(fetchId)) history.onDone();
  }

  /** PUBLISH_NAMESPACEs wired/moqt_chat/<suffix...>; the returned handle's
   * cancel() withdraws it (draft 3.3.3: a reset, not a FIN). */
  async publishNamespace(suffix: string[]): Promise<{ cancel(): void } | undefined> {
    return this.#request(MSG_TYPE_PUBLISH_NAMESPACE, (requestId) =>
      encodeNamespaceRequest({
        requestId,
        namespace: [...ROOM_NAMESPACE, ...suffix.map(utf8ToBytes)],
        parameters: [],
      }),
    );
  }

  /** Joins the room's discovery: announces wired/moqt_chat/<own id> and
   * watches the wired/moqt_chat prefix (draft 6.1-6.2). Call once every
   * track a peer should find is PUBLISHed. */
  async announce(): Promise<void> {
    await this.publishNamespace([this.#localId]);
    await this.#request(
      MSG_TYPE_SUBSCRIBE_NAMESPACE,
      (requestId) => encodeNamespaceRequest({ requestId, namespace: ROOM_NAMESPACE, parameters: [] }),
      (r) => this.#onNamespacePush(r),
    );
  }

  #onNamespacePush({ type, body }: Reply): void {
    if (type !== MSG_TYPE_NAMESPACE && type !== MSG_TYPE_NAMESPACE_DONE) return;
    let suffix: string[];
    try {
      suffix = decodeNamespaceSuffix(body).map(bytesToUtf8);
    } catch {
      return;
    }
    const peer = suffix[0];
    if (peer === this.#localId || !CANDIDATE_PARTICIPANT_IDS.includes(peer)) return;
    const active = type === MSG_TYPE_NAMESPACE;
    if (suffix.length === 1 && active) void this.#subscribeChat(peer);
    if (suffix.length === 1 && !active) this.#dropPeer(peer);
    this.#callbacks.onNamespace?.(suffix, active);
  }

  #subscribeChat(peer: string): Promise<void> {
    return this.subscribeTrack(utf8ToBytes(peer), peer, {
      joiningStart: CHAT_HISTORY_GROUPS,
      onObject: (o) => this.#dispatchChatPayload(peer, o.payload),
      onDone: () => {},
    });
  }

  // The peer left: every subscription to it is cancelled (draft 3.3.3),
  // freeing the hub's request slots; a rejoin subscribes afresh.
  #dropPeer(peer: string): void {
    for (const [label, pending] of this.#subs) {
      if (label !== peer && !label.startsWith(`${peer}/`)) continue;
      this.#subs.delete(label);
      this.#subscribed.delete(label);
      void pending.then((req) => req?.cancel());
    }
  }

  // A FETCH data stream (draft 11.4.4): FETCH_HEADER names the request,
  // then fetch Objects until FIN. An unknown Request ID is not ours.
  async #readFetchStream(first: Uint8Array, reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
    const head = decodeFetchHeader(first);
    const history = this.#fetches.get(head.requestId);
    if (!history) {
      void reader.cancel().catch(() => {});
      return;
    }
    let buffered: Uint8Array = first.slice(head.len);
    const seq = newFetchSeq();
    try {
      for (;;) {
        buffered = drainFetchObjects(buffered, seq, history.onObject);
        const { value, done } = await reader.read();
        if (done) break;
        buffered = concatBytes([buffered, value]);
      }
    } finally {
      this.#fetches.delete(head.requestId);
      history.onDone();
    }
  }

  async #readIncomingUniStreams(): Promise<void> {
    if (!this.#wt) return;
    const reader = this.#wt.incomingUnidirectionalStreams.getReader();
    for (;;) {
      const { value: stream, done } = await reader.read();
      if (done || !stream) break;
      this.#readOneUniStream(stream).catch(() => {
        /* a malformed/aborted stream is dropped, not fatal to the session */
      });
    }
  }

  // Same alias routing as #readOneUniStream, over the session's datagram
  // path: only the audio track sends OBJECT_DATAGRAMs (chat and every other
  // track are stream-borne), so a chat-range alias here has no consumer and
  // is dropped, and anything else goes to onUnknownDatagram. A datagram
  // that does not decode is dropped, not fatal to the session.
  async #readIncomingDatagrams(): Promise<void> {
    const datagrams = this.#wt?.datagrams;
    if (!datagrams) return;
    const reader = datagrams.readable.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done || !value) break;
      this.#routeDatagram(value);
    }
  }

  #routeDatagram(bytes: Uint8Array): void {
    let datagram;
    try {
      datagram = decodeObjectDatagram(bytes);
    } catch {
      return;
    }
    if (datagram.trackAlias >= BigInt(CANDIDATE_PARTICIPANT_IDS.length)) {
      this.#callbacks.onUnknownDatagram?.(datagram);
    }
  }

  // Reads only enough of the stream to decode its SUBGROUP_HEADER (assumed
  // to arrive whole in the first chunk -- it is a handful of bytes, always
  // written in one call by both buildChatObjectMessage and
  // buildVoiceSubgroupHeader), then routes by Track Alias: a chat alias
  // (0..N-1, this room's candidate-list range) is read to completion and
  // its chat Objects parsed; anything else (the audio track's separate
  // alias range, moqtVoiceClient.ts's ownAudioTrackAlias, or the screen
  // track's alias range, moqtScreenClient.ts) is handed to onUnknownUniStream
  // instead of read to EOF here.
  async #readOneUniStream(stream: ReadableStream<Uint8Array>): Promise<void> {
    const reader = stream.getReader();
    const { value: first, done } = await reader.read();
    if (done || !first || first.length === 0) {
      reader.releaseLock();
      return;
    }
    if (decodeVarint(first).value === STREAM_TYPE_FETCH_HEADER) {
      await this.#readFetchStream(first, reader);
      return;
    }
    let header;
    let headerLen;
    try {
      const decoded = decodeSubgroupHeader(first);
      header = decoded.header;
      headerLen = decoded.len;
    } catch {
      reader.releaseLock();
      return;
    }
    if (header.trackAlias >= BigInt(CANDIDATE_PARTICIPANT_IDS.length)) {
      this.#callbacks.onUnknownUniStream?.(header, first.slice(headerLen), reader);
      return;
    }
    await this.#readChatObjectStream(first, reader);
  }

  async #readChatObjectStream(
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): Promise<void> {
    const wire = await readToEof(firstChunk, reader);

    // Decode only the SUBGROUP_HEADER + Object framing here -- NOT via
    // parseChatObjectMessage, which also UTF-8-decodes the payload and
    // would corrupt/throw on binary image-chunk bytes (classifyChatPayload's
    // own doc on why the marker byte must be checked first). A text or
    // nickname stream carries one Object; an attachment stream carries one
    // per chunk, so walk them all. A torn trailing Object ends the walk --
    // whatever decoded before it still counts.
    let header;
    let offset;
    try {
      const decoded = decodeSubgroupHeader(wire);
      header = decoded.header;
      offset = decoded.len;
    } catch {
      return;
    }
    // ownTrackAlias's doc: resolve the sender from the fixed candidate-list
    // mapping (the publisher's own alias, unmodified by relay), not from
    // this session's SUBSCRIBE_OK aliases.
    const participant = participantForTrackAlias(header.trackAlias);
    if (!participant) return;

    let prevObjectId = 0n;
    let first = true;
    while (offset < wire.length) {
      let payload: Uint8Array;
      try {
        const { object, len } = decodeSubgroupObject(wire, offset, header.flags.properties, prevObjectId, first);
        payload = object.payload;
        prevObjectId = object.objectId;
        offset += len;
        first = false;
      } catch {
        return;
      }
      this.#dispatchChatPayload(participant, payload);
    }
  }

  #dispatchChatPayload(participant: string, payload: Uint8Array): void {
    const kind = classifyChatPayload(payload);
    if (kind === "attachment-chunk") {
      this.#handleAttachmentChunkPayload(participant, payload);
      return;
    }
    if (kind === "attachment-text") {
      this.#handleTextPartPayload(participant, payload);
      return;
    }
    const text = bytesToUtf8(payload);
    if (kind === "nickname") {
      this.#callbacks.onNickname?.(participant, parseNicknameFromChatText(text) ?? "");
      return;
    }
    this.#callbacks.onMessage(participant, text, []);
  }

  // Key for both #pendingMessages and #attachmentMimeTypes: one message's
  // reassembly state must never be confused with another participant's or
  // another messageId's, and a delivered/timed-out messageId's key simply
  // stops being looked up -- Map holds no memory of it (brief's own
  // "messageId re-use needs no explicit cleanup" note).
  #pendingKey(participant: string, messageId: number): string {
    return `${participant}:${messageId}`;
  }

  #pendingFor(participant: string, messageId: number): PendingMessage {
    const key = this.#pendingKey(participant, messageId);
    let pending = this.#pendingMessages.get(key);
    if (!pending) {
      // attachmentCount stays 0 until the text part sets the real count;
      // an attachment-chunk-only arrival never completes on its own (the
      // completion check there also requires pending.text !== undefined).
      pending = { attachmentCount: 0, attachments: new Map(), receivedAt: Date.now() };
      this.#pendingMessages.set(key, pending);
    }
    return pending;
  }

  // Attachments can complete reassembly in any order; onMessage always
  // sees them in attachmentIdx order (the order sendMessage sent them in).
  #orderedAttachments(pending: PendingMessage): ChatAttachment[] {
    return [...pending.attachments.entries()].sort(([a], [b]) => a - b).map(([, v]) => v);
  }

  // A PendingMessage sits waiting for its sibling streams indefinitely
  // otherwise (e.g. the text part never arrives). Swept lazily on every
  // text-part/attachment-chunk delivery, mirroring moqtAttachmentWire.ts's
  // own per-chunk pruning -- no dedicated timer (YAGNI).
  #pruneExpiredMessages(now: number): void {
    for (const [key, pending] of this.#pendingMessages) {
      if (now - pending.receivedAt >= PENDING_MESSAGE_TIMEOUT_MS) {
        this.#pendingMessages.delete(key);
        // M1: an idx===0 chunk's mimeType recorded for this message (below)
        // outlives the message itself otherwise -- #attachmentMimeTypes has
        // no timeout of its own, so a message that never completes would
        // leak one entry per attachment forever.
        const prefix = `${key}:`;
        for (const mimeKey of this.#attachmentMimeTypes.keys()) {
          if (mimeKey.startsWith(prefix)) this.#attachmentMimeTypes.delete(mimeKey);
        }
      }
    }
  }

  #handleTextPartPayload(participant: string, payload: Uint8Array): void {
    let parsed;
    try {
      parsed = decodeTextPartMessage(payload);
    } catch {
      return;
    }
    // I1(a): a text-part claiming more attachments than this app ever sends
    // is untrusted input -- dropped whole, same silent-drop pattern as a
    // decode failure above.
    if (parsed.attachmentCount > ATTACHMENT_MAX_COUNT) return;
    const now = Date.now();
    this.#pruneExpiredMessages(now);

    const key = this.#pendingKey(participant, parsed.messageId);
    const pending = this.#pendingFor(participant, parsed.messageId);
    pending.text = parsed.text;
    pending.attachmentCount = parsed.attachmentCount;
    pending.receivedAt = now;

    if (pending.attachments.size >= pending.attachmentCount) {
      this.#pendingMessages.delete(key);
      this.#callbacks.onMessage(participant, pending.text, this.#orderedAttachments(pending), key);
    }
  }

  // messageId:attachmentIdx -> mimeType, held only between an attachment's
  // idx===0 chunk (the only one carrying mimeType) and that attachment's
  // reassembly completing -- attachmentReassemblerPush itself returns just
  // the concatenated bytes (moqtAttachmentWire.ts), not the mimeType.
  #attachmentMimeTypes = new Map<string, string>();

  #handleAttachmentChunkPayload(participant: string, payload: Uint8Array): void {
    let chunk;
    try {
      chunk = decodeAttachmentChunkMessage(payload);
    } catch {
      return;
    }
    // I1(b2): once the text part has confirmed this message's real
    // attachmentCount, a chunk claiming an attachmentIdx outside that
    // confirmed range is untrusted (attachmentReassemblerPush's own
    // isTrustedChunk already rejects attachmentIdx >= ATTACHMENT_MAX_COUNT
    // unconditionally -- this is the tighter, message-specific bound).
    const knownPending = this.#pendingMessages.get(this.#pendingKey(participant, chunk.messageId));
    if (knownPending?.text !== undefined && chunk.attachmentIdx >= knownPending.attachmentCount) {
      return;
    }
    if (chunk.idx === 0 && chunk.mimeType !== undefined) {
      this.#attachmentMimeTypes.set(
        `${participant}:${chunk.messageId}:${chunk.attachmentIdx}`,
        chunk.mimeType,
      );
    }

    let reassembler = this.#attachmentReassemblers.get(participant);
    if (!reassembler) {
      reassembler = attachmentReassemblerInit();
      this.#attachmentReassemblers.set(participant, reassembler);
    }
    const bytes = attachmentReassemblerPush(reassembler, chunk);
    if (!bytes) return;

    const mimeKey = `${participant}:${chunk.messageId}:${chunk.attachmentIdx}`;
    const mimeType = this.#attachmentMimeTypes.get(mimeKey) ?? "";
    this.#attachmentMimeTypes.delete(mimeKey);

    const now = Date.now();
    this.#pruneExpiredMessages(now);

    const key = this.#pendingKey(participant, chunk.messageId);
    const pending = this.#pendingFor(participant, chunk.messageId);
    pending.attachments.set(chunk.attachmentIdx, { bytes, mimeType });
    pending.receivedAt = now;

    if (pending.text !== undefined && pending.attachments.size >= pending.attachmentCount) {
      this.#pendingMessages.delete(key);
      this.#callbacks.onMessage(participant, pending.text, this.#orderedAttachments(pending), key);
    }
  }
}
