// MOQT chat transport: wires the browser WebTransport API to the
// draft-ietf-moq-transport-19 codec in moqtWire.ts, matching the fixed hub
// protocol implemented by wired_server (examples/moqt_chat/wired_server.c,
// src/app/moqt/run/moqtrun.c):
//
//  - The hub opens ONE server-initiated bidirectional stream per session and
//    sends SETUP on it (draft 3.3). The client does not reply with its own
//    SETUP; it reuses that same stream to send PUBLISH and SUBSCRIBE request
//    messages (moqtrun.c dispatches every message on that stream through the
//    same control handler, keyed only by Message Type).
//  - PUBLISH is accepted unconditionally; the hub replies REQUEST_OK.
//  - SUBSCRIBE is matched against another peer's already-PUBLISHed Track
//    Name and answered with SUBSCRIBE_OK or REQUEST_ERROR, in the order the
//    hub received the requests (it replies synchronously per message, SS10
//    control stream). No discovery messages exist in this subset, so this
//    client tries a fixed pool of candidate participant ids and remembers
//    which one each in-flight SUBSCRIBE was for, to pair it with the
//    resulting SUBSCRIBE_OK's Track Alias (or drop it on REQUEST_ERROR).
//  - Chat messages are sent as one uni stream each: SUBGROUP_HEADER + one
//    Object (1 message = 1 Object = 1 Group = 1 Subgroup), matching
//    moqdata.h's quic_moqdata_msg_build layout on the server side.

import {
  bytesToUtf8,
  concatBytes,
  decodeControlFrame,
  decodeSubgroupHeader,
  decodeSubgroupObject,
  decodeSubscribeOk,
  encodeControlFrame,
  encodePublish,
  encodeSubscribe,
  encodeVarint,
  hexToBytes,
  utf8ToBytes,
} from "./moqtWire";

// draft-ietf-moq-transport-19 SS10 message type IDs used on the wire here.
const MSG_TYPE_PUBLISH = 0x1dn;
const MSG_TYPE_SUBSCRIBE = 0x3n;
const MSG_TYPE_SUBSCRIBE_OK = 0x4n;
const MSG_TYPE_REQUEST_ERROR = 0x5n;

// SUBGROUP_HEADER Type (moqdata.h QUIC_MOQDATA_MSG builder): PROPERTIES off,
// SUBGROUP_ID_MODE 0b00, no end-of-group, DEFAULT_PRIORITY on, FIRST_OBJECT
// on: 0x10 (base) | 0x40 (FIRST_OBJECT) | 0x20 (DEFAULT_PRIORITY) = 0x70.
const SUBGROUP_HEADER_TYPE = 0x70n;

// Fixed candidate pool: no track-namespace discovery exists in this subset
// (moqtrun.h M5-6), so the client guesses room members from a small fixed
// list and lets REQUEST_ERROR/DOES_NOT_EXIST tell it which ones are absent.
// ponytail: raise/replace with real discovery if the room ever needs more.
const CANDIDATE_PARTICIPANT_IDS = ["user1", "user2", "user3", "user4"];

export function candidateParticipantIds(localId: string): string[] {
  return CANDIDATE_PARTICIPANT_IDS.filter((id) => id !== localId);
}

// moqtrun.c relays a publisher's SUBGROUP bytes unmodified (T-146): the
// Track Alias a subscriber sees on the wire is the PUBLISHER's own alias,
// not the alias the hub assigned that subscriber in its own SUBSCRIBE_OK
// (draft SS10.7/SS11.1 -- Track Alias is scoped per session, so a
// publisher and each of its subscribers can legitimately disagree on the
// number). Using the hub's per-subscriber SUBSCRIBE_OK alias to resolve an
// incoming Object's sender is therefore wrong; every client in this fixed
// room instead PUBLISHes under a deterministic alias derived from its own
// candidate-list index, and resolves an incoming Object's sender from that
// same fixed table rather than from SUBSCRIBE_OK.
function ownTrackAlias(localId: string): bigint {
  const idx = CANDIDATE_PARTICIPANT_IDS.indexOf(localId);
  return BigInt(idx < 0 ? 0 : idx);
}

function participantForTrackAlias(trackAlias: bigint): string | undefined {
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

// --- MOQT session over one WebTransport connection -------------------------

const ROOM_NAMESPACE = [utf8ToBytes("wired"), utf8ToBytes("moqt_chat")];

export interface MoqtChatCallbacks {
  onStatusChange(status: "connecting" | "connected" | "disconnected"): void;
  onMessage(participantId: string, text: string): void;
}

/** Drives one chat participant's MOQT session: connects, PUBLISHes its own
 * track, SUBSCRIBEs to the fixed candidate pool, and relays incoming
 * SUBGROUP Objects to onMessage. The pure wire-framing helpers above
 * (buildChatObjectMessage/parseChatObjectMessage/candidateParticipantIds/
 * certHashesToWebTransportOptions) are what moqtClient.test.ts exercises;
 * this class is the network-facing glue around them and is out of scope for
 * unit testing (no fake WebTransport in this subset -- see the report). */
// How often to retry SUBSCRIBE for a candidate that hasn't PUBLISHed yet
// (see #retrySubscribes' doc for why this exists at all).
const SUBSCRIBE_RETRY_MS = 1000;

// How long a SUBSCRIBE may sit in #pendingSubscribes with no reply before
// it is treated as lost and retried (see #retrySubscribes' own doc on why
// a reply can be delayed indefinitely on the hub side, not just dropped).
// Comfortably above SUBSCRIBE_RETRY_MS so a reply that is merely running a
// tick or two late is not resent needlessly.
const SUBSCRIBE_PENDING_TIMEOUT_MS = 3000;

export class MoqtChatClient {
  #wt?: WebTransport;
  #controlWriter?: WritableStreamDefaultWriter<Uint8Array>;
  #localId: string;
  #localTrackAlias: bigint;
  #groupId = 0n;
  #foundParticipants = new Set<string>();
  #retryTimer?: ReturnType<typeof setInterval>;
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
    await wt.ready;

    this.#readIncomingUniStreams();
    await this.#openControlStream();
    await this.#publishOwnTrack();
    await this.#subscribeToCandidates();
    this.#retryTimer = setInterval(() => this.#retrySubscribes(), SUBSCRIBE_RETRY_MS);

    this.#callbacks.onStatusChange("connected");
  }

  async send(text: string): Promise<void> {
    if (!this.#wt) return;
    const wire = buildChatObjectMessage({
      trackAlias: this.#localTrackAlias,
      groupId: this.#groupId++,
      text,
    });
    const stream = await this.#wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    try {
      await writer.write(wire);
    } finally {
      await writer.close();
    }
  }

  close(): void {
    clearInterval(this.#retryTimer);
    this.#wt?.close();
    this.#callbacks.onStatusChange("disconnected");
  }

  // The hub opens this stream itself right after the session is
  // established (draft 3.3 / moqtrun.c wired_moqt_on_session); the client
  // only needs to pick it up from incomingBidirectionalStreams and reuse it
  // for PUBLISH/SUBSCRIBE. Its readable side is drained in the background
  // for SUBSCRIBE_OK/REQUEST_ERROR replies.
  async #openControlStream(): Promise<void> {
    if (!this.#wt) return;
    const reader = this.#wt.incomingBidirectionalStreams.getReader();
    const { value: stream, done } = await reader.read();
    reader.releaseLock();
    if (done || !stream) throw new Error("hub did not open a control stream");
    this.#controlWriter = stream.writable.getWriter();
    this.#readControlReplies(stream.readable);
  }

  async #publishOwnTrack(): Promise<void> {
    if (!this.#controlWriter) return;
    const body = encodePublish({
      requestId: 0n,
      trackNamespace: ROOM_NAMESPACE,
      trackName: utf8ToBytes(this.#localId),
      trackAlias: this.#localTrackAlias,
      parameters: [],
      trackProperties: [],
    });
    await this.#controlWriter.write(encodeControlFrame(MSG_TYPE_PUBLISH, body));
  }

  // Requests answered in send order (the hub replies synchronously per
  // message on this stream), so a FIFO queue pairs each SUBSCRIBE_OK/
  // REQUEST_ERROR with the candidate participant id it was sent for.
  // sentAt backs the pending-timeout retry (#retrySubscribes' own doc): a
  // reply the hub could not send yet (its control stream's previous round
  // still unacknowledged) can be delayed past the next few
  // SUBSCRIBE_RETRY_MS ticks, not just dropped -- without a timeout this
  // entry would block #retrySubscribes from ever resending it.
  #pendingSubscribes: { candidate: string; sentAt: number }[] = [];
  #nextRequestId = 1n;

  // Builds one SUBSCRIBE control frame's bytes for candidate and queues it
  // in #pendingSubscribes, without writing anything -- callers batch one or
  // more of these into a single #controlWriter.write() (see
  // #subscribeToCandidates/#subscribeTo's doc for why a single write matters
  // here).
  #buildSubscribeFrame(candidate: string): Uint8Array {
    const rid = this.#nextRequestId++;
    const body = encodeSubscribe({
      requestId: rid,
      trackNamespace: ROOM_NAMESPACE,
      trackName: utf8ToBytes(candidate),
      parameters: [],
    });
    this.#pendingSubscribes.push({ candidate, sentAt: Date.now() });
    return encodeControlFrame(MSG_TYPE_SUBSCRIBE, body);
  }

  // moqtrun.c's control-stream dispatch (moqtrun_dispatch_ctl_stream)
  // parses every complete message in one wt_on_stream_data delivery, but
  // this subset's WT layer buffers nothing across separate deliveries
  // (moqtrun.h's doc on wired_moqt_on_stream_data): a message whose bytes
  // straddle two deliveries is silently dropped, not reassembled. Awaiting
  // each SUBSCRIBE's write() individually risked exactly that split across
  // browser-side buffering/pacing boundaries -- concatenating every
  // candidate's frame into one write() keeps each SUBSCRIBE request whole
  // within a single delivery whenever the browser doesn't itself fragment
  // one write() call.
  async #subscribeTo(candidate: string): Promise<void> {
    if (!this.#controlWriter) return;
    await this.#controlWriter.write(this.#buildSubscribeFrame(candidate));
  }

  async #subscribeToCandidates(): Promise<void> {
    if (!this.#controlWriter) return;
    const frames = candidateParticipantIds(this.#localId).map((c) =>
      this.#buildSubscribeFrame(c),
    );
    await this.#controlWriter.write(concatBytes(frames));
  }

  // The hub replies REQUEST_ERROR/DOES_NOT_EXIST to a SUBSCRIBE for a
  // participant that hasn't connected/PUBLISHed yet (no namespace discovery
  // exists in this subset -- see the class doc), and never notifies a
  // subscriber later when that peer does show up. Retrying on an interval
  // for every candidate not yet found is this client's stand-in for
  // discovery: cheap since a room only has a few candidate ids, and
  // idempotent on the hub side (each retry is matched fresh against
  // moqtrun's current PUBLISH state, draft SS10.7).
  //
  // A candidate already in #pendingSubscribes is normally skipped (its
  // reply is still on the way), but the hub can also fail to send that
  // reply at all for a while: its control stream is a keep-open bidi
  // stream, and a new round is refused until the previous one is fully
  // acknowledged, so a reply queued behind an earlier one can sit unsent
  // across several SUBSCRIBE_RETRY_MS ticks. Dropping a pending entry once
  // it's older than SUBSCRIBE_PENDING_TIMEOUT_MS and resending it is what
  // keeps that case from stalling forever -- the hub matches every
  // SUBSCRIBE fresh against its current PUBLISH state, so a resend is
  // never wrong, only sometimes redundant.
  async #retrySubscribes(): Promise<void> {
    const now = Date.now();
    this.#pendingSubscribes = this.#pendingSubscribes.filter(
      (p) => now - p.sentAt < SUBSCRIBE_PENDING_TIMEOUT_MS,
    );
    for (const candidate of candidateParticipantIds(this.#localId)) {
      if (this.#foundParticipants.has(candidate)) continue;
      if (this.#pendingSubscribes.some((p) => p.candidate === candidate)) continue;
      await this.#subscribeTo(candidate);
    }
  }

  // Reads every control message the hub sends back on the control stream
  // (REQUEST_OK for our PUBLISH, then SUBSCRIBE_OK/REQUEST_ERROR for each
  // SUBSCRIBE). Only SUBSCRIBE_OK/REQUEST_ERROR consume the pending queue.
  async #readControlReplies(readable: ReadableStream<Uint8Array>): Promise<void> {
    let buffered: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    for await (const chunk of readable as unknown as AsyncIterable<Uint8Array>) {
      buffered = concatBytes([buffered, chunk]);
      buffered = this.#drainControlFrames(buffered);
    }
  }

  #drainControlFrames(buffered: Uint8Array): Uint8Array<ArrayBufferLike> {
    let offset = 0;
    for (;;) {
      let decoded;
      try {
        decoded = decodeControlFrame(buffered, offset);
      } catch {
        break; // not enough bytes yet for the next frame
      }
      this.#handleControlFrame(decoded.frame.type, decoded.frame.body);
      offset += decoded.len;
    }
    return buffered.slice(offset);
  }

  #handleControlFrame(type: bigint, body: Uint8Array): void {
    // SETUP (from the hub, draft 3.3) and REQUEST_OK (our own PUBLISH's
    // reply) also arrive on this stream but need no action here; only
    // SUBSCRIBE_OK/REQUEST_ERROR consume the pending queue.
    if (type === MSG_TYPE_SUBSCRIBE_OK) {
      const pending = this.#pendingSubscribes.shift();
      if (pending) {
        decodeSubscribeOk(body);
        this.#foundParticipants.add(pending.candidate);
      }
      return;
    }
    if (type === MSG_TYPE_REQUEST_ERROR) {
      this.#pendingSubscribes.shift(); // DOES_NOT_EXIST: candidate absent, drop it
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

  async #readOneUniStream(stream: ReadableStream<Uint8Array>): Promise<void> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of stream as unknown as AsyncIterable<Uint8Array>) {
      chunks.push(chunk);
    }
    const wire = concatBytes(chunks);
    if (wire.length === 0) return;

    // Every uni stream the hub relays here is a SUBGROUP stream (padding/
    // fetch/control streams never arrive this way in this subset); decode
    // it directly and drop anything that fails to parse as one.
    let parsed;
    try {
      parsed = parseChatObjectMessage(wire);
    } catch {
      return;
    }
    // ownTrackAlias's doc: resolve the sender from the fixed candidate-list
    // mapping (the publisher's own alias, unmodified by relay), not from
    // this session's SUBSCRIBE_OK aliases.
    const participant = participantForTrackAlias(parsed.trackAlias);
    if (participant) this.#callbacks.onMessage(participant, parsed.text);
  }
}
