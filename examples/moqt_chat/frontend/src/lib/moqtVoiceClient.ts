// MOQT voice transport: PUBLISHes/SUBSCRIBEs the "<id>/audio" track over
// the same MOQT session moqtClient.ts's MoqtChatClient already manages
// (M1's hub tracks up to 2 tracks per peer -- see moqtrun.h), and carries
// Opus frames as MOQT Objects (moqtVoiceWire.ts) instead of a raw
// WebTransport DATAGRAM.
//
// One long-lived uni stream per publish, not one stream per frame: the hub
// (moqtrun.c) now appends each relayed Object to a per-subscriber stream it
// keeps open for the whole call, mirroring this side. Opening a fresh
// stream per 20ms Opus frame exhausted the server's WT uni-stream receive
// slots (WIRED_SRVLOOP_MAX_WT_UNI_STREAMS) under normal chat+voice load and
// silently dropped both chat and voice traffic sharing those slots.
//
// Track Alias space: chat aliases are 0..N-1 (moqtClient.ts's
// ownTrackAlias, N = CANDIDATE_PARTICIPANT_IDS.length); audio aliases are
// offset by N so the two never collide on the wire (moqtClient.ts's
// onUnknownUniStream routes anything >= N here).

import {
  CANDIDATE_PARTICIPANT_IDS,
  ownTrackAlias,
  participantForTrackAlias,
  type MoqtChatClient,
} from "./moqtClient";
import {
  concatBytes,
  encodeObjectDatagram,
  type ObjectDatagram,
  type SubgroupHeader,
} from "./moqtWire";
import {
  buildVoiceSubgroupHeader,
  decodeVoiceObjectPayload,
  drainVoiceObjectStream,
  encodeVoiceObjectMessage,
  encodeVoiceObjectPayload,
  voiceObjectSeqInit,
  type VoiceObjectPayload,
} from "./moqtVoiceWire";
import { voiceTap } from "./voiceTap";

const AUDIO_ALIAS_OFFSET = BigInt(CANDIDATE_PARTICIPANT_IDS.length);

export function ownAudioTrackAlias(localId: string): bigint {
  return ownTrackAlias(localId) + AUDIO_ALIAS_OFFSET;
}

function participantForAudioTrackAlias(trackAlias: bigint): string | undefined {
  if (trackAlias < AUDIO_ALIAS_OFFSET) return undefined;
  return participantForTrackAlias(trackAlias - AUDIO_ALIAS_OFFSET);
}

function audioTrackName(participantId: string): Uint8Array {
  return new TextEncoder().encode(`${participantId}/audio`);
}

export interface MoqtVoiceCallbacks {
  onOpusFrame(participantId: string, payload: VoiceObjectPayload): void;
}

export class MoqtVoiceClient {
  #chat: MoqtChatClient;
  #callbacks: MoqtVoiceCallbacks;
  #trackAlias = 0n;
  #groupId = 0n;
  // Wire seq counter (u16 wrap, encodeVoiceObjectPayload's own contract):
  // the receive side keys its jitter buffer on this, and drops any seq it
  // has already buffered as a duplicate -- a constant seq would deliver
  // exactly ONE frame per call and silently discard every later one.
  #seq = 0;
  #writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  #datagramWriter: WritableStreamDefaultWriter<Uint8Array> | undefined;

  constructor(chat: MoqtChatClient, callbacks: MoqtVoiceCallbacks) {
    this.#chat = chat;
    this.#callbacks = callbacks;
  }

  /** PUBLISHes this client's "<id>/audio" track. No stream is opened here
   * -- sendOpusFrame opens the one long-lived stream on its first call
   * (class doc). */
  async publishAudioTrack(): Promise<void> {
    this.#trackAlias = ownAudioTrackAlias(this.#chat.localId);
    await this.#chat.publishTrack(audioTrackName(this.#chat.localId), this.#trackAlias);
  }

  /** SUBSCRIBEs to participantId's "<id>/audio" track. The reply is not
   * awaited (moqtClient.ts's subscribeTrack doc); a successful SUBSCRIBE
   * shows up as incoming uni streams once the peer starts talking, routed
   * here via handleIncomingStream. */
  async subscribeToAudioTrack(participantId: string): Promise<void> {
    await this.#chat.subscribeTrack(
      audioTrackName(participantId),
      `${participantId}/audio`,
    );
  }

  /** Sends one Opus frame, preferring one OBJECT_DATAGRAM per frame (Type
   * 0x08, DEFAULT_PRIORITY: no priority byte on the wire) when the session
   * has a datagram path and the encoded frame fits maxDatagramSize -- a
   * lost 20ms frame is better skipped than delivered late, which is what a
   * datagram's fire-and-forget gives over the stream's retransmits. A frame
   * that does not fit (or a transport without a usable datagram path) falls
   * back to the long-lived uni stream (#sendOnStream). Both paths carry the
   * same Object payload shape, seq u16 BE + opus, so the receive side's
   * jitter buffer and taps cannot tell them apart. No-op before
   * publishAudioTrack() completes or if the WebTransport session is
   * unavailable. Callers must serialize calls (micPipeline.ts's sendGate)
   * -- this method does not lock the writers itself. */
  async sendOpusFrame(payload: Uint8Array): Promise<void> {
    const seq = this.#seq++;
    // & 0xffff matches the wire's own u16 wrap (encodeVoiceObjectPayload),
    // so the receive side's tap sees the same seq value.
    voiceTap({ dir: "send", seq: seq & 0xffff, t: performance.now(), bytes: payload.byteLength });
    const wt = this.#chat.webTransport;
    if (!wt) return;
    const datagram = encodeObjectDatagram({
      type: 0x08n,
      trackAlias: this.#trackAlias,
      groupId: 0n,
      objectId: BigInt(seq),
      payload: encodeVoiceObjectPayload({ seq, opus: payload }),
    });
    const max = wt.datagrams?.maxDatagramSize;
    if (max !== undefined && datagram.length <= max) {
      this.#datagramWriter ??= wt.datagrams.writable.getWriter();
      await this.#datagramWriter.write(datagram);
      return;
    }
    await this.#sendOnStream(wt, encodeVoiceObjectMessage(0n, { seq, opus: payload }));
  }

  /** The stream fallback: one long-lived uni stream kept open for the whole
   * call. The SUBGROUP_HEADER (fixed Group ID) goes out once, on the first
   * call that opens the stream; every call after that appends a bare Object
   * (moqtrun.c's own hub-side doc: a header-less call on an already-bound
   * stream is exactly this shape). Object ID Delta 0 on every call is
   * correct either way -- FIRST_OBJECT mode makes the first one's delta the
   * absolute id (0), and decodeSubgroupObject's own chaining rule
   * (prevId + delta + 1) turns a delta of 0 into a plain increment for
   * every Object after that. */
  async #sendOnStream(wt: WebTransport, object: Uint8Array): Promise<void> {
    if (!this.#writer) {
      const stream = await wt.createUnidirectionalStream();
      this.#writer = stream.getWriter();
      await this.#writer.write(
        concatBytes([buildVoiceSubgroupHeader(this.#trackAlias, this.#groupId), object]),
      );
    } else {
      await this.#writer.write(object);
    }
  }

  /** Routes one incoming OBJECT_DATAGRAM (already decoded by
   * moqtClient.ts's datagram read loop) to onOpusFrame if its Track Alias
   * resolves to a known participant's audio track; anything else -- an
   * alias outside the audio range, or a payload too short to carry the seq
   * header -- is dropped without throwing, mirroring handleIncomingStream's
   * own tolerance. */
  handleIncomingDatagram(datagram: ObjectDatagram): void {
    const participant = participantForAudioTrackAlias(datagram.trackAlias);
    if (!participant) return;
    let payload: VoiceObjectPayload;
    try {
      payload = decodeVoiceObjectPayload(datagram.payload);
    } catch {
      return;
    }
    this.#callbacks.onOpusFrame(participant, payload);
  }

  /** Routes one incoming uni stream (the publisher's long-lived audio relay
   * stream) to onOpusFrame if its Track Alias resolves to a known
   * participant's audio track -- called from moqtClient.ts's
   * onUnknownUniStream. Unlike chat's one-shot-per-message stream, this one
   * stays open for the whole call: reading it to EOF before decoding (chat's
   * own #readChatObjectStream shape) would delay every frame until the call
   * ends, so this decodes incrementally as chunks arrive instead
   * (drainVoiceObjectStream). */
  handleIncomingStream(
    header: SubgroupHeader,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): void {
    const participant = participantForAudioTrackAlias(header.trackAlias);
    if (!participant) {
      reader.cancel().catch(() => {});
      return;
    }
    this.#readOneVoiceStream(participant, firstChunk, reader);
  }

  async #readOneVoiceStream(
    participant: string,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): Promise<void> {
    const seq = voiceObjectSeqInit();
    const onPayload = (payload: VoiceObjectPayload) =>
      this.#callbacks.onOpusFrame(participant, payload);
    let buffered = drainVoiceObjectStream(firstChunk, false, seq, onPayload);
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        buffered = drainVoiceObjectStream(
          concatBytes([buffered, value]),
          false,
          seq,
          onPayload,
        );
      }
    } catch {
      // aborted mid-stream: whatever wasn't decoded yet is dropped, not fatal
    }
  }

  /** FINs the long-lived send stream, if one was ever opened, and drops the
   * datagram writer (datagrams have no FIN; the session teardown ends
   * them). */
  close(): void {
    this.#writer?.close().catch(() => {});
    this.#writer = undefined;
    this.#datagramWriter?.releaseLock();
    this.#datagramWriter = undefined;
  }
}
