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
import { concatBytes, type SubgroupHeader } from "./moqtWire";
import {
  buildVoiceSubgroupHeader,
  drainVoiceObjectStream,
  encodeVoiceObjectMessage,
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

  /** Sends one Opus frame as an Object on the one long-lived uni stream
   * this client keeps open for the whole call: the SUBGROUP_HEADER (fixed
   * Group ID) goes out once, on the first call that opens the stream;
   * every call after that appends a bare Object (moqtrun.c's own hub-side
   * doc: a header-less call on an already-bound stream is exactly this
   * shape). Object ID Delta 0 on every call is correct either way --
   * FIRST_OBJECT mode makes the first one's delta the absolute id (0), and
   * decodeSubgroupObject's own chaining rule (prevId + delta + 1) turns a
   * delta of 0 into a plain increment for every Object after that. No-op
   * before publishAudioTrack() completes or if the WebTransport session is
   * unavailable. Callers must serialize calls (micPipeline.ts's sendGate)
   * -- this method does not lock the writer itself. */
  async sendOpusFrame(payload: Uint8Array): Promise<void> {
    const seq = this.#seq++;
    const object = encodeVoiceObjectMessage(0n, { seq, opus: payload });
    // & 0xffff matches the wire's own u16 wrap (encodeVoiceObjectPayload),
    // so the receive side's tap sees the same seq value.
    voiceTap({ dir: "send", seq: seq & 0xffff, t: performance.now() });
    if (!this.#writer) {
      const wt = this.#chat.webTransport;
      if (!wt) return;
      const stream = await wt.createUnidirectionalStream();
      this.#writer = stream.getWriter();
      await this.#writer.write(
        concatBytes([buildVoiceSubgroupHeader(this.#trackAlias, this.#groupId), object]),
      );
    } else {
      await this.#writer.write(object);
    }
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

  /** FINs the long-lived send stream, if one was ever opened. */
  close(): void {
    this.#writer?.close().catch(() => {});
    this.#writer = undefined;
  }
}
