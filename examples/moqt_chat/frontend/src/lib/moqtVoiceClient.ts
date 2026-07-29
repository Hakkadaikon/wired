// MOQT voice transport: PUBLISHes/SUBSCRIBEs the "<id>/audio" track over
// the same MOQT session moqtClient.ts's MoqtChatClient already manages
// (M1's hub tracks up to 2 tracks per peer -- see moqtrun.h), and carries
// Opus frames as MOQT Objects (moqtVoiceWire.ts) instead of a raw
// WebTransport DATAGRAM.
//
// Same "one message, one uni stream" shape as chat's buildChatObjectMessage,
// NOT a single long-lived appended-to stream: moqtrun_relay_to_one
// (moqtrun.c) forwards each relayed chunk as its own fresh one-shot uni
// stream (FIN'd immediately) regardless of how the publisher sent it, so a
// publisher-side long-lived stream would arrive at each subscriber as a
// series of short-lived ones with no header on any but the first --
// unrecoverable without also teaching the hub to track per-subscriber
// stream continuity. Sending one full SUBGROUP_HEADER+Object per Opus
// frame instead matches the hub's actual relay unit exactly, at the cost
// of one stream open/close per 20ms frame (the same cost chat already
// pays per message).
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
  decodeVoiceObjectStream,
  encodeVoiceObjectMessage,
  type VoiceObjectPayload,
} from "./moqtVoiceWire";

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

  constructor(chat: MoqtChatClient, callbacks: MoqtVoiceCallbacks) {
    this.#chat = chat;
    this.#callbacks = callbacks;
  }

  /** PUBLISHes this client's "<id>/audio" track. No stream is opened here
   * -- sendOpusFrame opens one fresh uni stream per frame, matching the
   * hub's per-relay-call unit (class doc). */
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

  /** Sends one Opus frame as a complete SUBGROUP_HEADER+Object on a fresh
   * uni stream (a new Group per frame -- FIRST_OBJECT mode makes the
   * Object ID Delta the absolute id 0 every time, so no cross-frame
   * sequencing state is needed here). No-op before publishAudioTrack()
   * completes or if the WebTransport session is unavailable. */
  async sendOpusFrame(payload: Uint8Array): Promise<void> {
    const wt = this.#chat.webTransport;
    if (!wt) return;
    const wire = concatBytes([
      buildVoiceSubgroupHeader(this.#trackAlias, this.#groupId++),
      encodeVoiceObjectMessage(0n, { seq: 0, opus: payload }),
    ]);
    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    try {
      await writer.write(wire);
    } finally {
      await writer.close();
    }
  }

  /** Routes one incoming uni stream (a complete SUBGROUP_HEADER+Object, the
   * hub's own relay unit) to onOpusFrame if its Track Alias resolves to a
   * known participant's audio track -- called from moqtClient.ts's
   * onUnknownUniStream. Reads the stream to completion (chat's own
   * #readChatObjectStream shape): unlike a long-lived append-to stream,
   * each of these closes with FIN right after its one Object. */
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
    const chunks: Uint8Array[] = [firstChunk];
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
    } catch {
      return; // aborted mid-stream: this one frame is dropped, not fatal
    }
    const payloads = decodeVoiceObjectStream(concatBytes(chunks), 0, false);
    for (const payload of payloads) this.#callbacks.onOpusFrame(participant, payload);
  }

  close(): void {}
}
