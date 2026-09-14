// MOQT screen-share transport: PUBLISHes/SUBSCRIBEs the "<id>/screen" track
// over the same MOQT session moqtClient.ts's MoqtChatClient already manages.
// Mirrors moqtVoiceClient.ts's shape exactly (one long-lived uni stream per
// publish, opened lazily on the first sendVideoChunk call) -- see that
// file's doc for why a long-lived stream instead of one-per-frame. Each
// Object carries one video chunk (moqtScreenWire.ts); the caller
// (Task 7's screen-share pipeline) is responsible for chunking a frame and
// reassembling it on receive (screenFrameReassemblerPush).
//
// Track Alias space: chat aliases are 0..N-1, audio N..2N-1
// (moqtVoiceClient.ts), the live movie sits at 2N/2N+1
// (moqtMovieClient.ts's MOVIE_TRACK_ALIAS/MOVIE_INIT_TRACK_ALIAS). Screen
// aliases are offset from MOVIE_INIT_TRACK_ALIAS + 1 (relative, not a bare
// 10) so they self-adjust if CANDIDATE_PARTICIPANT_IDS.length ever changes.

import {
  CANDIDATE_PARTICIPANT_IDS,
  ownTrackAlias,
  participantForTrackAlias,
  type MoqtChatClient,
} from "./moqtClient";
import { MOVIE_INIT_TRACK_ALIAS } from "./moqtMovieClient";
import {
  concatBytes,
  decodeSubgroupObject,
  encodeVarint,
  type SubgroupHeader,
} from "./moqtWire";
import {
  buildScreenSubgroupHeader,
  encodeScreenObjectMessage,
  decodeScreenObjectMessage,
  type ScreenChunk,
} from "./moqtScreenWire";

export const SCREEN_ALIAS_OFFSET = MOVIE_INIT_TRACK_ALIAS + 1n;

export function ownScreenTrackAlias(localId: string): bigint {
  return ownTrackAlias(localId) + SCREEN_ALIAS_OFFSET;
}

function participantForScreenTrackAlias(trackAlias: bigint): string | undefined {
  if (trackAlias < SCREEN_ALIAS_OFFSET) return undefined;
  return participantForTrackAlias(trackAlias - SCREEN_ALIAS_OFFSET);
}

/** True when `trackAlias` falls in the screen-share alias range
 * [SCREEN_ALIAS_OFFSET, SCREEN_ALIAS_OFFSET + N). Exported so
 * useMoqtChat.ts's onUnknownUniStream can route on it directly. */
export function isScreenTrackAlias(trackAlias: bigint): boolean {
  return (
    trackAlias >= SCREEN_ALIAS_OFFSET &&
    trackAlias < SCREEN_ALIAS_OFFSET + BigInt(CANDIDATE_PARTICIPANT_IDS.length)
  );
}

function screenTrackName(participantId: string): Uint8Array {
  return new TextEncoder().encode(`${participantId}/screen`);
}

export interface MoqtScreenCallbacks {
  onScreenChunk(participantId: string, chunk: ScreenChunk): void;
}

export class MoqtScreenClient {
  #chat: MoqtChatClient;
  #callbacks: MoqtScreenCallbacks;
  #trackAlias = 0n;
  #groupId = 0n;
  #writer: WritableStreamDefaultWriter<Uint8Array> | undefined;

  constructor(chat: MoqtChatClient, callbacks: MoqtScreenCallbacks) {
    this.#chat = chat;
    this.#callbacks = callbacks;
  }

  /** PUBLISHes this client's "<id>/screen" track. No stream is opened here
   * -- sendVideoChunk opens the one long-lived stream on its first call
   * (class doc). */
  async publishScreenTrack(): Promise<void> {
    this.#trackAlias = ownScreenTrackAlias(this.#chat.localId);
    await this.#chat.publishTrack(screenTrackName(this.#chat.localId), this.#trackAlias);
  }

  /** SUBSCRIBEs to participantId's "<id>/screen" track. Not awaited beyond
   * the SUBSCRIBE round trip itself -- mirrors subscribeToAudioTrack; the
   * caller retries on an interval the same way (moqtVoiceClient.ts's own
   * doc / useMoqtChat.ts's VOICE_SUBSCRIBE_RETRY_MS pattern). */
  async subscribeToScreenTrack(participantId: string): Promise<void> {
    await this.#chat.subscribeTrack(
      screenTrackName(participantId),
      `${participantId}/screen`,
    );
  }

  /** Sends one video chunk as an Object on the one long-lived uni stream
   * this client keeps open for the whole share: the SUBGROUP_HEADER goes
   * out once, on the first call that opens the stream; every call after
   * that appends a bare Object. Callers must serialize calls through
   * sendGate.ts (same contract as sendOpusFrame) -- this method does not
   * lock the writer itself. */
  async sendVideoChunk(chunk: ScreenChunk): Promise<void> {
    const body = encodeScreenObjectMessage(chunk);
    // objectIdDelta 0 on every call is correct either way -- FIRST_OBJECT
    // mode makes the first one's delta the absolute id (0), and
    // decodeSubgroupObject's own chaining rule (prevId + delta + 1) turns a
    // delta of 0 into a plain increment for every Object after that
    // (mirrors encodeVoiceObjectMessage's own doc).
    const object = concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    if (!this.#writer) {
      const wt = this.#chat.webTransport;
      if (!wt) return;
      const stream = await wt.createUnidirectionalStream();
      this.#writer = stream.getWriter();
      await this.#writer.write(
        concatBytes([buildScreenSubgroupHeader(this.#trackAlias, this.#groupId), object]),
      );
    } else {
      await this.#writer.write(object);
    }
  }

  /** Routes one incoming uni stream to onScreenChunk if its Track Alias
   * resolves to a known participant's screen track -- called from
   * useMoqtChat.ts's onUnknownUniStream. Like voice, decodes incrementally
   * as chunks arrive rather than reading to EOF first (a share can run for
   * the whole call). */
  handleIncomingStream(
    header: SubgroupHeader,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): void {
    const participant = participantForScreenTrackAlias(header.trackAlias);
    if (!participant) {
      reader.cancel().catch(() => {});
      return;
    }
    this.#readOneScreenStream(participant, firstChunk, reader);
  }

  async #readOneScreenStream(
    participant: string,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): Promise<void> {
    let buffered = firstChunk;
    const seq: ScreenObjectSeq = { prevObjectId: 0n, isFirst: true };
    const onChunk = (chunk: ScreenChunk) => this.#callbacks.onScreenChunk(participant, chunk);
    try {
      for (;;) {
        buffered = drainScreenObjectStream(buffered, seq, onChunk);
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        buffered = concatBytes([buffered, value]);
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

// Object ID accumulation state threaded across successive
// drainScreenObjectStream calls on the same stream -- mirrors
// moqtVoiceWire.ts's VoiceObjectSeq (moqtScreenWire.ts has no stream-level
// decoder of its own, only decodeScreenObjectMessage for one Object body,
// so the Object framing itself is unwrapped here via decodeSubgroupObject).
interface ScreenObjectSeq {
  prevObjectId: bigint;
  isFirst: boolean;
}

/** Decodes as many complete Objects as `buffered` holds, calling `onChunk`
 * for each, and returns the undecoded remainder. Mirrors
 * drainVoiceObjectStream's incremental shape: decodeSubgroupObject slices a
 * short payload without throwing on a truncated tail, so `len >
 * buffered.length` is checked explicitly (moqtMovieClient.ts's own doc). */
function drainScreenObjectStream(
  buffered: Uint8Array,
  seq: ScreenObjectSeq,
  onChunk: (chunk: ScreenChunk) => void,
): Uint8Array {
  let pos = 0;
  for (;;) {
    let parsed: ReturnType<typeof decodeSubgroupObject>;
    try {
      parsed = decodeSubgroupObject(buffered, pos, false, seq.prevObjectId, seq.isFirst);
    } catch {
      break; // incomplete Object (truncated varint), wait for more data
    }
    if (pos + parsed.len > buffered.length) break; // truncated tail, wait for more data
    const { chunk } = decodeScreenObjectMessage(parsed.object.payload);
    onChunk(chunk);
    seq.prevObjectId = parsed.object.objectId;
    seq.isFirst = false;
    pos += parsed.len;
  }
  return buffered.slice(pos);
}
