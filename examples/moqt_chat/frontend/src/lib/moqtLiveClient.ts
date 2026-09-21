// MOQT live movie playback: the hub paces keyframe-aligned fMP4 fragments
// as MoQT Groups on the "movie" track (Track Alias 8) and serves the init
// segment once on "movie/init" (alias 9, moqtMovieClient.ts's blob reader).
// Each Group's stream is SUBGROUP_HEADER + one Object whose payload is a
// moof+mdat pair; appended to a SourceBuffer in "sequence" mode so the
// asset's 30-second loop (timestamps restart at 0) plays through.

import type { MoqtChatClient } from "./moqtClient";
import {
  decodeBlobObjects,
  MOVIE_TRACK_NAME,
  subscribeMovieInit,
} from "./moqtMovieClient";
import { readToEof, utf8ToBytes } from "./moqtWire";

export const MOVIE_MIME = 'video/mp4; codecs="avc1.64001e, mp4a.40.2"';
// Trim only once more than a minute of media sits behind the playhead, and
// keep the last 30 s so a small seek back still has buffer.
const KEEP_BEHIND_S = 30;
const TRIM_WHEN_BEHIND_S = 60;
// Fragments that arrive before the init segment are held (newest wins);
// the hub paces ~1 Group/s, so 8 covers any realistic init delay.
const PENDING_CAP = 8;

// 1.5 Groups of margin before (re)starting playback: one whole 2-second
// Group absorbs the next Group's arrival jitter, plus half a Group of
// slack so a slightly late Group still lands before the margin runs out.
export const LIVE_TARGET_AHEAD_S = 3;
// A receiver that fell behind (tab throttled, slow link) and then caught
// up in a burst can sit far behind the live edge; beyond 4 Groups (8 s)
// jump forward instead of playing stale media.
const MAX_BEHIND_S = 8;

/** True when the buffered range containing (or starting at/after)
 * currentTime extends at least targetAheadS beyond currentTime. */
export function shouldPlay(
  buffered: { length: number; start(i: number): number; end(i: number): number },
  currentTime: number,
  targetAheadS: number,
): boolean {
  for (let i = 0; i < buffered.length; i++) {
    if (buffered.end(i) < currentTime) continue;
    return buffered.end(i) - currentTime >= targetAheadS;
  }
  return false;
}

/** Where to seek before playing when currentTime is more than MAX_BEHIND_S
 * behind the buffered end; undefined when no jump is needed. */
export function catchUpTarget(
  buffered: { length: number; start(i: number): number; end(i: number): number },
  currentTime: number,
): number | undefined {
  if (buffered.length === 0) return undefined;
  const end = buffered.end(buffered.length - 1);
  return end - currentTime > MAX_BEHIND_S ? end - LIVE_TARGET_AHEAD_S : undefined;
}

/** The subset of SourceBuffer the queue drives -- narrow so tests can hand
 * in a plain fake instead of a real MediaSource. */
export interface SourceBufferLike {
  updating: boolean;
  mode: string;
  appendBuffer(b: BufferSource): void;
  remove(s: number, e: number): void;
  addEventListener(t: "updateend" | "error", h: () => void): void;
  buffered: { length: number; start(i: number): number; end(i: number): number };
}

/** Serializes appendBuffer/remove against a SourceBuffer: only one
 * operation may be in flight (SourceBuffer throws while `updating`), so
 * ops queue and the updateend event drains them in order. A SourceBuffer
 * error is terminal: report once, drop everything after. */
export class AppendQueue {
  #sb: SourceBufferLike;
  #queue: (() => void)[] = [];
  #dead = false;
  #onError: (m: string) => void;

  constructor(sb: SourceBufferLike, onError: (msg: string) => void) {
    this.#sb = sb;
    this.#onError = onError;
    sb.addEventListener("updateend", () => this.#next());
    sb.addEventListener("error", () => {
      this.#dead = true;
      onError("video buffer error");
    });
  }

  push(bytes: Uint8Array) {
    this.#enqueue(() => this.#sb.appendBuffer(bytes as BufferSource));
  }

  trim(currentTime: number) {
    if (this.#dead) return;
    const b = this.#sb.buffered;
    if (b.length === 0 || currentTime - b.start(0) <= TRIM_WHEN_BEHIND_S) return;
    this.#enqueue(() => this.#sb.remove(0, currentTime - KEEP_BEHIND_S));
  }

  /** Stops this queue from ever touching the SourceBuffer again -- call
   * before the SourceBuffer is detached from its MediaSource (e.g. on
   * video.load()), since a detached SourceBuffer throws even just reading
   * .buffered and the updateend/timeupdate listeners stay alive. */
  dispose() {
    this.#dead = true;
    this.#queue = [];
  }

  #enqueue(op: () => void) {
    if (this.#dead) return;
    this.#queue.push(op);
    if (!this.#sb.updating) this.#next();
  }

  #next() {
    if (this.#sb.updating || this.#dead) return;
    const op = this.#queue.shift();
    if (!op) return;
    try {
      op();
    } catch {
      this.#dead = true;
      this.#onError("video buffer append failed");
    }
  }
}

export interface LiveMovieOptions {
  onError(msg: string): void;
  onFirstGroup?(g: bigint): void;
}

/** Plays the hub's live movie: start() opens a MediaSource on the <video>
 * and SUBSCRIBEs "movie/init"; once handleInit gets the init segment it is
 * appended, buffered fragments flush, and the live "movie" track is
 * SUBSCRIBEd so every further Group appends one fragment. */
export class LiveMovie {
  #chat: MoqtChatClient;
  #video: HTMLVideoElement;
  #opts: LiveMovieOptions;
  #q: AppendQueue | undefined;
  #url: string | undefined;
  #init: Uint8Array | undefined;
  #pending: Uint8Array[] = [];
  #playFailed = false;
  firstGroup: bigint | undefined;

  constructor(chat: MoqtChatClient, video: HTMLVideoElement, opts: LiveMovieOptions) {
    this.#chat = chat;
    this.#video = video;
    this.#opts = opts;
  }

  async start(): Promise<void> {
    // A silent spinner is worse than an error: a Chromium build without
    // H.264/AAC (or Safari's MSE quirks) rejects this MIME, and without the
    // check the <video> just never leaves readyState 0.
    if (typeof MediaSource === "undefined" || !MediaSource.isTypeSupported(MOVIE_MIME)) {
      this.#opts.onError(
        `this browser cannot play ${MOVIE_MIME} through Media Source Extensions (H.264/AAC support missing?)`,
      );
      return;
    }
    try {
      await this.#open();
    } catch (err) {
      const e = err as Error;
      this.#opts.onError(`live start failed: ${e.name}: ${e.message}`);
    }
  }

  async #open(): Promise<void> {
    const ms = new MediaSource();
    this.#url = URL.createObjectURL(ms);
    this.#video.src = this.#url;
    this.#video.addEventListener("error", () =>
      this.#opts.onError(`video error: ${this.#video.error?.message ?? "unknown"}`),
    );
    await new Promise<void>((r) => ms.addEventListener("sourceopen", () => r(), { once: true }));
    const sb = ms.addSourceBuffer(MOVIE_MIME) as unknown as SourceBufferLike;
    sb.mode = "sequence";
    this.#q = new AppendQueue(sb, this.#opts.onError);
    // Every completed append (and a stall) re-evaluates the playback gate:
    // this class owns play(), the <video> has no autoplay.
    sb.addEventListener("updateend", () => this.#maybePlay());
    this.#video.addEventListener("waiting", () => this.#maybePlay());
    this.#video.addEventListener("stalled", () => this.#maybePlay());
    this.#video.addEventListener("timeupdate", () => this.#q?.trim(this.#video.currentTime));
    await subscribeMovieInit(this.#chat);
  }

  handleInit(bytes: Uint8Array): void {
    this.#init = bytes;
    this.#q?.push(bytes);
    for (const frag of this.#pending) this.#q?.push(frag);
    this.#pending = [];
    void this.#chat.subscribeTrack(utf8ToBytes(MOVIE_TRACK_NAME), MOVIE_TRACK_NAME);
  }

  async handleFragment(
    firstChunkTail: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
    hasProperties: boolean,
    groupId: bigint,
  ): Promise<void> {
    let bytes: Uint8Array;
    try {
      bytes = decodeBlobObjects(await readToEof(firstChunkTail, reader), hasProperties);
    } catch {
      return; // malformed or aborted Group: dropped, not fatal
    }
    if (this.firstGroup === undefined) {
      this.firstGroup = groupId;
      this.#opts.onFirstGroup?.(groupId);
    }
    if (!this.#init) {
      if (this.#pending.length >= PENDING_CAP) this.#pending.shift();
      this.#pending.push(bytes);
      return;
    }
    this.#q?.push(bytes);
  }

  // Only ever (re)starts playback -- a stall is the browser's own
  // "waiting"; pausing is left entirely to it.
  #maybePlay(): void {
    const v = this.#video;
    if (!v.paused || !this.#gate(v)) return;
    void v.play().catch((err) => this.#reportPlayFailure(err as Error));
  }

  #gate(v: HTMLVideoElement): boolean {
    const jump = catchUpTarget(v.buffered, v.currentTime);
    if (jump !== undefined) v.currentTime = jump;
    return shouldPlay(v.buffered, v.currentTime, LIVE_TARGET_AHEAD_S);
  }

  // Muted autoplay is normally allowed, so a rejection is unexpected;
  // report it once instead of once per append.
  #reportPlayFailure(e: Error): void {
    if (this.#playFailed) return;
    this.#playFailed = true;
    this.#opts.onError(`video play failed: ${e.name}: ${e.message}`);
  }

  stop(): void {
    // Dispose the queue first: video.load() below detaches the
    // SourceBuffer from its MediaSource, and the updateend/timeupdate
    // listeners stay registered -- without this, a late event reads
    // .buffered on a removed SourceBuffer and throws InvalidStateError.
    this.#q?.dispose();
    // Revoke first: the object URL pins the MediaSource until the tab
    // closes, so every connect->leave cycle would leak one otherwise.
    if (this.#url) URL.revokeObjectURL(this.#url);
    this.#url = undefined;
    this.#video.removeAttribute("src");
    this.#video.load();
  }
}
