// MOQT screen-share transport: PUBLISHes/SUBSCRIBEs the "<id>/screen" track
// over the same MOQT session moqtClient.ts's MoqtChatClient already manages.
// Like moqtVoiceClient.ts, frames are appended to a long-lived uni stream
// rather than one stream per frame, but every keyframe starts a new Group
// on a fresh stream, so a late joiner's history of the current Group --
// a fill of Relative Start 1 (draft-ietf-moq-transport-22 3.4, 9.20.9), or
// on the draft-19 legacy session a Joining FETCH with Joining Start 0
// (d19 10.12.2) -- begins at a keyframe. Each
// Object carries one video chunk (moqtScreenWire.ts); the caller
// (Task 7's screen-share pipeline) is responsible for chunking a frame and
// reassembling it on receive (screenFrameReassemblerPush).
//
// Track Alias space: chat aliases are 0..N-1, audio N..2N-1
// (moqtVoiceClient.ts). Screen aliases are offset from
// CANDIDATE_PARTICIPANT_IDS.length * 2 (relative, not a bare 8) so they
// self-adjust if CANDIDATE_PARTICIPANT_IDS.length ever changes; the extra
// +2 leaves a 2-alias gap above the audio range for future use.

// Track switching (tasks/moqt-trackswitch-plan.md, draft-22 sessions whose
// hub advertised SSTS_ALGORITHMS only -- MoqtChatClient.trackSwitching): a
// share is published as two variants with ALIGNED Group IDs, "<id>/screen"
// (hi) and "<id>/screen-lo" (lo, <= 640 wide, screenSharePipeline.ts), both
// cut from the same captured frames with one keyframe decision. A watcher
// subscribes both into one sender-side switching set (SWITCHING_SET_ASSIGNMENT
// 0x41), so the hub forwards one of them per Group, or -- the per-tile
// quality selector -- just one, moving between them with SWITCH_FROM (0x24).
// Both variants feed the participant's one decoder; a Group gate keeps
// the other variant's copy of a Group and a switched-away variant's tail out
// of it. Elsewhere (d19, an extension-less hub) nothing changes: hi only,
// one plain subscription, no gate.
//
// Lo aliases sit right above the hi range: SCREEN_LO_ALIAS_OFFSET =
// SCREEN_ALIAS_OFFSET + N.

import {
  CANDIDATE_PARTICIPANT_IDS,
  ownTrackAlias,
  participantForTrackAlias,
  type MoqtChatClient,
} from "./moqtClient";
import {
  concatBytes,
  decodeSubgroupObject,
  encodeVarint,
  switchFromParam,
  switchingSetAssignmentParam,
  SWITCH_MODE_SOFT,
  type MessageParam,
  type SubgroupHeader,
} from "./moqtWire";
import {
  buildScreenSubgroupHeader,
  encodeScreenObjectMessage,
  decodeScreenObjectMessage,
  type ScreenChunk,
} from "./moqtScreenWire";

/** hi: the share as captured; lo: the low-quality copy (track switching). */
export type ScreenVariant = "hi" | "lo";
/** A remote tile's quality choice: the SSTS pair, or one variant only. */
export type ScreenQuality = "auto" | "high" | "low";

const POOL = BigInt(CANDIDATE_PARTICIPANT_IDS.length);
export const SCREEN_ALIAS_OFFSET = POOL * 2n + 2n;
export const SCREEN_LO_ALIAS_OFFSET = SCREEN_ALIAS_OFFSET + POOL;

const VARIANT_OFFSET: Record<ScreenVariant, bigint> = { hi: SCREEN_ALIAS_OFFSET, lo: SCREEN_LO_ALIAS_OFFSET };
const VARIANT_SUFFIX: Record<ScreenVariant, string> = { hi: "screen", lo: "screen-lo" };
const QUALITY_VARIANT: Record<"high" | "low", ScreenVariant> = { high: "hi", low: "lo" };

// SWITCHING_SET_ASSIGNMENT values: each variant's bandwidth threshold, equal
// weights, and Activate 2 (the set switches once both members are in).
// hi's bitrate is not one number -- screenBitrate scales it with the
// capture, clamped to [SCREEN_HI_MIN_BITRATE, SCREEN_HI_MAX_BITRATE] =
// [1, 4] Mbps -- so its threshold is a fixed point inside that band: 2000
// kbps sits just under 1080p10's 2.5 Mbps (the common share) and above
// every smaller capture's need, without demanding the 4 Mbps cap that a
// 4K share alone reaches. lo's 400 kbps is SCREEN_LO_BITRATE (350 kbps)
// plus headroom.
export const SCREEN_SSTS_THRESHOLD_KBPS: Record<ScreenVariant, bigint> = { hi: 2000n, lo: 400n };
const SSTS_WEIGHT = 1n;
const SSTS_ACTIVATE = 2n;

/** The hi variant's ("<id>/screen") Track Alias. */
export function ownScreenTrackAlias(localId: string): bigint {
  return screenVariantAlias(localId, "hi");
}

/** Either variant's Track Alias: hi in [10, 14), lo in [14, 18). */
export function screenVariantAlias(localId: string, variant: ScreenVariant): bigint {
  return ownTrackAlias(localId) + VARIANT_OFFSET[variant];
}

/** The participant and variant a screen Track Alias belongs to. */
function screenAliasOwner(trackAlias: bigint): { participant: string; variant: ScreenVariant } | undefined {
  if (!isScreenTrackAlias(trackAlias)) return undefined;
  const variant: ScreenVariant = trackAlias >= SCREEN_LO_ALIAS_OFFSET ? "lo" : "hi";
  const participant = participantForTrackAlias(trackAlias - VARIANT_OFFSET[variant]);
  return participant ? { participant, variant } : undefined;
}

/** True when `trackAlias` falls in either screen-share alias range
 * [SCREEN_ALIAS_OFFSET, SCREEN_LO_ALIAS_OFFSET + N). Exported so
 * useMoqtChat.ts's onUnknownUniStream can route on it directly. */
export function isScreenTrackAlias(trackAlias: bigint): boolean {
  return trackAlias >= SCREEN_ALIAS_OFFSET && trackAlias < SCREEN_LO_ALIAS_OFFSET + POOL;
}

function screenLabel(participantId: string, variant: ScreenVariant): string {
  return `${participantId}/${VARIANT_SUFFIX[variant]}`;
}

function screenTrackName(participantId: string, variant: ScreenVariant = "hi"): Uint8Array {
  return new TextEncoder().encode(screenLabel(participantId, variant));
}

/** Which (Group, variant) a participant's decoder is following. */
export interface ScreenGroupGate {
  group?: bigint;
  variant?: ScreenVariant;
  /** The binding came from a history fill, not yet confirmed live. */
  byFill?: boolean;
}

/** Whether a chunk of Group `group` from `variant` may reach the decoder.
 * Every Group opens with a keyframe on both variants (aligned Groups), so the
 * gate follows the first keyframe of each newer Group and drops: the other
 * variant's copy of the current Group (both forwarded, or both fills), any
 * older Group however late it arrives (a Soft switch's old track, a slow
 * stream), and a newer Group not opened by its keyframe. A publisher that
 * restarts its count (a new session) is followed through a fresh gate:
 * subscribeToScreenTrack resets it when the share is announced again.
 *
 * `live` false = a history fill. Fills are per subscription and SSTS does
 * not gate them, so a fill may bind a Group to the variant the hub is NOT
 * forwarding live for it (Auto: lo's fill one Group ahead of hi's). A gate
 * a fill bound is therefore only provisional: the live keyframe of that
 * Group from the other variant -- the member the hub actually chose --
 * takes it over (the decoder reconfigures on a keyframe, so the switch
 * mid-Group is safe). Live data of the bound variant confirms it. */
export function screenGroupGateAccept(
  gate: ScreenGroupGate,
  group: bigint,
  variant: ScreenVariant,
  keyframe: boolean,
  live = true,
): boolean {
  const fresh = gate.group === undefined || group > gate.group;
  if (!fresh) {
    if (group !== gate.group) return false;
    if (variant === gate.variant) {
      if (live) gate.byFill = false;
      return true;
    }
    if (!(gate.byFill && live && keyframe)) return false;
  } else if (!keyframe) {
    return false;
  }
  gate.group = group;
  gate.variant = variant;
  gate.byFill = !live;
  return true;
}

/** One chunk on its way to onScreenChunk. */
interface ScreenItem {
  chunk: ScreenChunk;
  group: bigint;
  variant: ScreenVariant;
  /** false: from a history fill (screenGroupGateAccept's `live`). */
  live: boolean;
}

/** Live chunks held back while `pending` histories are still running. */
interface JoinHold {
  held: ScreenItem[];
  pending: number;
}

/** One variant's send stream: the Group it carries and its writer. */
interface SendLane {
  writer?: WritableStreamDefaultWriter<Uint8Array>;
  group?: bigint;
  // A caller-given Group whose stream died (write timeout/failure): its
  // remaining chunks are dropped -- reopening it would start a second
  // subgroup stream of the same Group with Object IDs from 0 again. The
  // reset's keyframe opens the next Group.
  dead?: bigint;
}

export interface MoqtScreenCallbacks {
  /** `variant`: which of the sender's variants carried the chunk (always
   * "hi" without track switching). */
  onScreenChunk(participantId: string, chunk: ScreenChunk, variant: ScreenVariant): void;
  /** The send stream was dropped (a write or open that hung past
   * SCREEN_WRITE_TIMEOUT_MS, or a write that failed); the next chunk opens
   * a fresh stream, so the caller should make its next frame a keyframe. */
  onStreamReset?(): void;
}

// A write() that has not returned in this long is a stream the hub is not
// draining (flow-control window shut, or the stream never got credit):
// every later frame would queue behind it forever. 1 s is ten frames at
// the pipeline's 10 fps -- long past any healthy round trip, short enough
// that the viewer sees a hiccup, not a freeze.
export const SCREEN_WRITE_TIMEOUT_MS = 1000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`screen send timed out after ${ms} ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

/** sendVideoChunk's routing: `group` set = the caller's (aligned) Group, a
 * new stream whenever it changes; unset = the single-variant rule, a new
 * Group at every keyframe. `variant` defaults to hi. */
export interface ScreenSendOptions {
  group?: bigint;
  variant?: ScreenVariant;
}

export class MoqtScreenClient {
  #chat: MoqtChatClient;
  #callbacks: MoqtScreenCallbacks;
  // Group of the NEXT Group opened: shared by both variants (allocateGroup),
  // monotonic across the session's shares.
  #groupId = 0n;
  #lanes: Record<ScreenVariant, SendLane> = { hi: {}, lo: {} };
  #published = false;
  #loPublished = false;
  // The <id>/screen namespace while this client shares (discovery's
  // "a share started" signal); cancelled by close().
  #announcement: { cancel(): void } | undefined;
  // Peers whose history fetches (d22 fill / d19 Joining FETCH) are still
  // running: their live chunks wait here so the decoder sees the keyframe
  // Group's start first.
  #joining = new Map<string, JoinHold>();
  // Per-participant Group gates, only for a track-switching subscription
  // (two variants may feed one decoder).
  #gates = new Map<string, ScreenGroupGate>();
  #quality = new Map<string, ScreenQuality>();
  // setScreenQuality calls run one at a time per participant.
  #qualityTurn = new Map<string, Promise<void>>();
  // Bumped by forgetParticipant: a quality change begun before it is stale.
  #generation = new Map<string, number>();

  constructor(chat: MoqtChatClient, callbacks: MoqtScreenCallbacks) {
    this.#chat = chat;
    this.#callbacks = callbacks;
  }

  /** Whether shares go out as two variants and watchers may switch:
   * MoqtChatClient.trackSwitching (draft-22, hub advertised SSTS). */
  get variantsEnabled(): boolean {
    return this.#chat.trackSwitching;
  }

  /** Whether "<id>/screen-lo" is PUBLISHed on this session (the hub may
   * refuse it, e.g. over its per-peer track limit): only then is the lo
   * encoder worth running. */
  get loPublished(): boolean {
    return this.#loPublished;
  }

  /** Drops a participant who left: its quality choice, Group gate, and any
   * held live chunks (its subscriptions are the chat client's to cancel). */
  forgetParticipant(participantId: string): void {
    this.#quality.delete(participantId);
    this.#gates.delete(participantId);
    this.#joining.delete(participantId);
    this.#qualityTurn.delete(participantId);
    this.#generation.set(participantId, this.#generationOf(participantId) + 1);
  }

  #generationOf(participantId: string): number {
    return this.#generation.get(participantId) ?? 0;
  }


  /** The next Group ID, shared by both variants: the screen pipeline takes
   * one per keyframe decision, so Group g of hi and lo open on the same
   * captured frame. */
  allocateGroup(): bigint {
    return this.#groupId++;
  }

  /** PUBLISHes this client's "<id>/screen" track -- plus "<id>/screen-lo"
   * when variantsEnabled -- (once per session: a later share reuses them)
   * and announces wired/moqt_chat/<id>/screen so the room's watchers
   * subscribe. No stream is opened here -- sendVideoChunk opens one per
   * Group. */
  async publishScreenTrack(): Promise<void> {
    const id = this.#chat.localId;
    if (!this.#published) {
      this.#published = await this.#chat.publishTrack(screenTrackName(id), ownScreenTrackAlias(id));
    }
    if (!this.#loPublished && this.variantsEnabled) {
      this.#loPublished = await this.#chat.publishTrack(screenTrackName(id, "lo"), screenVariantAlias(id, "lo"));
    }
    this.#announcement = await this.#chat.publishNamespace([id, "screen"]);
  }

  /** The quality chosen for participantId's tile ("auto" until set). */
  screenQuality(participantId: string): ScreenQuality {
    return this.#quality.get(participantId) ?? "auto";
  }

  /** SUBSCRIBEs to participantId's screen share starting at the Next
   * Object, plus a history of the current Group (joiningStart 0: a d22
   * fill of Relative Start 1, or a d19 Relative Joining FETCH with Joining
   * Start 0): every Group opens with a keyframe, so a late joiner decodes
   * from there instead of waiting for the next one. With track switching and
   * a negotiated SSTS algorithm, "auto" subscribes both variants into one
   * switching set; "high"/"low" subscribe that variant alone. */
  async subscribeToScreenTrack(participantId: string): Promise<void> {
    const variants = this.#plan(participantId);
    if (this.variantsEnabled) this.#gates.set(participantId, {});
    else this.#gates.delete(participantId);
    const hold: JoinHold = { held: [], pending: variants.length };
    this.#joining.set(participantId, hold);
    await Promise.all(variants.map(({ variant, params }) => this.#subscribeVariant(participantId, variant, hold, params)));
  }

  // What subscribeToScreenTrack sends: the SSTS pair, one chosen variant,
  // or (no switching) hi alone.
  #plan(participantId: string): { variant: ScreenVariant; params: MessageParam[] }[] {
    const quality = this.screenQuality(participantId);
    if (!this.variantsEnabled) return [{ variant: "hi", params: [] }];
    if (quality !== "auto") return [{ variant: QUALITY_VARIANT[quality], params: [] }];
    const algorithmId = this.#chat.sstsAlgorithm;
    if (algorithmId === undefined) return [{ variant: "hi", params: [] }];
    const setId = BigInt(CANDIDATE_PARTICIPANT_IDS.indexOf(participantId));
    const ssa = (variant: ScreenVariant) =>
      switchingSetAssignmentParam({
        setId,
        algorithmId,
        thresholdKbps: SCREEN_SSTS_THRESHOLD_KBPS[variant],
        weight: SSTS_WEIGHT,
        activate: SSTS_ACTIVATE,
      });
    return (["hi", "lo"] as const).map((variant) => ({ variant, params: [ssa(variant)] }));
  }

  async #subscribeVariant(
    participantId: string,
    variant: ScreenVariant,
    hold: JoinHold,
    params: MessageParam[],
  ): Promise<void> {
    let ended = false;
    const done = () => {
      if (ended) return;
      ended = true;
      this.#releaseHold(participantId, hold);
    };
    // A share restarted while still subscribed sends no new SUBSCRIBE, so no
    // fetch will end the hold: release it now.
    const sent = await this.#chat.subscribeTrack(
      screenTrackName(participantId, variant),
      screenLabel(participantId, variant),
      {
        joiningStart: 0n,
        onObject: (o) => {
          try {
            const { chunk } = decodeScreenObjectMessage(o.payload);
            this.#deliver(participantId, { chunk, group: o.group, variant, live: false });
          } catch {
            // a malformed fetched chunk is skipped, like a live one
          }
        },
        onDone: done,
      },
      { params },
    );
    if (!sent) done();
  }

  // One history of `hold` ended; the last one releases its held live chunks
  // (unless a newer subscribe replaced the hold meanwhile).
  #releaseHold(participantId: string, hold: JoinHold): void {
    hold.pending -= 1;
    if (hold.pending > 0 || this.#joining.get(participantId) !== hold) return;
    this.#joining.delete(participantId);
    for (const item of hold.held) this.#deliver(participantId, item);
  }

  /** Changes participantId's tile quality. Between "high" and "low" it is
   * one SUBSCRIBE carrying SWITCH_FROM (Soft, Publish Done) of the current
   * subscription -- the hub ends the old one at the Group boundary -- and
   * the quality only changes once that SUBSCRIBE is accepted. To or from
   * "auto" the current subscriptions are cancelled and the new plan
   * subscribed; a variant the sender does not have (its SUBSCRIBE refused)
   * restores the previous choice. Calls for one participant run in order,
   * each after the previous one settled. A no-op without track switching. */
  setScreenQuality(participantId: string, quality: ScreenQuality): Promise<void> {
    const generation = this.#generationOf(participantId);
    const turn = (this.#qualityTurn.get(participantId) ?? Promise.resolve())
      .then(() => this.#applyQuality(participantId, quality, generation))
      .catch(() => {});
    this.#qualityTurn.set(participantId, turn);
    return turn;
  }

  async #applyQuality(participantId: string, quality: ScreenQuality, generation: number): Promise<void> {
    const stale = () => this.#generationOf(participantId) !== generation;
    const prev = this.screenQuality(participantId);
    if (stale() || !this.variantsEnabled || prev === quality) return;
    // A stale change (its participant left) just stops: touching state or
    // labels now could hit a rejoined peer's fresh subscriptions under the
    // same id. Nothing of the old one needs cleaning -- the chat client's
    // #dropPeer cancelled every SUBSCRIBE made before the leave, and its
    // stale-answer guard cancels any still in flight.
    if (prev !== "auto" && quality !== "auto") {
      await this.#switchVariant(participantId, QUALITY_VARIANT[prev], QUALITY_VARIANT[quality], stale);
      if (stale()) return;
      if (this.#chat.isSubscribed(screenLabel(participantId, QUALITY_VARIANT[quality]))) {
        this.#quality.set(participantId, quality);
      }
      return;
    }
    await this.#resubscribe(participantId, quality);
    if (stale()) return;
    if (quality === "auto" || this.#chat.isSubscribed(screenLabel(participantId, QUALITY_VARIANT[quality]))) return;
    await this.#resubscribe(participantId, prev); // no such variant: back to what played
  }

  async #resubscribe(participantId: string, quality: ScreenQuality): Promise<void> {
    this.#quality.set(participantId, quality);
    for (const variant of ["hi", "lo"] as const) this.#chat.unsubscribe(screenLabel(participantId, variant));
    await this.subscribeToScreenTrack(participantId);
  }

  async #switchVariant(
    participantId: string,
    from: ScreenVariant,
    to: ScreenVariant,
    stale: () => boolean,
  ): Promise<void> {
    const fromLabel = screenLabel(participantId, from);
    const rid = await this.#chat.subscriptionRequestId(fromLabel);
    if (stale()) return; // left while we looked: send nothing
    const params = rid === undefined ? [] : [switchFromParam({ requestId: rid, mode: SWITCH_MODE_SOFT, publishDone: true })];
    await this.#chat.subscribeTrack(screenTrackName(participantId, to), screenLabel(participantId, to), undefined, {
      params,
    });
    if (this.#chat.isSubscribed(screenLabel(participantId, to))) this.#chat.forgetSubscription(fromLabel);
  }

  // The one way out to onScreenChunk: held while a history runs, then
  // through the participant's Group gate (track switching only).
  #deliver(participantId: string, item: ScreenItem): void {
    const gate = this.#gates.get(participantId);
    if (gate && !screenGroupGateAccept(gate, item.group, item.variant, item.chunk.keyframe, item.live)) return;
    this.#callbacks.onScreenChunk(participantId, item.chunk, item.variant);
  }

  #emitLive(participantId: string, item: ScreenItem): void {
    const hold = this.#joining.get(participantId);
    if (hold) hold.held.push(item);
    else this.#deliver(participantId, item);
  }

  /** Sends one video chunk as an Object on its variant's current Group
   * stream (SUBGROUP_HEADER once per stream, bare Objects after it). A new
   * Group -- `opts.group` changing, or without it a keyframe's first chunk --
   * FINs the previous stream and opens a fresh one. A lo chunk while lo is
   * not published is dropped. Callers must serialize calls per variant
   * through sendGate.ts (same contract as sendOpusFrame) -- this method does
   * not lock the writer itself. */
  async sendVideoChunk(chunk: ScreenChunk, opts: ScreenSendOptions = {}): Promise<void> {
    const variant = opts.variant ?? "hi";
    if (variant === "lo" && !this.#loPublished) return;
    const lane = this.#lanes[variant];
    if (opts.group !== undefined && opts.group === lane.dead) return;
    lane.dead = undefined;
    const newGroup = opts.group === undefined ? chunk.keyframe && chunk.idx === 0 : opts.group !== lane.group;
    if (newGroup && lane.writer) {
      void lane.writer.close().catch(() => {});
      lane.writer = undefined;
    }
    const body = encodeScreenObjectMessage(chunk);
    // objectIdDelta 0 on every call is correct either way -- FIRST_OBJECT
    // mode makes the first one's delta the absolute id (0), and
    // decodeSubgroupObject's own chaining rule (prevId + delta + 1) turns a
    // delta of 0 into a plain increment for every Object after that
    // (mirrors encodeVoiceObjectMessage's own doc).
    const object = concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    try {
      await withTimeout(this.#write(variant, opts.group, object), SCREEN_WRITE_TIMEOUT_MS);
    } catch (err) {
      // A hung or failed write means this stream is dead for good; drop it
      // so the next chunk starts over, rather than queueing behind it.
      lane.writer?.abort().catch(() => {});
      lane.writer = undefined;
      lane.group = undefined;
      lane.dead = opts.group;
      this.#callbacks.onStreamReset?.();
      throw err;
    }
  }

  async #write(variant: ScreenVariant, group: bigint | undefined, object: Uint8Array): Promise<void> {
    const lane = this.#lanes[variant];
    if (lane.writer) {
      await lane.writer.write(object);
      return;
    }
    const wt = this.#chat.webTransport;
    if (!wt) return;
    const groupId = group ?? this.#groupId++;
    if (this.#groupId <= groupId) this.#groupId = groupId + 1n;
    lane.group = groupId;
    const stream = await wt.createUnidirectionalStream();
    lane.writer = stream.getWriter();
    const alias = screenVariantAlias(this.#chat.localId, variant);
    await lane.writer.write(concatBytes([buildScreenSubgroupHeader(alias, groupId), object]));
  }

  /** Routes one incoming uni stream to onScreenChunk if its Track Alias
   * resolves to a known participant's screen track (either variant) --
   * called from useMoqtChat.ts's onUnknownUniStream. Like voice, decodes
   * incrementally as chunks arrive rather than reading to EOF first (a
   * share can run for the whole call). */
  handleIncomingStream(
    header: SubgroupHeader,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): void {
    const owner = screenAliasOwner(header.trackAlias);
    if (!owner) {
      reader.cancel().catch(() => {});
      return;
    }
    this.#readOneScreenStream(owner.participant, owner.variant, header.groupId, firstChunk, reader);
  }

  async #readOneScreenStream(
    participant: string,
    variant: ScreenVariant,
    group: bigint,
    firstChunk: Uint8Array,
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): Promise<void> {
    let buffered = firstChunk;
    const seq: ScreenObjectSeq = { prevObjectId: 0n, isFirst: true };
    const onChunk = (chunk: ScreenChunk) => this.#emitLive(participant, { chunk, group, variant, live: true });
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

  /** FINs the send streams, if any were ever opened, and withdraws the
   * <id>/screen announcement. */
  close(): void {
    for (const lane of Object.values(this.#lanes)) {
      lane.writer?.close().catch(() => {});
      lane.writer = undefined;
      lane.group = undefined;
    }
    this.#announcement?.cancel();
    this.#announcement = undefined;
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
 * buffered.length` is checked explicitly. */
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
