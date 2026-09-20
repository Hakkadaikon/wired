// Per-sender jitter buffer for reassembling voice frames into playback
// order, with a design verified against a formal model of its state
// machine: serial-number comparison (newer), self-echo filtering across
// every own sender ID ever used (usedOwn), and overflow eviction of the
// serial-oldest of buffer+newcomer (a duplicate arriving at a full buffer
// is simply discarded, never routed through overflow).

const SEQ_SPACE = 0x10000;
const HALF = SEQ_SPACE / 2;

// Q-A adaptive pull() constants (one call == one 20 ms tick).
const TARGET_START = 2;
const GAP_WAIT_TICKS = 3;
const REPRIME_TICKS = 10;
const EXCESS = 2;
const DECAY_TICKS = 250;
const MAX_PER_TICK = 2;

export type Pull = { type: "frame" | "lost"; seq: number } | { type: "wait" };

// True when `a` is strictly newer than `b` in u16 serial-number arithmetic.
function newer(a: number, b: number): boolean {
  const d = (a + SEQ_SPACE - b) % SEQ_SPACE;
  return d !== 0 && d < HALF;
}

type SenderState = {
  buf: number[]; // buffered seqs, unsorted arrival order
  hasPlayed: boolean;
  lastSeq: number;
  // Q-A pull() state: not modeled by push()/drain() above.
  primed: boolean;
  waitTicks: number; // shared by prebuffer wait and steady-state gap wait
  emptyTicks: number; // consecutive ticks seen with an empty buffer
  target: number;
  late: boolean; // an isOld push landed since the last pull() consumed it
  cleanTicks: number; // consecutive pull() ticks with no late push
};

function freshSender(): SenderState {
  return {
    buf: [],
    hasPlayed: false,
    lastSeq: 0,
    primed: false,
    waitTicks: 0,
    emptyTicks: 0,
    target: TARGET_START,
    late: false,
    cleanTicks: 0,
  };
}

function oldest(seqs: number[]): number {
  return seqs.reduce((o, s) => (newer(o, s) ? s : o));
}

// Consume the sender's expected seq -- advance the cursor and return it.
// Callers decide whether that means a played frame or a reported loss.
function advanceCursor(state: SenderState, expected: number): void {
  state.hasPlayed = true;
  state.lastSeq = expected;
  state.waitTicks = 0;
}

// The next seq playback is waiting for: send-order successor of the last
// played/lost seq, or the oldest buffered seq before anything has played.
function expectedSeq(state: SenderState): number {
  return state.hasPlayed ? nextSeq(state.lastSeq) : oldest(state.buf);
}

// One steady-state emission attempt (primed): play the expected seq if
// buffered, else wait/report-lost per the shared GAP_WAIT_TICKS budget.
function steadyStep(state: SenderState): Pull {
  const expected = expectedSeq(state);
  const idx = state.buf.indexOf(expected);
  if (idx !== -1) {
    state.buf.splice(idx, 1);
    advanceCursor(state, expected);
    return { type: "frame", seq: expected };
  }
  if (state.buf.length >= state.target || state.waitTicks >= GAP_WAIT_TICKS) {
    advanceCursor(state, expected);
    return { type: "lost", seq: expected };
  }
  state.waitTicks++;
  return { type: "wait" };
}

// One prebuffer emission attempt (not yet primed): D-3 -- the wait shares
// waitTicks/GAP_WAIT_TICKS with the steady-state gap wait, so a lone
// trailing frame below target still plays after at most 3 wait ticks
// instead of stalling until the target decays down to it.
function primeStep(state: SenderState): Pull {
  if (state.buf.length >= state.target || state.waitTicks >= GAP_WAIT_TICKS) {
    state.primed = true;
    state.waitTicks = 0;
    // N-7: reaching target primes AND emits in the same tick.
    return state.buf.length === 0 ? { type: "wait" } : steadyStep(state);
  }
  state.waitTicks++;
  return { type: "wait" };
}

function emitOne(state: SenderState): Pull {
  return state.primed ? steadyStep(state) : primeStep(state);
}

// N-3: an isOld push sets `late`; each pull() tick consumes it at most once
// (raising target by 1, capped at bufCap) and otherwise counts the tick
// toward DECAY_TICKS, lowering target by 1 (floor 1) once reached.
function adapt(state: SenderState, bufCap: number): void {
  if (state.late) {
    state.late = false;
    state.target = Math.min(state.target + 1, bufCap);
    state.cleanTicks = 0;
    return;
  }
  state.cleanTicks++;
  if (state.cleanTicks >= DECAY_TICKS) {
    state.target = Math.max(state.target - 1, 1);
    state.cleanTicks = 0;
  }
}

// Wire sequence counter contract: increments (mod u16 space) every sent
// frame, mute or not -- muting only skips the send, never resets this
// counter.
export function nextSeq(seq: number): number {
  return (seq + 1) % SEQ_SPACE;
}

export class JitterBufferManager {
  private usedOwn: Set<string>;
  private senders = new Map<string, SenderState>();

  constructor(
    private myId: string,
    private bufCap: number,
  ) {
    this.usedOwn = new Set([myId]);
  }

  private stateFor(senderId: string): SenderState {
    let s = this.senders.get(senderId);
    if (!s) {
      s = freshSender();
      this.senders.set(senderId, s);
    }
    return s;
  }

  private isSelf(senderId: string): boolean {
    return this.usedOwn.has(senderId);
  }

  private isOld(state: SenderState, seq: number): boolean {
    return state.hasPlayed && !newer(seq, state.lastSeq);
  }

  // Handle one arriving voice frame: buffer it, evict on overflow, or
  // discard it (self-echo, stale, duplicate, or duplicate-at-full-buffer).
  push(senderId: string, seq: number): void {
    if (this.isSelf(senderId)) return;
    const state = this.stateFor(senderId);
    if (this.isOld(state, seq)) {
      // N-3: a stale push is always counted late, whether it is a genuine
      // late arrival or a network duplicate of an already-played sequence --
      // the two are indistinguishable here and the cost of conflating them
      // is bounded by bufCap/DECAY_TICKS, so no extra bookkeeping is worth it.
      state.late = true;
      return;
    }
    if (state.buf.includes(seq)) return; // duplicate: never grows/shrinks the buffer
    if (state.buf.length < this.bufCap) {
      state.buf.push(seq);
      return;
    }
    // Full buffer: evict the serial-oldest of buffer+newcomer.
    const candidate = oldest([...state.buf, seq]);
    if (candidate === seq) return; // newcomer itself is the oldest: drop it
    state.buf = state.buf.filter((s) => s !== candidate);
    state.buf.push(seq);
  }

  // Drain every currently-buffered frame for one sender in serial (send)
  // order, advancing the playback cursor. Gaps are never waited on.
  drain(senderId: string): number[] {
    const state = this.stateFor(senderId);
    const ordered = [...state.buf].sort((a, b) => (newer(a, b) ? 1 : -1));
    state.buf = [];
    for (const seq of ordered) {
      state.hasPlayed = true;
      state.lastSeq = seq;
    }
    return ordered;
  }

  bufferedSeqs(senderId: string): number[] {
    return [...this.stateFor(senderId).buf];
  }

  // One 20 ms tick: adapt the target from any late push seen since the
  // last tick, track REPRIME_TICKS of silence, then emit up to
  // MAX_PER_TICK items (N-6: the burst check re-reads depth after the
  // first emission).
  pull(senderId: string): Pull[] {
    const state = this.stateFor(senderId);
    adapt(state, this.bufCap);
    if (state.buf.length === 0) {
      state.emptyTicks++;
      if (state.emptyTicks >= REPRIME_TICKS) {
        state.primed = false;
        state.waitTicks = 0;
        state.emptyTicks = 0;
      }
      return [{ type: "wait" }];
    }
    state.emptyTicks = 0;

    const results: Pull[] = [emitOne(state)];
    if (results[0].type !== "wait" && state.buf.length > state.target + EXCESS) {
      results.push(emitOne(state));
    }
    return results.slice(0, MAX_PER_TICK);
  }

  // Read-only accessor for tests/tap: current adaptive target depth.
  targetDepth(senderId: string): number {
    return this.stateFor(senderId).target;
  }

  // Start a fresh session: new own ID (remembered alongside every prior
  // one), every sender's buffer and playback cursor wiped.
  reconnect(newOwnId: string): void {
    this.myId = newOwnId;
    this.usedOwn.add(newOwnId);
    this.senders.clear();
  }
}
