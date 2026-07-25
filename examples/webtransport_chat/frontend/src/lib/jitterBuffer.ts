// Per-sender jitter buffer for reassembling voice frames into playback
// order, with a design verified against a formal model of its state
// machine: serial-number comparison (newer), self-echo filtering across
// every own sender ID ever used (usedOwn), and overflow eviction of the
// serial-oldest of buffer+newcomer (a duplicate arriving at a full buffer
// is simply discarded, never routed through overflow).

const SEQ_SPACE = 0x10000;
const HALF = SEQ_SPACE / 2;

// True when `a` is strictly newer than `b` in u16 serial-number arithmetic.
function newer(a: number, b: number): boolean {
  const d = (a + SEQ_SPACE - b) % SEQ_SPACE;
  return d !== 0 && d < HALF;
}

type SenderState = {
  buf: number[]; // buffered seqs, unsorted arrival order
  hasPlayed: boolean;
  lastSeq: number;
};

function freshSender(): SenderState {
  return { buf: [], hasPlayed: false, lastSeq: 0 };
}

function oldest(seqs: number[]): number {
  return seqs.reduce((o, s) => (newer(o, s) ? s : o));
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
    if (this.isOld(state, seq)) return;
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

  // Start a fresh session: new own ID (remembered alongside every prior
  // one), every sender's buffer and playback cursor wiped.
  reconnect(newOwnId: string): void {
    this.myId = newOwnId;
    this.usedOwn.add(newOwnId);
    this.senders.clear();
  }
}
