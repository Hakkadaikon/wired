import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { JitterBufferManager } from "../jitterBuffer";

const OWN = "AAAAAAAA";
const SPEAKER_B = "BBBBBBBB";

// Q-A adaptive pull() tests use the full bufCap (8) per the design.
function manager(bufCap = 8) {
  return new JitterBufferManager(OWN, bufCap);
}

describe("jitterBuffer/pull prebuffer", () => {
  it("prebuffer holds playback until the target depth is reached", () => {
    const jb = manager();
    expect(jb.targetDepth(SPEAKER_B)).toBe(2);
    jb.push(SPEAKER_B, 10);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    jb.push(SPEAKER_B, 11);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 10 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 11 }]);
  });

  it("a lone trailing frame below the target depth plays after the prebuffer timeout", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 5);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 5 }]);
  });
});

describe("jitterBuffer/pull steady state", () => {
  function primed11(jb: JitterBufferManager) {
    jb.push(SPEAKER_B, 10);
    jb.push(SPEAKER_B, 11);
    jb.pull(SPEAKER_B); // frame 10
    jb.pull(SPEAKER_B); // frame 11 -> lastSeq=11, primed=true
  }

  it("steady arrival of one frame per tick plays one frame per tick", () => {
    const jb = manager();
    primed11(jb);
    jb.push(SPEAKER_B, 12);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 12 }]);
    jb.push(SPEAKER_B, 13);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 13 }]);
    jb.push(SPEAKER_B, 14);
    const r = jb.pull(SPEAKER_B);
    expect(r).toEqual([{ type: "frame", seq: 14 }]);
    expect(r.length).toBe(1);
  });

  it("a gap is waited for three ticks and reported lost on the fourth", () => {
    const jb = manager();
    primed11(jb);
    jb.push(SPEAKER_B, 13);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "lost", seq: 12 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 13 }]);
  });

  it("the awaited frame arriving during the gap wait is played with no lost", () => {
    const jb = manager();
    primed11(jb);
    jb.push(SPEAKER_B, 13);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    jb.push(SPEAKER_B, 12);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 12 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 13 }]);
  });

  it("a gap with the buffer at target depth is reported lost immediately", () => {
    const jb = manager();
    primed11(jb);
    jb.push(SPEAKER_B, 13);
    jb.push(SPEAKER_B, 14);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "lost", seq: 12 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 13 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 14 }]);
  });

  it("an over-full buffer drains two frames in one tick", () => {
    const jb = manager();
    primed11(jb);
    for (const seq of [12, 13, 14, 15, 16, 17]) jb.push(SPEAKER_B, seq);
    expect(jb.pull(SPEAKER_B)).toEqual([
      { type: "frame", seq: 12 },
      { type: "frame", seq: 13 },
    ]);
  });

  it("a sequence reported lost is discarded when it finally arrives", () => {
    const jb = manager();
    primed11(jb);
    jb.push(SPEAKER_B, 13);
    jb.push(SPEAKER_B, 14);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "lost", seq: 12 }]); // lost 12
    jb.push(SPEAKER_B, 12);
    expect(jb.bufferedSeqs(SPEAKER_B).sort((a, b) => a - b)).toEqual([13, 14]);
    expect(jb.targetDepth(SPEAKER_B)).toBe(2);
    jb.pull(SPEAKER_B); // consumes the late flag, target -> 3
    expect(jb.targetDepth(SPEAKER_B)).toBe(3);
  });
});

describe("jitterBuffer/pull reprime", () => {
  it("ten consecutive empty ticks unprime the playback", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 20);
    jb.pull(SPEAKER_B); // wait (prebuffer, len1<2)
    jb.push(SPEAKER_B, 21);
    jb.pull(SPEAKER_B); // primes + emits frame 20 (buf now has 21 left... )
    // Re-derive a clean primed-at-20 state instead of reusing the above.
    const jb2 = manager();
    jb2.push(SPEAKER_B, 19);
    jb2.push(SPEAKER_B, 20);
    jb2.pull(SPEAKER_B); // frame 19
    jb2.pull(SPEAKER_B); // frame 20, primed, lastSeq=20
    for (let i = 0; i < 10; i++) {
      expect(jb2.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    }
    jb2.push(SPEAKER_B, 21);
    expect(jb2.pull(SPEAKER_B)).toEqual([{ type: "wait" }]);
    jb2.push(SPEAKER_B, 22);
    expect(jb2.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 21 }]);
  });

  it("a sequence reported lost before a silence is still rejected after reprime", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 10);
    jb.push(SPEAKER_B, 11);
    jb.pull(SPEAKER_B); // frame 10
    jb.pull(SPEAKER_B); // frame 11, primed, lastSeq=11
    jb.push(SPEAKER_B, 13);
    jb.pull(SPEAKER_B); // wait
    jb.pull(SPEAKER_B); // wait
    jb.pull(SPEAKER_B); // wait
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "lost", seq: 12 }]); // lastSeq -> 12
    jb.pull(SPEAKER_B); // frame 13
    for (let i = 0; i < 10; i++) jb.pull(SPEAKER_B); // 10 empty ticks -> unprime
    jb.push(SPEAKER_B, 12);
    expect(jb.bufferedSeqs(SPEAKER_B)).toEqual([]);
    expect(jb.targetDepth(SPEAKER_B)).toBe(2);
    jb.pull(SPEAKER_B); // consumes the late flag -> target 3
    expect(jb.targetDepth(SPEAKER_B)).toBe(3);
  });
});

describe("jitterBuffer/pull adaptation", () => {
  it("a late arrival raises the target depth by one", () => {
    const jb = manager();
    for (let seq = 25; seq <= 30; seq++) jb.push(SPEAKER_B, seq);
    // drain up through 30 via drain() (unaffected by pull's own state machine).
    jb.drain(SPEAKER_B);
    expect(jb.targetDepth(SPEAKER_B)).toBe(2);
    jb.push(SPEAKER_B, 29); // isOld: discarded, counted late
    expect(jb.targetDepth(SPEAKER_B)).toBe(2); // not yet consumed
    jb.pull(SPEAKER_B);
    expect(jb.targetDepth(SPEAKER_B)).toBe(3);
  });

  it("the target depth never exceeds the buffer capacity", () => {
    const jb = manager(8);
    for (let seq = 0; seq < 8; seq++) {
      jb.push(SPEAKER_B, seq);
      jb.pull(SPEAKER_B);
    }
    // Force target to bufCap by repeatedly triggering late+pull.
    for (let i = 0; i < 10; i++) {
      jb.push(SPEAKER_B, 0); // always old once hasPlayed -> counted late
      jb.pull(SPEAKER_B);
    }
    expect(jb.targetDepth(SPEAKER_B)).toBe(8);
    jb.push(SPEAKER_B, 0);
    jb.pull(SPEAKER_B);
    expect(jb.targetDepth(SPEAKER_B)).toBe(8);
  });

  it("two hundred fifty late-free ticks lower the target depth by one down to one", () => {
    const jb = manager();
    for (let i = 0; i < 250; i++) jb.pull(SPEAKER_B);
    expect(jb.targetDepth(SPEAKER_B)).toBe(1);
    for (let i = 0; i < 250; i++) jb.pull(SPEAKER_B);
    expect(jb.targetDepth(SPEAKER_B)).toBe(1);
  });
});

describe("jitterBuffer/pull wrap", () => {
  it("pull plays sequences across the u16 wrap in send order", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 65533);
    jb.push(SPEAKER_B, 65534);
    jb.pull(SPEAKER_B); // frame 65533
    jb.pull(SPEAKER_B); // frame 65534, primed, lastSeq=65534
    jb.push(SPEAKER_B, 65535);
    jb.push(SPEAKER_B, 0);
    jb.push(SPEAKER_B, 1);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 65535 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 0 }]);
    expect(jb.pull(SPEAKER_B)).toEqual([{ type: "frame", seq: 1 }]);
  });
});

describe("jitterBuffer/pull property", () => {
  it("interleaved push/pull: emitted seqs increase in serial order, buf never exceeds cap, every emitted frame was pushed", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.oneof(
            fc.record({ kind: fc.constant("push"), seq: fc.integer({ min: 0, max: 65535 }) }),
            fc.record({ kind: fc.constant("pull") }),
          ),
          { minLength: 1, maxLength: 300 },
        ),
        (ops) => {
          const cap = 8;
          const jb = new JitterBufferManager(OWN, cap);
          const pushed = new Set<number>();
          let lastEmitted: number | null = null;
          for (const op of ops) {
            if (op.kind === "push") {
              pushed.add(op.seq);
              jb.push(SPEAKER_B, op.seq);
            } else {
              const results = jb.pull(SPEAKER_B);
              for (const r of results) {
                if (r.type === "frame") {
                  expect(pushed.has(r.seq)).toBe(true);
                  if (lastEmitted !== null) {
                    const d = (r.seq - lastEmitted + 0x10000) % 0x10000;
                    expect(d).toBeGreaterThan(0);
                    expect(d).toBeLessThan(0x8000);
                  }
                  lastEmitted = r.seq;
                }
              }
              expect(jb.bufferedSeqs(SPEAKER_B).length).toBeLessThanOrEqual(cap);
            }
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
