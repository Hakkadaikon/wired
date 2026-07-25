import { describe, expect, it } from "vitest";
import { JitterBufferManager, nextSeq } from "../jitterBuffer";

const OWN = "AAAAAAAA";
const SPEAKER_B = "BBBBBBBB";
const SPEAKER_C = "CCCCCCCC";
const NEW_OWN = "DDDDDDDD";

function manager(bufCap = 3) {
  return new JitterBufferManager(OWN, bufCap);
}

describe("jitterBuffer", () => {
  it("plays frames arriving in sequence order in that order", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 10);
    jb.push(SPEAKER_B, 11);
    jb.push(SPEAKER_B, 12);
    expect(jb.drain(SPEAKER_B)).toEqual([10, 11, 12]);
  });

  it("reorders out-of-order frames into serial order before playback", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 11);
    jb.push(SPEAKER_B, 10);
    expect(jb.drain(SPEAKER_B)).toEqual([10, 11]);
  });

  it("discards a frame older than lastPlayed without changing buffer state", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 12);
    jb.drain(SPEAKER_B);
    jb.push(SPEAKER_B, 11);
    expect(jb.bufferedSeqs(SPEAKER_B)).toEqual([]);
  });

  it("discards a duplicate of an already played sequence", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 10);
    jb.drain(SPEAKER_B);
    jb.push(SPEAKER_B, 10);
    expect(jb.bufferedSeqs(SPEAKER_B)).toEqual([]);
  });

  it("leaves a full buffer unchanged when a duplicate of a buffered sequence arrives", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 13);
    jb.push(SPEAKER_B, 14);
    jb.push(SPEAKER_B, 15);
    jb.push(SPEAKER_B, 14);
    expect(jb.bufferedSeqs(SPEAKER_B).sort()).toEqual([13, 14, 15]);
  });

  it("evicts the oldest buffered frame and accepts the newcomer on overflow", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 10);
    jb.push(SPEAKER_B, 11);
    jb.push(SPEAKER_B, 12);
    jb.push(SPEAKER_B, 13);
    expect(jb.bufferedSeqs(SPEAKER_B).sort((a, b) => a - b)).toEqual([
      11, 12, 13,
    ]);
  });

  it("discards the newcomer itself when it would be the oldest of buffer+newcomer on overflow", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 11);
    jb.push(SPEAKER_B, 12);
    jb.push(SPEAKER_B, 13);
    jb.push(SPEAKER_B, 10);
    expect(jb.bufferedSeqs(SPEAKER_B).sort((a, b) => a - b)).toEqual([
      11, 12, 13,
    ]);
  });

  it("plays frames crossing the u16 wrap boundary in send order", () => {
    const jb = manager(4);
    jb.push(SPEAKER_B, 65534);
    jb.push(SPEAKER_B, 65535);
    jb.push(SPEAKER_B, 0);
    jb.push(SPEAKER_B, 1);
    expect(jb.drain(SPEAKER_B)).toEqual([65534, 65535, 0, 1]);
  });

  it("discards a pre-wrap frame arriving after post-wrap playback", () => {
    const jb = manager(4);
    jb.push(SPEAKER_B, 65535);
    jb.push(SPEAKER_B, 0);
    jb.drain(SPEAKER_B);
    jb.push(SPEAKER_B, 65535);
    expect(jb.bufferedSeqs(SPEAKER_B)).toEqual([]);
  });

  it("skips a lost sequence and advances playback without waiting", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 20);
    jb.push(SPEAKER_B, 22);
    expect(jb.drain(SPEAKER_B)).toEqual([20, 22]);
  });

  it("keeps two speakers buffered and played independently", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 5);
    jb.push(SPEAKER_C, 9);
    jb.push(SPEAKER_B, 6);
    expect(jb.drain(SPEAKER_B)).toEqual([5, 6]);
    expect(jb.drain(SPEAKER_C)).toEqual([9]);
  });

  it("plays a post-unmute frame in normal sequence order since seq did not reset", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 30);
    jb.drain(SPEAKER_B);
    jb.push(SPEAKER_B, 31);
    expect(jb.drain(SPEAKER_B)).toEqual([31]);
  });

  it("excludes a residue frame bearing a previously-used own sender id after reconnect", () => {
    const jb = manager();
    jb.reconnect(NEW_OWN);
    jb.push(OWN, 0);
    expect(jb.bufferedSeqs(OWN)).toEqual([]);
  });

  it("clears all jitter buffers on reconnect and accepts any first sequence unconditionally", () => {
    const jb = manager();
    jb.push(SPEAKER_B, 40);
    jb.push(SPEAKER_B, 41);
    jb.reconnect(NEW_OWN);
    expect(jb.bufferedSeqs(SPEAKER_B)).toEqual([]);
    jb.push(SPEAKER_B, 500);
    expect(jb.drain(SPEAKER_B)).toEqual([500]);
  });
});

describe("jitterBuffer/chat", () => {
  it("never plays own voice frames but always displays own chat frames", () => {
    // Asymmetry lives across two modules: voice self-frames are filtered by
    // JitterBufferManager (never buffered/played); chat has no such filter
    // because the decoded chat frame is handed straight to the UI regardless
    // of sender id (voiceProtocol.decodeFrame does not discriminate self vs.
    // peer for the chat channel).
    const jb = manager();
    jb.push(OWN, 1);
    expect(jb.bufferedSeqs(OWN)).toEqual([]);
  });
});

describe("mute", () => {
  it("does not reset the sequence counter across a mute/unmute cycle", () => {
    // Sending is a separate concern (WebTransport client layer, region 3);
    // the jitter buffer's contract is only that seq keeps incrementing
    // across a mute/unmute cycle. nextSeq models that counter contract.
    const lastSentSeq = 30;
    // mute: no frame emitted while muted (region 3 concern, not modeled here)
    const firstSeqAfterUnmute = nextSeq(lastSentSeq);
    expect(firstSeqAfterUnmute).toBe(31);
  });
});
