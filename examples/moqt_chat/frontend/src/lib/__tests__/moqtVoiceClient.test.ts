import { describe, expect, it } from "vitest";
import { ownAudioTrackAlias } from "../moqtVoiceClient";
import { CANDIDATE_PARTICIPANT_IDS, ownTrackAlias } from "../moqtClient";

describe("ownAudioTrackAlias", () => {
  it("never collides with a chat Track Alias (0..N-1)", () => {
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(ownAudioTrackAlias(id)).toBeGreaterThanOrEqual(
        BigInt(CANDIDATE_PARTICIPANT_IDS.length),
      );
    }
  });

  it("is offset from the same participant's chat alias by the candidate pool size", () => {
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(ownAudioTrackAlias(id) - ownTrackAlias(id)).toBe(
        BigInt(CANDIDATE_PARTICIPANT_IDS.length),
      );
    }
  });

  it("is distinct per participant (no two audio aliases collide)", () => {
    const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownAudioTrackAlias);
    expect(new Set(aliases).size).toBe(aliases.length);
  });
});
