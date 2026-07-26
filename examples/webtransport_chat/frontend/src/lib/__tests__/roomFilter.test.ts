import { describe, expect, it } from "vitest";
import { ROOMS, stripRoomTag, tagWithRoom } from "../roomFilter";

describe("ROOMS", () => {
  it("lists exactly 4 animal room names", () => {
    expect(ROOMS).toHaveLength(4);
    expect(new Set(ROOMS).size).toBe(4);
  });
});

describe("tagWithRoom / stripRoomTag", () => {
  it("round-trips a datagram with its room appended", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const tagged = tagWithRoom(bytes, ROOMS[0]);
    expect(tagged.length).toBe(bytes.length + 1);
    const result = stripRoomTag(tagged);
    expect(result).not.toBeNull();
    expect(result!.room).toBe(ROOMS[0]);
    expect(Array.from(result!.bytes)).toEqual([1, 2, 3]);
  });

  it("distinguishes every room", () => {
    for (const room of ROOMS) {
      const tagged = tagWithRoom(new Uint8Array([9]), room);
      expect(stripRoomTag(tagged)!.room).toBe(room);
    }
  });

  it("returns null for an unknown room byte", () => {
    const bytes = new Uint8Array([1, 2, 3, 0xff]);
    expect(stripRoomTag(bytes)).toBeNull();
  });

  it("returns null for an empty datagram", () => {
    expect(stripRoomTag(new Uint8Array([]))).toBeNull();
  });
});
