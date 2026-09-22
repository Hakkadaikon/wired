import { describe, expect, it } from "vitest";
import {
  ATTACHMENT_MAX_BYTES,
  ATTACHMENT_MAX_COUNT,
  isAllowedAttachmentMimeType,
  validateAttachmentCandidate,
} from "../attachmentValidation";

describe("isAllowedAttachmentMimeType", () => {
  it("allows image/* and video/*", () => {
    expect(isAllowedAttachmentMimeType("image/png")).toBe(true);
    expect(isAllowedAttachmentMimeType("video/mp4")).toBe(true);
  });

  it("rejects any other MIME type", () => {
    expect(isAllowedAttachmentMimeType("application/pdf")).toBe(false);
    expect(isAllowedAttachmentMimeType("text/plain")).toBe(false);
  });
});

describe("validateAttachmentCandidate", () => {
  it("accepts a file at or under the 5MB limit", () => {
    expect(
      validateAttachmentCandidate({ byteLength: ATTACHMENT_MAX_BYTES, mimeType: "image/png" }, 0),
    ).toEqual({ ok: true });
  });

  it("rejects a file over the 5MB limit", () => {
    expect(
      validateAttachmentCandidate(
        { byteLength: ATTACHMENT_MAX_BYTES + 1, mimeType: "image/png" },
        0,
      ),
    ).toEqual({ ok: false, reason: "too-large" });
  });

  it("accepts up to the 4-attachment limit (existing + new)", () => {
    expect(
      validateAttachmentCandidate(
        { byteLength: 100, mimeType: "image/png" },
        ATTACHMENT_MAX_COUNT - 1,
      ),
    ).toEqual({ ok: true });
  });

  it("rejects once existing + new would exceed the 4-attachment limit", () => {
    expect(
      validateAttachmentCandidate({ byteLength: 100, mimeType: "image/png" }, ATTACHMENT_MAX_COUNT),
    ).toEqual({ ok: false, reason: "too-many" });
  });

  it("rejects a disallowed MIME type", () => {
    expect(validateAttachmentCandidate({ byteLength: 100, mimeType: "application/pdf" }, 0)).toEqual({
      ok: false,
      reason: "unsupported-type",
    });
  });
});
