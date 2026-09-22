// Pure limit/type checks for a chat attachment (image or video), shared by
// the file-picker and clipboard-paste paths in Compose (page.tsx). Kept
// framework-free so it's testable without @testing-library/react (this
// codebase's own rule: components aren't tested, extracted pure functions
// are).

export const ATTACHMENT_MAX_BYTES = 5 * 1024 * 1024;
export const ATTACHMENT_MAX_COUNT = 4;

/** image/* and video/* only -- the two kinds Compose/Message can render. */
export function isAllowedAttachmentMimeType(mimeType: string): boolean {
  return mimeType.startsWith("image/") || mimeType.startsWith("video/");
}

export type AttachmentRejectionReason = "too-large" | "too-many" | "unsupported-type";
export type AttachmentValidationResult = { ok: true } | { ok: false; reason: AttachmentRejectionReason };

/** Checks one candidate file against the size/count/type limits.
 * `existingCount` is the number of attachments already in the draft, so the
 * caller can validate each newly picked/pasted file one at a time as the
 * count grows. */
export function validateAttachmentCandidate(
  file: { byteLength: number; mimeType: string },
  existingCount: number,
): AttachmentValidationResult {
  if (existingCount >= ATTACHMENT_MAX_COUNT) return { ok: false, reason: "too-many" };
  if (!isAllowedAttachmentMimeType(file.mimeType)) return { ok: false, reason: "unsupported-type" };
  if (file.byteLength > ATTACHMENT_MAX_BYTES) return { ok: false, reason: "too-large" };
  return { ok: true };
}
