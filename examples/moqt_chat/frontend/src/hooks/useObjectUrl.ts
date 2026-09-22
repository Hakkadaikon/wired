"use client";

import { useEffect, useRef, useState } from "react";

// One Blob URL per draft attachment: created once for the given bytes, and
// revoked on unmount (or when the bytes identity changes) -- so removing a
// draft item and letting it unmount is what frees the URL, rather than the
// caller managing a URL map by hand.
export function useObjectUrl(bytes: Uint8Array, mimeType: string): string {
  const [url] = useState(() => URL.createObjectURL(new Blob([bytes as BlobPart], { type: mimeType })));
  const urlRef = useRef(url);
  useEffect(() => () => URL.revokeObjectURL(urlRef.current), []);
  return url;
}
