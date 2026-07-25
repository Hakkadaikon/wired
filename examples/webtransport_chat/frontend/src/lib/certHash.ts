// Parses the server's logged sha-256 certificate fingerprint (hex, with or
// without colon separators) into the byte form serverCertificateHashes wants.
// Returns null for empty or malformed input so the caller can skip pinning.
export function parseCertHash(hex: string): Uint8Array | null {
  const clean = hex.replace(/[:\s]/g, "");
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
