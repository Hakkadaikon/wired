// Thin wrapper around the browser's native WebTransport API.

// "a1b2c3" -> Uint8Array([0xa1, 0xb2, 0xc3]); separators (colons,
// whitespace, newlines from a terminal copy) are stripped.
export function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Parsed serverCertificateHashes entries for the given colon-hex SHA-256
// fingerprints. A SHA-256 hash is exactly 32 bytes; anything else (a byte
// lost while copying from a terminal, a whole log line pasted in) can never
// match and the browser would report only an opaque
// CERTIFICATE_VERIFY_FAILED after a doomed connection attempt -- fail loudly
// up front instead.
export function certHashesToOpts(hexList) {
  return hexList.map((hex) => {
    const bytes = hexToBytes(hex);
    if (bytes.length !== 32) {
      throw new Error(
        `certificate hash must be 32 bytes (SHA-256), got ${bytes.length} -- re-copy the full fingerprint from the server log`,
      );
    }
    return { algorithm: 'sha-256', value: bytes.buffer };
  });
}

export class WebTransportClient {
  #wt;
  #url;
  #certificateHashesHex;
  #pendingReceiveCallback;

  constructor(url, certificateHashesHex = []) {
    this.#url = url;
    this.#certificateHashesHex = certificateHashesHex;
  }

  async connect() {
    const opts = {};
    if (this.#certificateHashesHex.length > 0) {
      opts.serverCertificateHashes = certHashesToOpts(this.#certificateHashesHex);
    }
    this.#wt = new WebTransport(this.#url, opts);
    await this.#wt.ready;
    if (this.#pendingReceiveCallback) {
      this.#readLoop(this.#pendingReceiveCallback);
    }
  }

  async send(bytesUint8Array) {
    const writer = this.#wt.datagrams.writable.getWriter();
    try {
      await writer.write(bytesUint8Array);
    } finally {
      writer.releaseLock();
    }
  }

  // May be called before connect() resolves; the read loop is deferred
  // until the transport is ready.
  onReceive(callback) {
    this.#pendingReceiveCallback = callback;
    if (this.#wt) {
      this.#readLoop(callback);
    }
  }

  async #readLoop(callback) {
    const reader = this.#wt.datagrams.readable.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      callback(value);
    }
  }

  close() {
    this.#wt?.close();
  }
}
