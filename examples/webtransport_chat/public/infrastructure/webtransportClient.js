// Thin wrapper around the browser's native WebTransport API.

// "a1b2c3" -> Uint8Array([0xa1, 0xb2, 0xc3])
export function hexToBytes(hex) {
  const clean = hex.replace(/:/g, '').trim();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
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
      opts.serverCertificateHashes = this.#certificateHashesHex.map((hex) => ({
        algorithm: 'sha-256',
        value: hexToBytes(hex).buffer,
      }));
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
