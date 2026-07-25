// Thin wrapper around the browser WebTransport API: owns the connection
// state machine (connecting -> established -> disconnected) and makes sure
// cleanup runs exactly once no matter which of .ready/.closed settles first
// or in what order.

export type ConnectionState = "connecting" | "established" | "disconnected";

// Subset of the real WebTransport API this client depends on. Kept minimal
// so tests can supply a plain object instead of a browser instance.
export interface TransportLike {
  ready: Promise<void>;
  closed: Promise<void>;
  close?: (info?: unknown) => void;
}

export type WebTransportClientOptions = {
  onError?: (err: unknown) => void;
  onCleanup?: () => void;
  onDisconnect?: () => void;
};

export class WebTransportClient<T extends TransportLike = TransportLike> {
  state: ConnectionState = "connecting";
  transport: T | undefined;

  private cleanedUp = false;

  constructor(
    private makeTransport: () => T,
    private options: WebTransportClientOptions = {},
  ) {}

  private cleanup(): void {
    if (this.cleanedUp) return;
    this.cleanedUp = true;
    this.state = "disconnected";
    this.options.onCleanup?.();
    this.options.onDisconnect?.();
  }

  async connect(): Promise<void> {
    const transport = this.makeTransport();
    this.transport = transport;
    // .closed may settle before .ready (or instead of it); race both so
    // whichever settles first drives the state transition, and cleanup()
    // is idempotent so a later settlement of the other one is a no-op.
    transport.closed.then(
      () => this.cleanup(),
      () => this.cleanup(),
    );
    try {
      await transport.ready;
      if (this.cleanedUp) return;
      this.state = "established";
    } catch (err) {
      if (this.cleanedUp) return;
      this.options.onError?.(err);
    }
  }
}
