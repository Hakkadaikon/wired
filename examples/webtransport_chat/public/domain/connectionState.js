// Connection state machine: 4 states, fixed set of allowed transitions.
export const STATES = Object.freeze({
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  CLOSED: 'closed',
});

const ALLOWED = new Set([
  `${STATES.DISCONNECTED}->${STATES.CONNECTING}`,
  `${STATES.CONNECTING}->${STATES.CONNECTED}`,
  `${STATES.CONNECTING}->${STATES.DISCONNECTED}`,
  `${STATES.CONNECTED}->${STATES.CLOSED}`,
  `${STATES.CLOSED}->${STATES.CONNECTING}`,
]);

export function canTransition(from, to) {
  return ALLOWED.has(`${from}->${to}`);
}
