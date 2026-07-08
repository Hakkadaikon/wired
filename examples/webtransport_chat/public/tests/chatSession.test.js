import { test, assertEqual, assertTrue, report } from './testRunner.js';
import { ChatSession } from '../application/chatSession.js';
import { STATES } from '../domain/connectionState.js';
import { ChatMessage } from '../domain/message.js';

function makeMockClient({ connectFails = false } = {}) {
  const receiveCallbacks = [];
  return {
    sent: [],
    connectCalled: false,
    connect() {
      this.connectCalled = true;
      return connectFails ? Promise.reject(new Error('connect failed')) : Promise.resolve();
    },
    send(bytes) {
      this.sent.push(bytes);
      return Promise.resolve();
    },
    onReceive(cb) {
      receiveCallbacks.push(cb);
    },
    // test helper: simulate the server pushing bytes to us
    _emitReceive(bytes) {
      for (const cb of receiveCallbacks) cb(bytes);
    },
  };
}

test('initial state is disconnected', () => {
  const session = new ChatSession(makeMockClient());
  assertEqual(session.state, STATES.DISCONNECTED);
});

test('connect() transitions state to connected', async () => {
  const session = new ChatSession(makeMockClient());
  await session.connect();
  assertEqual(session.state, STATES.CONNECTED);
});

test('connect() failure leaves state as disconnected and propagates error', async () => {
  const client = makeMockClient({ connectFails: true });
  const session = new ChatSession(client);
  let threw = false;
  try {
    await session.connect();
  } catch {
    threw = true;
  }
  assertTrue(threw, 'connect() should propagate the rejection');
  assertEqual(session.state, STATES.DISCONNECTED);
});

test('send() delivers a UTF-8 encoded JSON message to client.send', async () => {
  const client = makeMockClient();
  const session = new ChatSession(client);
  await session.connect();
  await session.send('alice', 'hello');

  assertEqual(client.sent.length, 1);
  const bytes = client.sent[0];
  assertTrue(bytes instanceof Uint8Array, 'sent payload should be a Uint8Array');
  const decoded = JSON.parse(new TextDecoder().decode(bytes));
  assertEqual(decoded.a, 'alice');
  assertEqual(decoded.t, 'hello');
  assertTrue(typeof decoded.ts === 'number', 'decoded payload should carry a numeric timestamp');
});

test('send() with empty text throws and does not call client.send', async () => {
  const client = makeMockClient();
  const session = new ChatSession(client);
  await session.connect();

  let threw = false;
  try {
    await session.send('alice', '');
  } catch {
    threw = true;
  }
  assertTrue(threw, 'send() should throw for invalid message');
  assertEqual(client.sent.length, 0);
});

test('onMessageReceived callback fires with a ChatMessage on incoming bytes', async () => {
  const client = makeMockClient();
  const session = new ChatSession(client);
  await session.connect();

  let received = null;
  session.onMessageReceived((msg) => {
    received = msg;
  });

  const payload = JSON.stringify({ a: 'bob', t: 'hi there', ts: 42 });
  client._emitReceive(new TextEncoder().encode(payload));

  assertTrue(received instanceof ChatMessage, 'callback should receive a ChatMessage instance');
  assertEqual(received.author, 'bob');
  assertEqual(received.text, 'hi there');
  assertEqual(received.timestamp, 42);
});

report();
