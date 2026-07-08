import { test, assertEqual, assertTrue, assertThrows, report } from './testRunner.js';
import { createMessage, ChatMessage } from '../domain/message.js';

test('createMessage: valid input builds a message with given fields', () => {
  const m = createMessage('alice', 'hello', 123);
  assertEqual(m.author, 'alice');
  assertEqual(m.text, 'hello');
  assertEqual(m.timestamp, 123);
});

test('createMessage: timestamp defaults to Date.now() when omitted', () => {
  const before = Date.now();
  const m = createMessage('alice', 'hello');
  const after = Date.now();
  assertTrue(m.timestamp >= before && m.timestamp <= after, 'timestamp should be current time');
});

test('createMessage: empty author throws', () => {
  assertThrows(() => createMessage('', 'hello'));
});

test('createMessage: whitespace-only author throws', () => {
  assertThrows(() => createMessage('   ', 'hello'));
});

test('createMessage: empty text throws', () => {
  assertThrows(() => createMessage('alice', ''));
});

test('createMessage: whitespace-only text throws', () => {
  assertThrows(() => createMessage('alice', '   '));
});

test('createMessage: text over 500 chars throws', () => {
  assertThrows(() => createMessage('alice', 'a'.repeat(501)));
});

test('createMessage: text of exactly 500 chars is accepted', () => {
  const m = createMessage('alice', 'a'.repeat(500), 1);
  assertEqual(m.text.length, 500);
});

test('toJSON: returns plain object shaped {a, t, ts}', () => {
  const m = createMessage('alice', 'hello', 123);
  assertEqual(JSON.stringify(m.toJSON()), JSON.stringify({ a: 'alice', t: 'hello', ts: 123 }));
});

test('ChatMessage.fromJSON: reconstructs matching message', () => {
  const m = ChatMessage.fromJSON({ a: 'bob', t: 'hi', ts: 456 });
  assertEqual(m.author, 'bob');
  assertEqual(m.text, 'hi');
  assertEqual(m.timestamp, 456);
});

test('round trip: toJSON -> fromJSON preserves author/text/timestamp', () => {
  const original = createMessage('carol', 'round trip', 789);
  const restored = ChatMessage.fromJSON(original.toJSON());
  assertEqual(restored.author, original.author);
  assertEqual(restored.text, original.text);
  assertEqual(restored.timestamp, original.timestamp);
});

test('ChatMessage instances are frozen (immutable)', () => {
  const m = createMessage('alice', 'hello', 123);
  assertThrows(() => {
    'use strict';
    m.author = 'mallory';
  });
  assertTrue(Object.isFrozen(m), 'instance should be frozen');
});

report();
