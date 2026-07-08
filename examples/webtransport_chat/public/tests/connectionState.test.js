import { test, assertEqual, report } from './testRunner.js';
import { STATES, canTransition } from '../domain/connectionState.js';

test('disconnected -> connecting is allowed', () => {
  assertEqual(canTransition(STATES.DISCONNECTED, STATES.CONNECTING), true);
});

test('connecting -> connected is allowed', () => {
  assertEqual(canTransition(STATES.CONNECTING, STATES.CONNECTED), true);
});

test('connecting -> disconnected is allowed (connect failure)', () => {
  assertEqual(canTransition(STATES.CONNECTING, STATES.DISCONNECTED), true);
});

test('connected -> closed is allowed', () => {
  assertEqual(canTransition(STATES.CONNECTED, STATES.CLOSED), true);
});

test('closed -> connecting is allowed (reconnect)', () => {
  assertEqual(canTransition(STATES.CLOSED, STATES.CONNECTING), true);
});

test('disconnected -> connected is NOT allowed', () => {
  assertEqual(canTransition(STATES.DISCONNECTED, STATES.CONNECTED), false);
});

test('connecting -> closed is NOT allowed', () => {
  assertEqual(canTransition(STATES.CONNECTING, STATES.CLOSED), false);
});

test('connected -> connecting is NOT allowed', () => {
  assertEqual(canTransition(STATES.CONNECTED, STATES.CONNECTING), false);
});

test('disconnected -> closed is NOT allowed', () => {
  assertEqual(canTransition(STATES.DISCONNECTED, STATES.CLOSED), false);
});

test('closed -> connected is NOT allowed', () => {
  assertEqual(canTransition(STATES.CLOSED, STATES.CONNECTED), false);
});

test('unknown state does not throw and returns false', () => {
  assertEqual(canTransition('bogus', STATES.CONNECTING), false);
});

report();
