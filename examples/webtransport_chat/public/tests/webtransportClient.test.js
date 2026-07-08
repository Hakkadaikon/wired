import { test, assertEqual, report } from './testRunner.js';
import { hexToBytes } from '../infrastructure/webtransportClient.js';

test('hexToBytes converts a plain hex string', () => {
  const bytes = hexToBytes('a1b2c3');
  assertEqual(bytes.length, 3);
  assertEqual(bytes[0], 0xa1);
  assertEqual(bytes[1], 0xb2);
  assertEqual(bytes[2], 0xc3);
});

test('hexToBytes strips colon separators', () => {
  const bytes = hexToBytes('a1:b2:c3');
  assertEqual(bytes.length, 3);
  assertEqual(bytes[0], 0xa1);
  assertEqual(bytes[2], 0xc3);
});

test('hexToBytes handles empty string', () => {
  assertEqual(hexToBytes('').length, 0);
});

report();
