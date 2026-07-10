import { test, assertEqual, assertThrows, report } from './testRunner.js';
import {
  hexToBytes,
  certHashesToOpts,
} from '../infrastructure/webtransportClient.js';

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

test('hexToBytes strips whitespace and newlines from a terminal copy', () => {
  const bytes = hexToBytes(' a1:b2\nc3 ');
  assertEqual(bytes.length, 3);
  assertEqual(bytes[0], 0xa1);
  assertEqual(bytes[2], 0xc3);
});

test('hexToBytes handles empty string', () => {
  assertEqual(hexToBytes('').length, 0);
});

const HASH_32 =
  '39:65:a1:f6:38:bc:df:ba:22:8e:ff:35:7c:90:aa:f2' +
  ':2d:98:ba:13:50:80:7c:5b:28:1d:94:94:1e:4c:b5:3c';

test('certHashesToOpts accepts a full 32-byte SHA-256 fingerprint', () => {
  const hashes = certHashesToOpts([HASH_32]);
  assertEqual(hashes.length, 1);
  assertEqual(hashes[0].algorithm, 'sha-256');
  assertEqual(hashes[0].value.byteLength, 32);
});

test('certHashesToOpts rejects a truncated fingerprint (31 bytes)', () => {
  // one byte lost in a terminal copy: a doomed connection Chrome reports
  // only as an opaque CERTIFICATE_VERIFY_FAILED -- fail loudly instead
  assertThrows(() => certHashesToOpts([HASH_32.slice(0, HASH_32.length - 3)]));
});

test('certHashesToOpts rejects a whole pasted log line', () => {
  assertThrows(() => certHashesToOpts([`cert sha-256 fingerprint: ${HASH_32}`]));
});

report();
