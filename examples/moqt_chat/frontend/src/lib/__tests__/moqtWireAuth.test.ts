// AUTHORIZATION TOKEN Setup Option (draft-ietf-moq-transport-23 9.1.4; the
// same Option Type 0x03 and Token structure in drafts 18, 19 and 22): odd
// Type, so Length + bytes; the bytes are the 8.9 Token with Alias Type
// USE_VALUE (0x3): Token Type, then the Value to the end. Goldens are
// hand-derived with the leading-ones varint (8.1): 0xxxxxxx up to 127,
// 10xxxxxx xxxxxxxx up to 16383.
import { describe, expect, it } from "vitest";
import {
	authTokenOption,
	SETUP_OPTION_AUTHORIZATION_TOKEN,
} from "../moqtAuthWire";
import {
	bytesToHex,
	decodeSetup,
	encodeSetup,
	encodeSstsAlgorithms,
	SETUP_OPTION_SSTS_ALGORITHMS,
	utf8ToBytes,
} from "../moqtWire";

const setupHex = (value: Uint8Array) =>
	bytesToHex(encodeSetup({ setupOptions: [authTokenOption(0n, value)] }));

describe("AUTHORIZATION TOKEN Setup Option (0x03)", () => {
	it("golden: value 'ab' is 03 04 03 00 61 62", () => {
		expect(setupHex(utf8ToBytes("ab"))).toBe("030403006162");
	});

	it("golden: ahead of SSTS_ALGORITHMS, whose Type delta is 0x3f01-3 = 0x3efe", () => {
		const body = encodeSetup({
			setupOptions: [
				authTokenOption(0n, utf8ToBytes("ab")),
				{
					type: SETUP_OPTION_SSTS_ALGORITHMS,
					raw: encodeSstsAlgorithms([0xff01n, 0n]),
				},
			],
		});
		expect(bytesToHex(body)).toBe(`030403006162befe04c0ff0100`);
	});

	it("Length boundary: 125-byte value -> 127 (1 byte), 126 -> 128 (80 80)", () => {
		expect(setupHex(new Uint8Array(125)).slice(0, 8)).toBe("037f0300");
		expect(setupHex(new Uint8Array(126)).slice(0, 10)).toBe("0380800300");
	});

	it("a ~600-byte NIP-98 event fits: Length 602 = 0x25a -> 82 5a", () => {
		expect(setupHex(new Uint8Array(600)).slice(0, 10)).toBe("03825a0300");
	});

	it("round-trips through decodeSetup", () => {
		const value = utf8ToBytes('{"kind":27235}');
		const [opt] = decodeSetup(
			encodeSetup({ setupOptions: [authTokenOption(0n, value)] }),
		).setupOptions;
		expect(opt.type).toBe(SETUP_OPTION_AUTHORIZATION_TOKEN);
		expect(bytesToHex(opt.raw ?? new Uint8Array())).toBe(
			`0300${bytesToHex(value)}`,
		);
	});
});
