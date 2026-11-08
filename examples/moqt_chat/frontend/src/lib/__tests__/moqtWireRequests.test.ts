// draft-ietf-moq-transport-23 request-stream messages, Message Parameters
// and the FETCH data stream. Every vector is hand-derived from the draft's
// own figures with its leading-ones varint (8.1): 0xxxxxxx is one byte,
// 10xxxxxx a 2-byte form (200 -> 80 c8, 0x8C -> 80 8c, 0x40C -> 84 0c),
// 110xxxxx a 3-byte one (65536 -> c1 00 00).
import { describe, expect, it } from "vitest";
import {
	bytesToHex,
	bytesToUtf8,
	decodeControlFrame,
	decodeFetchHeader,
	decodeFetchObject,
	decodeLocationFilter,
	decodeNamespaceSuffix,
	decodeParams,
	decodePublish,
	decodeRequestError,
	decodeSubscribe,
	decodeSubscribeOk,
	encodeControlFrame,
	encodeFillParameters,
	encodeLocationFilter,
	encodeNamespaceRequest,
	encodeParams,
	encodePublish,
	encodeRequestError,
	encodeSubscribe,
	hasUnknownMandatoryProperty,
	hexToBytes,
	largestObjectOf,
	MoqtDecodeError,
	newFetchSeq,
	utf8ToBytes,
} from "../moqtWire";

const hex = (s: string) => hexToBytes(s.replace(/ /g, ""));

// SUBSCRIBE body fields before the parameters: Request ID 0, Track
// Namespace {"chat", "room1"}, Track Name "alice" (9.6) -- 19 bytes.
const SUB_HEAD = "00 02 04 63686174 05 726f6f6d31 05 616c696365";
const subscribeOf = (trackName = "alice", parameters = []) => ({
	requestId: 0n,
	trackNamespace: ["chat", "room1"].map(utf8ToBytes),
	trackName: utf8ToBytes(trackName),
	parameters,
});

describe("control message framing (9): Length is a vi64", () => {
	it("SETUP with no options is af00 00", () => {
		// Type 0x2F00 = 12032 <= 16383: 2-byte form af 00; Length 0.
		expect(bytesToHex(encodeControlFrame(0x2f00n, new Uint8Array(0)))).toBe(
			"af0000",
		);
	});

	it("a 20-byte SUBSCRIBE carries Length 14 (one byte), not 00 14", () => {
		const body = encodeSubscribe(subscribeOf());
		const frame = encodeControlFrame(0x3n, body);
		expect(bytesToHex(frame)).toBe(bytesToHex(hex(`03 14 ${SUB_HEAD} 00`)));
		const { frame: f, len } = decodeControlFrame(frame);
		expect([f.type, f.body.length, len]).toEqual([0x3n, 20, 22]);
	});

	it("a 200-byte body takes the 2-byte Length 80 c8", () => {
		const frame = encodeControlFrame(0x7n, new Uint8Array(200));
		expect(bytesToHex(frame.slice(0, 3))).toBe("0780c8");
		expect(decodeControlFrame(frame).frame.body.length).toBe(200);
	});

	it("a body shorter than Length is truncated (the reader waits)", () => {
		expect(() => decodeControlFrame(hex("07 80c8 00"))).toThrow(/truncated/);
		expect(() => decodeControlFrame(hex("07"))).toThrow(MoqtDecodeError);
	});

	it("a Length over the default MAX_CONTROL_MESSAGE_SIZE 65535 is refused (9.1.8)", () => {
		expect(() => decodeControlFrame(hex("07 c10000"))).toThrow(
			/FIELD_LENGTH_EXCEEDED/,
		);
		expect(() => encodeControlFrame(0x7n, new Uint8Array(65536))).toThrow(
			MoqtDecodeError,
		);
		// 65535 itself (c0 ff ff) is allowed.
		const max = encodeControlFrame(0x7n, new Uint8Array(65535));
		expect(bytesToHex(max.slice(0, 4))).toBe("07c0ffff");
	});
});

describe("Message Parameters (9.19)", () => {
	it("SUBSCRIBE_OK: EXPIRES is a varint, LARGEST_OBJECT a Location", () => {
		// Track Alias 1, 2 params: EXPIRES (0x08) 100, delta 1 -> 0x09 {7, 3}.
		const msg = decodeSubscribeOk(hex("01 02 08 64 01 07 03"));
		expect(msg.trackAlias).toBe(1n);
		expect(msg.parameters[0]).toEqual({ type: 0x8n, value: 100n });
		expect(largestObjectOf(msg.parameters)).toEqual({ group: 7n, object: 3n });
		expect(largestObjectOf([])).toBeUndefined();
	});

	it("rejects an unknown parameter Type", () => {
		expect(() => decodeSubscribeOk(hex("01 01 3f 00"))).toThrow(
			MoqtDecodeError,
		);
	});

	it("PAUSED (0x11, 9.19.18) is a uint8 0 or 1; FORWARD (0x10) is gone", () => {
		expect(decodeParams(hex("01 11 01"), 0).params).toEqual([
			{ type: 0x11n, value: 1n },
		]);
		expect(() => decodeParams(hex("01 11 02"), 0)).toThrow(/INVALID_PARAMETER/);
		expect(() => decodeParams(hex("01 10 01"), 0)).toThrow(MoqtDecodeError);
	});

	it("uint8 parameters are one byte: SUBSCRIBER_PRIORITY 64, GROUP_ORDER 2", () => {
		const params = [
			{ type: 0x20n, value: 64n },
			{ type: 0x22n, value: 2n },
		];
		// 2 params: 0x20 then 40; delta 2 -> 0x22 then 02.
		expect(bytesToHex(encodeParams(params))).toBe("0220400202");
		expect(decodeParams(hex("0220400202"), 0).params).toEqual(params);
		expect(() => decodeParams(hex("01 20"), 0)).toThrow(/truncated/);
	});

	it("a Type past 2^64-1 is DELTA_ENCODING_OVERFLOW (9.19)", () => {
		// OBJECT_DELIVERY_TIMEOUT (0x02) 0, then Type Delta 2^64-1 (9-byte ff..).
		expect(() => decodeParams(hex("02 02 00 ff ffffffffffffffff"), 0)).toThrow(
			/DELTA_ENCODING_OVERFLOW/,
		);
	});

	it("a Track Namespace over 4096 bytes is FIELD_LENGTH_EXCEEDED (8.7)", () => {
		// 2 fields of 2049 bytes each (Length 0x801 -> 88 01).
		const field = new Uint8Array(2 + 2049);
		field.set(hex("8801"));
		const ns = new Uint8Array([0x02, ...field, ...field]);
		expect(() => decodeNamespaceSuffix(ns, false)).toThrow(
			/FIELD_LENGTH_EXCEEDED/,
		);
	});
});

describe("LOCATION_FILTER (9.19.9)", () => {
	const forms: [string, bigint, bigint[], string][] = [
		["None", 0x0n, [], "00"],
		["Relative Start", 0x1n, [3n], "0103"],
		["Absolute Start", 0x2n, [5n, 1n], "020501"],
		["Absolute Start, Group End", 0x3n, [5n, 0n, 3n], "03050003"],
		["Absolute Range", 0x4n, [5n, 0n, 3n, 7n], "0405000307"],
		["Next Object", 0x5n, [], "05"],
	];

	for (const [name, type, fields, h] of forms) {
		it(`encode/decode 0x0${type} ${name}`, () => {
			expect(bytesToHex(encodeLocationFilter({ type, fields }))).toBe(h);
			const bytes = hexToBytes(`${h}ff`); // the Type alone says where it ends
			expect(decodeLocationFilter(bytes, 0)).toEqual({
				filter: { type, fields },
				len: h.length / 2,
			});
		});
	}

	it("rejects an unknown Location Filter Type and a truncated filter", () => {
		expect(() => decodeLocationFilter(hex("06"), 0)).toThrow(MoqtDecodeError);
		expect(() => decodeLocationFilter(hex("0205"), 0)).toThrow(MoqtDecodeError);
		expect(() => encodeLocationFilter({ type: 0x2n, fields: [5n] })).toThrow(
			MoqtDecodeError,
		);
	});

	it("a parameter list carries the filter with no Length", () => {
		const next = { type: 0x21n, value: Uint8Array.of(0x05) };
		expect(bytesToHex(encodeParams([next]))).toBe("012105");
		expect(decodeParams(hex("012105"), 0)).toEqual({ params: [next], len: 3 });
	});
});

describe("FILL_PARAMETERS (9.19.15): a count of Parameters, no Length", () => {
	const fill = encodeFillParameters([
		{ type: 0x21n, value: encodeLocationFilter({ type: 0x1n, fields: [65n] }) },
	]);

	it("the value is count + Type-delta parameters: 01 21 01 41", () => {
		expect(bytesToHex(fill)).toBe("01210141");
	});

	it("SUBSCRIBE with Next Object + a fill of Relative Start 65", () => {
		// 2 params: 0x21 Next Object (05), delta 2 -> 0x23 then the bare value.
		const params = "02 21 05 02 01210141";
		const body = encodeSubscribe(
			subscribeOf("alice", [
				{ type: 0x21n, value: Uint8Array.of(0x05) },
				{ type: 0x23n, value: fill },
			] as never),
		);
		expect(bytesToHex(body)).toBe(bytesToHex(hex(`${SUB_HEAD} ${params}`)));
		const decoded = decodeSubscribe(body);
		expect(decoded.parameters.map((p) => p.type)).toEqual([0x21n, 0x23n]);
		expect(bytesToHex(decoded.parameters[1].value as Uint8Array)).toBe(
			"01210141",
		);
	});

	it("a parameter Table 7 does not list inside it is INVALID_PARAMETER", () => {
		// PAUSED (0x11) inside the fill.
		expect(() => decodeParams(hex("01 23 01 11 00"), 0)).toThrow(
			/INVALID_PARAMETER/,
		);
		// a bad inner LOCATION_FILTER Type fails the whole list
		expect(() => decodeParams(hex("01 23 01 21 09"), 0)).toThrow(
			MoqtDecodeError,
		);
	});
});

describe("Track Name MUST NOT be empty (2.4.1)", () => {
	it("encodeSubscribe / encodePublish refuse an empty Track Name", () => {
		expect(() => encodeSubscribe(subscribeOf(""))).toThrow(MoqtDecodeError);
		expect(() =>
			encodePublish({
				...subscribeOf(""),
				trackAlias: 1n,
				trackProperties: [],
			}),
		).toThrow(MoqtDecodeError);
	});

	it("a received empty Track Name is a PROTOCOL_VIOLATION", () => {
		// SUBSCRIBE: rid 0, ns {"chat"}, Track Name Length 0, no params.
		expect(() => decodeSubscribe(hex("00 01 04 63686174 00 00"))).toThrow(
			/PROTOCOL_VIOLATION/,
		);
		// PUBLISH: rid 0, ns {"chat"}, Track Name Length 0, alias 1, no params.
		expect(() => decodePublish(hex("00 01 04 63686174 00 01 00"))).toThrow(
			/PROTOCOL_VIOLATION/,
		);
	});
});

describe("REQUEST_ERROR (9.4.1): Error Details follow the Reason", () => {
	it("decodes the Error Details Key-Value-Pairs", () => {
		// NOT_SUPPORTED, Retry 0, empty reason, detail Type 2 (even) value 5.
		const msg = decodeRequestError(hex("03 00 00 02 05"));
		expect([msg.errorCode, msg.retryInterval]).toEqual([3n, 0n]);
		expect(msg.errorDetails).toEqual([{ type: 2n, num: 5n }]);
		expect(decodeRequestError(hex("03 00 00")).errorDetails).toEqual([]);
	});

	it("encodes no details as nothing after the Reason", () => {
		const body = encodeRequestError({
			errorCode: 3n,
			retryInterval: 0n,
			errorReason: new Uint8Array(0),
		});
		expect(bytesToHex(body)).toBe("030000");
	});

	it("a Reason Phrase over 1024 bytes is FIELD_LENGTH_EXCEEDED (8.5)", () => {
		// Length 1025 = 0x401 -> 84 01.
		const body = new Uint8Array(4 + 1025);
		body.set(hex("00 00 8401"));
		expect(() => decodeRequestError(body)).toThrow(/FIELD_LENGTH_EXCEEDED/);
	});
});

describe("namespace discovery (9.13-9.16)", () => {
	it("encode SUBSCRIBE_NAMESPACE rid 6 {chat}", () => {
		const body = encodeNamespaceRequest({
			requestId: 6n,
			namespace: [utf8ToBytes("chat")],
			parameters: [],
		});
		expect(bytesToHex(encodeControlFrame(0x50n, body))).toBe(
			"500806010463686174" + "00",
		);
	});

	it("NAMESPACE carries Parameters after the suffix (9.15)", () => {
		const suffix = decodeNamespaceSuffix(hex("01 05 7573657232 00"), true);
		expect(suffix.map(bytesToUtf8)).toEqual(["user2"]);
		// no Number of Parameters: truncated
		expect(() => decodeNamespaceSuffix(hex("01 05 7573657232"), true)).toThrow(
			MoqtDecodeError,
		);
	});

	it("NAMESPACE_DONE is the suffix alone (9.16)", () => {
		expect(
			decodeNamespaceSuffix(hex("01 05 7573657232"), false).map(bytesToUtf8),
		).toEqual(["user2"]);
		expect(() =>
			decodeNamespaceSuffix(hex("01 05 7573657232 00"), false),
		).toThrow(MoqtDecodeError);
	});
});

describe("Mandatory Track Properties (3.7)", () => {
	it("0x4000-0x7FFF are mandatory, grease (0x7f*N + 0x9D) is not", () => {
		const has = (type: bigint) => hasUnknownMandatoryProperty([{ type }]);
		expect(has(0x4000n)).toBe(true);
		expect(has(0x7fffn)).toBe(true);
		expect(has(0x3fffn)).toBe(false);
		expect(has(0x8000n)).toBe(false);
		// N = 129: 0x7f * 129 + 0x9D = 16383 + 157 = 16540 = 0x409C
		expect(has(0x409cn)).toBe(false);
		expect(hasUnknownMandatoryProperty([])).toBe(false);
	});
});

describe("FETCH data stream (11.4)", () => {
	// Decodes every item of a fetch stream (after its FETCH_HEADER) as
	// [group, object, marker or payload text].
	const walk = (h: string) => {
		const bytes = hex(h);
		const seq = newFetchSeq();
		const got: [bigint, bigint, string][] = [];
		for (let pos = 0; pos < bytes.length; ) {
			const { object, len } = decodeFetchObject(bytes, pos, seq);
			got.push([
				object.group,
				object.object,
				object.marker ?? bytesToUtf8(object.payload),
			]);
			pos += len;
		}
		return got;
	};

	it("FETCH_HEADER is Type 0x5 + Request ID", () => {
		expect(decodeFetchHeader(hex("05 02"))).toEqual({ requestId: 2n, len: 2 });
		expect(() => decodeFetchHeader(hex("04 02"))).toThrow(MoqtDecodeError);
	});

	it("an Object ID Delta within a Group adds Delta + 2 (11.4.1.1)", () => {
		// 1c: G5 O0 prio 0x80 "a"; 04: O = 0 + 1 + 2 = 3 "b"; 00: O = 4 "c".
		expect(walk("1c 05 00 80 01 61  04 01 01 62  00 01 63")).toEqual([
			[5n, 0n, "a"],
			[5n, 3n, "b"],
			[5n, 4n, "c"],
		]);
	});

	it("a later group's Group ID Delta is prior + delta + 1, its Object ID absolute", () => {
		expect(walk("1c 05 00 80 01 61  0c 00 02 01 62")).toEqual([
			[5n, 0n, "a"],
			[6n, 2n, "b"],
		]);
	});

	it("End of Range indicators are delta encoded (11.4.2.1)", () => {
		// 0x8C: Group Delta 0 -> G5, Object 0 + 2 + 1 = 3; then an Object
		// (flags 00) is prior + 1 = 4 with the last Object's priority;
		// 0x40C Gone: Group Delta 1 -> G6, Object Delta absolute 2.
		expect(walk("1c 05 00 80 01 61  808c 00 02  00 01 62  840c 01 02")).toEqual(
			[
				[5n, 0n, "a"],
				[5n, 3n, "non_existent"],
				[5n, 4n, "b"],
				[6n, 2n, "gone"],
			],
		);
	});

	it("a first End of Range carries absolute IDs; 0x10C / 0x20C are Unknown / Timed-Out", () => {
		expect(walk("820c 04 02  810c 00 00")).toEqual([
			[4n, 2n, "timed_out"],
			[4n, 3n, "unknown"],
		]);
	});

	it("End of Group (0x80) / End of Track (0x81) carry no fields (11.4.2.2)", () => {
		expect(walk("1c 05 00 80 01 61  8080  0c 00 00 01 62  8081")).toEqual([
			[5n, 0n, "a"],
			[5n, 0n, "end_of_group"],
			[6n, 0n, "b"],
			[6n, 0n, "end_of_track"],
		]);
	});

	it("after End of Group the prior Object ID is 2^64-1: a + 1 overflows", () => {
		expect(() => walk("1c 05 00 80 01 61  8080  00 01 62")).toThrow(
			/DELTA_ENCODING_OVERFLOW/,
		);
	});

	it("rejects other Serialization Flags >= 128", () => {
		expect(() => walk("8082")).toThrow(/MALFORMED_OBJECT/);
	});

	it("rejects a first Object or End of Group that references a prior one", () => {
		expect(() => walk("01 01 78")).toThrow(MoqtDecodeError);
		expect(() => walk("8080")).toThrow(MoqtDecodeError);
		expect(() => walk("1c 05 00")).toThrow(MoqtDecodeError); // no Priority
		expect(() => walk("0c 05 00 01 61")).toThrow(MoqtDecodeError); // no prior Priority
	});

	it("walks every Subgroup mode, the datagram bit and Properties", () => {
		// 1f: G5, explicit Subgroup 7, O3, prio 0x80; 01: Subgroup = prior,
		// O4; 02: prior + 1, O5; 04 delta 2: Subgroup 0, O = 5 + 2 + 2 = 9;
		// 60: datagram (no Subgroup) + Properties Length 2 (aa bb), O10.
		const bytes = hex(
			"1f 05 07 03 80 01 61  01 01 62  02 01 63  04 02 01 64  60 02 aabb 01 65",
		);
		const seq = newFetchSeq();
		const got = [];
		for (let pos = 0; pos < bytes.length; ) {
			const { object, len } = decodeFetchObject(bytes, pos, seq);
			got.push([object.object, seq.subgroup, bytesToUtf8(object.payload)]);
			pos += len;
		}
		expect(got).toEqual([
			[3n, 7n, "a"],
			[4n, 7n, "b"],
			[5n, 8n, "c"],
			[9n, 0n, "d"],
			[10n, undefined, "e"],
		]);
	});

	it("a truncated Object throws so the reader waits for more bytes", () => {
		const bytes = hex("1c 05 00 80 02 6869");
		expect(() =>
			decodeFetchObject(bytes.slice(0, 6), 0, newFetchSeq()),
		).toThrow(MoqtDecodeError);
		expect(decodeFetchObject(bytes, 0, newFetchSeq()).len).toBe(7);
	});
});
