// MOQT AUTHORIZATION TOKEN Setup Option (draft-ietf-moq-transport-23 9.1.4;
// Option Type 0x03 and the 8.9 Token structure are the same in drafts 18,
// 19 and 22). Apart from moqtWire.ts, which is at its Halstead file cap.

import { concatBytes, encodeVarint, type KeyValuePair } from "./moqtWire";

export const SETUP_OPTION_AUTHORIZATION_TOKEN = 0x03n;
const AUTH_ALIAS_USE_VALUE = 0x3n; // 8.9: no Alias, Type + Value follow

/** The option carrying one Token (8.9) with Alias Type USE_VALUE: Token Type
 * (0 = negotiated out of band), then the Token Value to the option's end
 * (odd Option Type: the KVP's Length bounds it). */
export function authTokenOption(
	tokenType: bigint,
	value: Uint8Array,
): KeyValuePair {
	return {
		type: SETUP_OPTION_AUTHORIZATION_TOKEN,
		raw: concatBytes([
			encodeVarint(AUTH_ALIAS_USE_VALUE),
			encodeVarint(tokenType),
			value,
		]),
	};
}
