#ifndef APP_MOQT_RUN_MOQTRUN_CLOSE_H
#define APP_MOQT_RUN_MOQTRUN_CLOSE_H

/* Session close codes beside moqtrun_types.h's. */

/** draft-ietf-moq-transport-19 3.5 GOAWAY_TIMEOUT session code. */
#define WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT 0x10

/** draft-ietf-moq-transport-19 3.5 INVALID_PATH session code (a SETUP
 * carried PATH over WebTransport, 10.4). */
#define WIRED_MOQTRUN_CLOSE_INVALID_PATH 0x8

/** draft-ietf-moq-transport-19 3.5 INVALID_AUTHORITY session code (a
 * SETUP carried AUTHORITY over WebTransport, 10.4). */
#define WIRED_MOQTRUN_CLOSE_INVALID_AUTHORITY 0x19

/** draft-ietf-moq-transport-19 3.5 / -22 12.2 MALFORMED_PATH session code
 * (a raw-QUIC SETUP's PATH is not path-abempty [?query], 10.3.1.2). */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_PATH 0x9

/** draft-ietf-moq-transport-19 3.5 / -22 12.2 MALFORMED_AUTHORITY session
 * code (a raw-QUIC SETUP's AUTHORITY is no RFC 3986 authority,
 * 10.3.1.1). */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY 0x1A

/** draft-ietf-moq-transport-19 3.5/10.9 TOO_MANY_REQUEST_UPDATES session
 * code: a request stream already holding MAX_REQUEST_UPDATES outstanding
 * REQUEST_UPDATEs received one more. */
#define WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES 0x1B

/** draft-ietf-moq-transport-22 8.9 / 12.2 AUTH_TOKEN_CACHE_OVERFLOW
 * session code: a REGISTER Token exceeded the hub's 0-byte token cache. */
#define WIRED_MOQTRUN_CLOSE_AUTH_TOKEN_CACHE_OVERFLOW 0x13

/** draft-ietf-moq-transport-22 8.9 / 12.2 UNKNOWN_AUTH_TOKEN_ALIAS session
 * code: a Token referenced an Alias the hub never registered. */
#define WIRED_MOQTRUN_CLOSE_UNKNOWN_AUTH_TOKEN_ALIAS 0x17

/* Session close codes draft-ietf-moq-transport-23 12.2 adds (Table 20),
 * picked by moqtrun_cc_code for a moqt-23 session. */

/** draft-ietf-moq-transport-23 12.2 DELTA_ENCODING_OVERFLOW session code:
 * a delta-encoded Type or ID would pass 2^64-1. */
#define WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW 0x400

/** draft-ietf-moq-transport-23 12.2 INVALID_STREAM_HEADER session code:
 * an unknown stream or datagram type, or a header field out of range. */
#define WIRED_MOQTRUN_CLOSE_INVALID_STREAM_HEADER 0x200

/** draft-ietf-moq-transport-23 12.2 MALFORMED_OBJECT session code. */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_OBJECT 0x201

/** draft-ietf-moq-transport-23 12.2 INVALID_OBJECT_STATUS session code. */
#define WIRED_MOQTRUN_CLOSE_INVALID_OBJECT_STATUS 0x202

/** draft-ietf-moq-transport-23 12.2 TRUNCATED_OBJECT session code: a
 * stream ended inside a serialized Object. */
#define WIRED_MOQTRUN_CLOSE_TRUNCATED_OBJECT 0x203

/** draft-ietf-moq-transport-23 12.2 MALFORMED_MESSAGE session code: a
 * control message that does not parse or does not match its Length. */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE 0x300

/** draft-ietf-moq-transport-23 12.2 INVALID_FIELD session code. */
#define WIRED_MOQTRUN_CLOSE_INVALID_FIELD 0x301

/** draft-ietf-moq-transport-23 12.2 INVALID_TRACK_NAMESPACE session code. */
#define WIRED_MOQTRUN_CLOSE_INVALID_TRACK_NAMESPACE 0x302

/** draft-ietf-moq-transport-23 12.2 UNEXPECTED_MESSAGE session code: an
 * unknown message type, or one not allowed where or when it came. */
#define WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE 0x303

/** draft-ietf-moq-transport-23 12.2 ROLE_VIOLATION session code: a
 * message or field only the other role may send. */
#define WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION 0x304

/** draft-ietf-moq-transport-23 12.2 INVALID_PARAMETER session code. */
#define WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER 0x305

/** draft-ietf-moq-transport-23 12.2 CLOSED_CONTROL_STREAM session code. */
#define WIRED_MOQTRUN_CLOSE_CLOSED_CONTROL_STREAM 0x306

/** draft-ietf-moq-transport-22/23 12.2 MALFORMED_KEY_VALUE session code
 * (KEY_VALUE_FORMATTING_ERROR before draft-23, same value). */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE 0x6

/** draft-ietf-moq-transport-23 8.9 / 12.2 MALFORMED_AUTH_TOKEN session
 * code: an AUTHORIZATION TOKEN that does not decode. */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_AUTH_TOKEN 0x16

#endif
