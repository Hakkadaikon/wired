#ifndef APP_MOQT_RUN_MOQTRUN_CLOSE_H
#define APP_MOQT_RUN_MOQTRUN_CLOSE_H

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
