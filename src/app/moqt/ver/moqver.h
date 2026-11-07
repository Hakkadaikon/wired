#ifndef MOQVER_H
#define MOQVER_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * The MOQT drafts this SDK speaks, as one table: each row is a dense
 * version id, its WebTransport subprotocol token (draft-ietf-moq-transport
 * 3.1, "moqt-NN") and the capability bits that differ between drafts.
 * Every per-draft decision reads a capability bit, never a draft number,
 * and the server's subprotocol offer is generated from the same table so
 * the two cannot drift apart. */

/** Dense version ids: the table's row index, which is also the order of
 * the server's subprotocol list (the client's offer order decides).
 * draft-ietf-moq-transport-23 ("moqt-23"). */
#define MOQVER_D23 0
/** draft-ietf-moq-transport-22 ("moqt-22"). */
#define MOQVER_D22 1
/** draft-ietf-moq-transport-19 ("moqt-19"); also the row used when no
 * subprotocol was negotiated. */
#define MOQVER_D19 2
/** draft-ietf-moq-transport-18 ("moqt-18"). */
#define MOQVER_D18 3
/** Number of supported drafts (rows in the table). */
#define MOQVER_COUNT 4

/** GOAWAY carries a Request ID (draft-18). */
#define MOQVER_CAP_GOAWAY_REQID (1u << 0)
/** DUPLICATE_SUBSCRIPTION request error (draft-18). */
#define MOQVER_CAP_DUP_SUBSCRIPTION (1u << 1)
/** FIN cancels a namespace subscription (draft-18). */
#define MOQVER_CAP_FIN_CANCEL_NS (1u << 2)
/** LOCATION_FILTER with an explicit type (draft-22). */
#define MOQVER_CAP_LOCFILTER_TYPED (1u << 4)
/** draft-22 FETCH body layout. */
#define MOQVER_CAP_FETCH_BODY_V22 (1u << 5)
/** Fill FETCH (draft-22). */
#define MOQVER_CAP_FILL_FETCH (1u << 6)
/** Publish-state notifications (draft-22). */
#define MOQVER_CAP_PUBLISH_STATE_NOTIFY (1u << 7)
/** FETCH End Location is inclusive (draft-22). */
#define MOQVER_CAP_FETCH_END_INCLUSIVE (1u << 8)
/** Range filters (draft-19, 22). */
#define MOQVER_CAP_RANGE_FILTERS (1u << 10)
/** MAX_REQUEST_UPDATES credit (draft-19, 22). */
#define MOQVER_CAP_MAX_REQUEST_UPDATES (1u << 11)
/** Namespace prefix matching (draft-22). */
#define MOQVER_CAP_NS_PREFIX_MATCH (1u << 13)
/** End of Timed-Out Range fetch marker 0x20C (draft-22). */
#define MOQVER_CAP_EOR_TIMED_OUT (1u << 14)
/** 0x1E is PUBLISH_OK, a REQUEST_OK alias (draft-18 SS10 table). */
#define MOQVER_CAP_PUBLISH_OK_ALIAS (1u << 15)
/** PUBLISH_DONE SUBSCRIPTION_ENDED status exists (draft-18, 19). */
#define MOQVER_CAP_SUBSCRIPTION_ENDED (1u << 16)
/** A REQUEST_UPDATE outside the updatable requests closes the session
 * (draft-19 10.9, draft-22 9.5; draft-18 10.9 has no such rule). */
#define MOQVER_CAP_UPDATE_STRAY_CLOSE (1u << 17)
/** A delivery-timeout Object Property on a datagram closes the session
 * (draft-18, ruling Q18-05: undefined input). */
#define MOQVER_CAP_DG_TIMEOUT_PROP_CLOSE (1u << 18)
/** The experimental SSTS_ALGORITHMS Setup Option is offered (draft-22,
 * 23). */
#define MOQVER_CAP_SSTS (1u << 19)
/** The control message Length is a vi64, not 16 bits (draft-23 9). */
#define MOQVER_CAP_CTL_LEN_VI (1u << 20)
/** Setup Option 0x09 is MAX_CONTROL_MESSAGE_SIZE and the experimental
 * SSTS_ALGORITHMS moves to MOQCTL_OPT_SSTS_ALGORITHMS_D23 (draft-23
 * 9.1.8). */
#define MOQVER_CAP_OPT_MAX_CTL_SIZE (1u << 21)
/** Session close codes use the draft-23 12.2 table (0x200-0x401) where
 * earlier drafts close PROTOCOL_VIOLATION (moqtrun_cc_code). */
#define MOQVER_CAP_CLOSE_CODES23 (1u << 22)
/** REQUEST_ERROR UNAVAILABLE (0xA) exists (draft-23 12.3); earlier drafts
 * send EXCESSIVE_LOAD instead (moqctl_request_error_for). */
#define MOQVER_CAP_UNAVAILABLE (1u << 23)
/** REQUEST_ERROR PREFIX_OVERLAP (0x30) exists (draft-18, 19, 22; gone in
 * draft-23 16.12.2). */
#define MOQVER_CAP_PREFIX_OVERLAP (1u << 24)
/** REQUEST_ERROR ends in Error Details (Key-Value-Pairs) carrying the
 * Redirect (draft-23 9.4.1). */
#define MOQVER_CAP_ERR_DETAILS (1u << 25)
/** Fetch streams use the draft-23 11.4 encoding: Object ID Delta + 2,
 * delta-encoded End of Range, End of Gone Range, End of Group / Track
 * (moqfetch_seq.d23). */
#define MOQVER_CAP_FETCH_STREAM23 (1u << 26)
/** FETCH is answered with REQUEST_OK carrying LARGEST_OBJECT (0x18 is
 * reserved) and a relative Location filter on it is INVALID_RANGE
 * (draft-23 3.2, 9.3). */
#define MOQVER_CAP_FETCH_REQUEST_OK (1u << 27)

/** Version id for a negotiated subprotocol token: the matching row, the
 * draft-19 row for an empty token (no subprotocol negotiated), -1 for a
 * token the table does not list. */
int moqver_find(wired_span token);

/** Capability bits (MOQVER_CAP_*) of version id ver (0..MOQVER_COUNT-1). */
u32 moqver_caps(int ver);

/** Writes the server's space-separated subprotocol list ("moqt-22 moqt-19
 * moqt-18", NUL-terminated; rows not offered yet are left out) to out, for
 * wired_srvrun_opt.wt_protocols. Returns its length without the NUL, 0 when cap
 * is too small. */
usz wired_moqt_wt_protocols(char* out, usz cap);

#endif
