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

/** Dense version ids: the table's row index, server preference order. */
#define MOQVER_D22 0
#define MOQVER_D19 1
#define MOQVER_D18 2
/** Number of supported drafts (rows in the table). */
#define MOQVER_COUNT 3

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
/** REQUEST_UPDATE may follow the sender's own PUBLISH (draft-22 9.8). */
#define MOQVER_CAP_UPDATE_ON_PUBLISH (1u << 17)

/** Version id for a negotiated subprotocol token: the matching row, the
 * draft-19 row for an empty token (no subprotocol negotiated), -1 for a
 * token the table does not list. */
int moqver_find(wired_span token);

/** Capability bits (MOQVER_CAP_*) of version id ver (0..MOQVER_COUNT-1). */
u32 moqver_caps(int ver);

/** Writes the server's space-separated subprotocol list ("moqt-22 moqt-19
 * moqt-18", NUL-terminated) to out, for wired_srvrun_opt.wt_protocols.
 * Returns its length without the NUL, 0 when cap is too small. */
usz wired_moqt_wt_protocols(char* out, usz cap);

#endif
