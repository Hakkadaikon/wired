#ifndef MOQTSTAT_H
#define MOQTSTAT_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * draft-ietf-moq-transport-19 TRACK_STATUS (10.14), its TRACK_STATUS_OK
 * response (a REQUEST_OK, 10.5) and REQUEST_UPDATE (10.9). Every take
 * decodes one whole Message Body (the bytes moqctl_peek_type framed) and
 * returns MOQCTL_OK, MOQCTL_VIOLATION (malformed, or a Length mismatch --
 * see moqctl_body_end) or MOQCTL_PARAMS_KVFMT.
 */

#define MOQTSTAT_T_REQUEST_UPDATE 0x2ULL
#define MOQTSTAT_T_TRACK_STATUS 0xDULL

/** TRACK_STATUS: "identical to the SUBSCRIBE message" (10.14), so it
 * decodes into a moqctl_subscribe and encodes with
 * moqctl_subscribe_encode; only the parameter scope differs. */
int moqtstat_take(int ver, wired_span body, moqctl_subscribe* out);

/** TRACK_STATUS_OK: a REQUEST_OK whose parameters are checked against the
 * TRACK_STATUS_OK scope and whose Track Properties may be non-empty.
 * Encode with moqctl_request_ok_encode. */
int moqtstat_ok_take(int ver, wired_span body, moqctl_request_ok* out);

/** REQUEST_UPDATE (10.9 Figure 12). */
typedef struct {
  u64           request_id;
  moqctl_params params;
} moqtstat_update;

/** ctx is the MOQCTL_PCTX_UPDATE_* bit of the request being updated, since
 * the admissible parameters depend on it (10.2.x). */
int moqtstat_update_take(
    int ver, wired_span body, u32 ctx, moqtstat_update* out);

/** Writes the Body only. Returns 1 ok, 0 if buf is too small. */
int moqtstat_update_encode(wired_mspan buf, usz* off, const moqtstat_update* m);

#endif
