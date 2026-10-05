#ifndef MOQNS_H
#define MOQNS_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * draft-ietf-moq-transport-18/19/22 namespace messages (draft-19
 * sections; draft-22 9.14-9.18): SUBSCRIBE_NAMESPACE (10.18),
 * PUBLISH_NAMESPACE (10.15), NAMESPACE (10.16) and NAMESPACE_DONE (10.17).
 * Takes with a ver argument check parameters against that draft. Every take
 * decodes one whole Message Body (the bytes moqctl_peek_type framed) and
 * returns MOQCTL_OK, MOQCTL_VIOLATION (malformed, or a Length mismatch -- see
 * moqctl_body_end) or MOQCTL_PARAMS_KVFMT. Encoders write the Body only and
 * return 1 ok, 0 if buf is too small.
 */

#define MOQNS_T_PUBLISH_NAMESPACE 0x6ULL
#define MOQNS_T_NAMESPACE 0x8ULL
#define MOQNS_T_NAMESPACE_DONE 0xEULL
#define MOQNS_T_SUBSCRIBE_NAMESPACE 0x50ULL

/** SUBSCRIBE_NAMESPACE (ns = Track Namespace Prefix) and
 * PUBLISH_NAMESPACE (ns = Track Namespace): the same body layout. */
typedef struct {
  u64           request_id;
  moqctl_ns     ns;
  moqctl_params params;
} moqns_req;

int moqns_subscribe_take(int ver, wired_span body, moqns_req* out);
int moqns_publish_take(int ver, wired_span body, moqns_req* out);
/** SUBSCRIBE_TRACKS (10.19): same body layout (Request ID, Track Namespace
 * Prefix, Parameters) as SUBSCRIBE_NAMESPACE, decoded against its own
 * MOQCTL_PCTX_SUBSCRIBE_TRACKS parameter scope. */
int moqns_subscribe_tracks_take(int ver, wired_span body, moqns_req* out);
int moqns_req_encode(wired_mspan buf, usz* off, const moqns_req* m);

/** NAMESPACE / NAMESPACE_DONE: the body is a Track Namespace Suffix.
 * Encode with moqctl_ns_put. */
int moqns_suffix_take(wired_span body, moqctl_ns* out);

/** draft-ietf-moq-transport-19 10.20 PUBLISH_SKIPPED: a SUBSCRIBE_TRACKS
 * response-stream message naming one Track the publisher will not PUBLISH
 * for -- ns is the Track Namespace Suffix (past the SUBSCRIBE_TRACKS's
 * Track Namespace Prefix, like NAMESPACE/NAMESPACE_DONE), name the Track
 * Name. */
typedef struct {
  moqctl_ns  ns;
  wired_span name;
} moqns_pub_skipped;

int moqns_pub_skipped_take(wired_span body, moqns_pub_skipped* out);
int moqns_pub_skipped_encode(
    wired_mspan buf, usz* off, const moqns_pub_skipped* m);

#endif
