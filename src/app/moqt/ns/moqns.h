#ifndef MOQNS_H
#define MOQNS_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * draft-ietf-moq-transport-19 namespace messages: SUBSCRIBE_NAMESPACE
 * (10.18), PUBLISH_NAMESPACE (10.15), NAMESPACE (10.16) and NAMESPACE_DONE
 * (10.17). Every take decodes one whole Message Body (the bytes
 * moqctl_peek_type framed) and returns MOQCTL_OK, MOQCTL_VIOLATION
 * (malformed, or a Length mismatch -- see moqctl_body_end) or
 * MOQCTL_PARAMS_KVFMT. Encoders write the Body only and return 1 ok, 0 if
 * buf is too small.
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
int moqns_req_encode(wired_mspan buf, usz* off, const moqns_req* m);

/** NAMESPACE / NAMESPACE_DONE: the body is a Track Namespace Suffix.
 * Encode with moqctl_ns_put. */
int moqns_suffix_take(wired_span body, moqctl_ns* out);

#endif
