#ifndef WIRED_H3REQDRIVE_REQUEST_PARSE_IMPL_H
#define WIRED_H3REQDRIVE_REQUEST_PARSE_IMPL_H

#include "app/http3/request/h3reqdrive/request_parse.h"

/* request_parse_frames.c: the request-stream frame grammar (RFC 9114 4.1,
 * 7.2) shared with request_parse.c. */
int h3reqdrive_frame_type_ok(u64 t);
int h3reqdrive_frames_after_headers(
    wired_span h3, usz off, wired_h3reqdrive_req* r);

#endif
