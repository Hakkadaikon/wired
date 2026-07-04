#ifndef WIRED_H3REQDRIVE_REQUEST_PARSE_H
#define WIRED_H3REQDRIVE_REQUEST_PARSE_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "common/bytes/span/span.h"

/* RFC 9114 4.1: take the request STREAM frame, locate its HEADERS field section
 * tolerating leading unknown/GREASE frames (RFC 9114 9), then view the trailing
 * DATA frame body into r. On success *fs views the HEADERS field section in
 * place. Returns 1, or 0 on a malformed/truncated stream. */
int wired_h3reqdrive_request_sections(
    quic_span stream_data, quic_span* fs, wired_h3reqdrive_req* r);

#endif
