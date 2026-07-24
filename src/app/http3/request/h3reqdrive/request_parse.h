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

/* RFC 9114 4.1: view the trailer section's field-section payload (the HEADERS
 * frame immediately following the body's last DATA frame, or immediately
 * after the leading HEADERS if there is no body) into *trailer_fs.
 * @param stream_data the STREAM frame payload carrying the request
 * @param trailer_fs receives the trailer HEADERS frame's field-section view
 * @return 1 if a trailer section is present, 0 if there is none (not an
 *   error -- most requests have no trailer) or the stream is malformed. */
int wired_h3reqdrive_request_trailer(
    quic_span stream_data, quic_span* trailer_fs);

#endif
