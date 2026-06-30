#ifndef QUIC_H3REQDRIVE_REQUEST_PARSE_H
#define QUIC_H3REQDRIVE_REQUEST_PARSE_H

#include "app/http3/request/h3reqdrive/request_drive.h"

/* RFC 9114 4.1: take the request STREAM frame, locate its HEADERS field section
 * tolerating leading unknown/GREASE frames (RFC 9114 9), then view the trailing
 * DATA frame body into r. On success *fs / *fs_len view the HEADERS field
 * section in place. Returns 1, or 0 on a malformed/truncated stream. */
int quic_h3reqdrive_request_sections(
    const u8            *stream_data,
    usz                  len,
    const u8           **fs,
    usz                 *fs_len,
    quic_h3reqdrive_req *r);

#endif
