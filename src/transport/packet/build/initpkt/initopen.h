#ifndef INITPKT_INITOPEN_H
#define INITPKT_INITOPEN_H

#include "common/bytes/span/span.h"
#include "transport/version/version/version.h"

/* RFC 9001 5.2: open an AEAD-protected Initial packet built by
 * initpkt_build. Re-derives the Initial keys from dcid, removes header
 * protection, and AEAD-opens the payload in place. On success *crypto views
 * the recovered frame bytes within pkt. Returns 1 on success, 0 on
 * authentication failure or short input. Equivalent to
 * initpkt_open_ver(dcid, VERSION_1, pkt, crypto). */
int initpkt_open(wired_span dcid, wired_mspan pkt, wired_span* crypto);

/* RFC 9001 5.2 / RFC 9369 3.3.1: same as initpkt_open, but deriving
 * Initial keys under the given version (the long header's own Version
 * field) instead of assuming v1 -- what a server's accept path needs for a
 * peer that arrived already speaking v2 -- and recovering the truncated
 * wire packet number against largest_pn, the largest Initial packet number
 * received so far (RFC 9000 A.3; a client whose Initials have been acked
 * truncates its retransmits below what the raw wire bytes express). */
int initpkt_open_ver(
    wired_span  dcid,
    u32         version,
    wired_mspan pkt,
    u64         largest_pn,
    wired_span* crypto);

#endif
