#ifndef QUIC_INITPKT_INITOPEN_H
#define QUIC_INITPKT_INITOPEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.2: open an AEAD-protected Initial packet built by
 * quic_initpkt_build. Re-derives the Initial keys from dcid, removes header
 * protection, and AEAD-opens the payload in place. On success *crypto_out
 * points at the recovered frame bytes within pkt and *crypto_len holds their
 * length. Returns 1 on success, 0 on authentication failure or short input. */
int quic_initpkt_open(const u8 *dcid, u8 dcid_len, u8 *pkt, usz len, u64 pn,
                      const u8 **crypto_out, usz *crypto_len);

#endif
