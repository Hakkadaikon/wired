#ifndef QUIC_TLS_CRYPTOLEVEL_H
#define QUIC_TLS_CRYPTOLEVEL_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1.3: each encryption level has its own CRYPTO stream offset
 * space. Once a level is superseded (keys for a higher level have been
 * installed), it becomes "previously installed"; these predicates decide
 * the two error conditions that apply to a superseded level, leaving the
 * caller to track per-level offsets and to close the connection. */

/* 1 if CRYPTO data [offset, offset+len) arriving at a previously installed
 * (superseded) encryption level extends past max_seen, the highest
 * offset+len already accepted at that level before it became superseded.
 * The caller must call this only for a level it has already superseded;
 * a true result is a connection error of type PROTOCOL_VIOLATION. */
int quic_cryptolevel_stale_extends(u64 max_seen, u64 offset, u64 len);

/* 1 if a level being superseded still has buffered-but-undelivered data:
 * received_to (the contiguous prefix received) is past read_upto (the
 * prefix already handed to TLS). Call when keys for a higher level are
 * about to be installed; a true result is a connection error of type
 * PROTOCOL_VIOLATION. */
int quic_cryptolevel_unconsumed_on_promote(u64 received_to, u64 read_upto);

#endif
