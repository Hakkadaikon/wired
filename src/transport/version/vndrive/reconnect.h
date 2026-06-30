#ifndef QUIC_VNDRIVE_RECONNECT_H
#define QUIC_VNDRIVE_RECONNECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 6.2: after selecting a version the client re-sends an Initial with
 * that version. To avoid an infinite loop it responds to a Version
 * Negotiation packet at most once. */

#define QUIC_VNDRIVE_MAX_RETRY 1

/* 1 if the client should re-send an Initial: chosen_version is non-zero and it
 * has not already exhausted its single VN retry. 0 means give up. */
int quic_vndrive_should_retry(u32 chosen_version, int vn_retry_count);

#endif
