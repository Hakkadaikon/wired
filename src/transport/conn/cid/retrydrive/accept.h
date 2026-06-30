#ifndef QUIC_RETRYDRIVE_ACCEPT_H
#define QUIC_RETRYDRIVE_ACCEPT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2.5.2: a client accepts the first Retry only; later Retry
 * packets and a Retry whose Integrity Tag is invalid are discarded. Returns 1
 * to accept (first Retry with a valid tag), 0 to discard. */
int quic_retrydrive_accept(int already_received_retry, int integrity_tag_valid);

#endif
