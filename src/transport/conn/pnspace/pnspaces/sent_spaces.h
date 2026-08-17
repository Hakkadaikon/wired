#ifndef QUIC_PNSPACES_SENT_SPACES_H
#define QUIC_PNSPACES_SENT_SPACES_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/lifecycle/conn/pnspace.h"
#include "transport/recovery/rtx/sentpkt/ack_process.h"
#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9000 13: each packet number space tracks its own sent packets and is
 * acknowledged independently; an ACK in one space never touches another. */

/** Per packet-number-space sent-packet tracking (RFC 9000 13): one
 * sentpkt table per space, acknowledged independently. */
typedef struct {
  sentpkt t[QUIC_PNS_COUNT];
} pnspaces_sent;

void pnspaces_sent_init(pnspaces_sent* s);

/* Record an in-flight packet in `space` only. Returns 1 on success, 0 if that
 * space's table is full. */
int pnspaces_on_send(pnspaces_sent* s, int space, const sentpkt_out* pkt);

/** The space an ACK applies to, plus its ranges (RFC 9000 19.3). */
typedef struct {
  int    space;
  ackset ackset;
} pnspaces_ack_in;

/* Process an ACK against `in->space` only; other spaces are untouched. Acked
 * packet numbers are appended to newly_acked_pns and *n_acked set to the
 * count. */
void pnspaces_on_ack(pnspaces_sent* s, const pnspaces_ack_in* in, u64out acked);

/* In-flight count recorded in `space`. */
usz pnspaces_sent_count(const pnspaces_sent* s, int space);

#endif
