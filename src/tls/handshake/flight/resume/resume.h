#ifndef QUIC_RESUME_RESUME_H
#define QUIC_RESUME_RESUME_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/schedule.h"

/* Resumption driver: hold a TLS session ticket (RFC 8446 4.6.1) across
 * connections and decide whether 0-RTT may be attempted on a later connection
 * (RFC 9001 4.6, RFC 9000 7). A Retry between attempts does not invalidate the
 * ticket (RFC 9000 8.1, 17.2.5): the resumed Initial carries both the Retry
 * token and the resumption PSK. */

#define QUIC_RESUME_TICKET_MAX 512

/* RFC 1035 3.1: a full domain name is at most 255 octets. */
#define QUIC_RESUME_SNI_MAX 255

/** RFC 8446 4.6.1: a stored session ticket plus the resumption PSK and
 * transport-parameter/SNI metadata needed to attempt 0-RTT on it later. */
typedef struct {
  u8  ticket[QUIC_RESUME_TICKET_MAX];
  usz ticket_len;
  u64 issued_at; /* RFC 8446 4.6.1 ticket issuance time */
  u32 lifetime;  /* ticket_lifetime, seconds */
  u64 max_data;  /* RFC 9000 7.4.1: remembered initial_max_data */
  int have_ticket;
  u8  psk[32];  /* RFC 8446 4.6.1: the resumption PSK captured with it */
  int have_psk; /* 1 when psk holds a value */
  /** RFC 6066 3: the server_name the original session was established
   * under, or sni_len 0 when none was offered. */
  u8  sni[QUIC_RESUME_SNI_MAX];
  usz sni_len;
} resume;

/** The transport parameters and ticket metadata to remember alongside a
 * stored ticket, besides the ticket bytes themselves. */
typedef struct {
  u64       issued_at; /* RFC 8446 4.6.1 ticket issuance time */
  u32       lifetime;  /* ticket_lifetime, seconds */
  u64       max_data;  /* RFC 9000 7.4.1: remembered initial_max_data */
  const u8* psk;       /* 32-byte resumption PSK, or 0 when unknown */
  /** RFC 6066 3: the server_name this session was established under (a view
   * kept alive only for the call), or n 0 when none was offered. Longer than
   * QUIC_RESUME_SNI_MAX is truncated to it. */
  wired_span sni;
} resume_store_in;

/* Store a ticket and the transport parameters to remember for 0-RTT.
 * Returns 1 on success, 0 if the ticket does not fit. RFC 8446 4.6.1. */
int resume_store(resume* r, wired_span ticket, const resume_store_in* in);

/* Serialize the stored session (ticket, metadata, PSK) into an opaque blob
 * the application can persist across processes (quiche session() shape).
 * Returns the byte count, or 0 when nothing is stored / out is too small. */
usz resume_session(const resume* r, u8* out, usz cap);

/* Restore a blob produced by resume_session. Returns 1 on success, 0 on
 * a malformed/truncated blob (r is left untouched then). */
int resume_set_session(resume* r, wired_span blob);

/* Derive the 0-RTT early keys from the stored session's PSK over the new
 * connection's ClientHello (RFC 9001 4.6 via tls_early_keys). Returns 1,
 * or 0 when the session carries no PSK. */
int resume_early_keys(
    const resume* r, const u8* ch, usz ch_len, initial_keys* out);

/* Returns 1 when a stored ticket is still within its lifetime at `now`
 * (seconds, same clock as issued_at). RFC 8446 4.6.1. */
int resume_valid(const resume* r, u64 now);

/* Returns 1 when the new connection's transport parameters are no more
 * permissive than those remembered, so 0-RTT data stays within limits.
 * RFC 9001 4.6 / RFC 9000 7.4.1. */
int resume_tp_compatible(u64 remembered_max_data, u64 new_max_data);

/* RFC 6066 3: the server_name offered on a resumption attempt is compatible
 * with the one the session was established under -- an empty new_sni (the
 * extension omitted this time) is always compatible, otherwise it must equal
 * the remembered server_name exactly (RFC 6125 6.4.1 ASCII case-insensitive
 * comparison, matching x509_san_matches's DNS-ID rule). A stored
 * session with no remembered server_name (r->sni_len 0) is compatible with
 * any new_sni. Returns 1 compatible, 0 otherwise. */
int resume_sni_compatible(const resume* r, wired_span new_sni);

/* Returns 1 when 0-RTT may be attempted: ticket valid and transport
 * parameters compatible. RFC 9001 4.6. */
int resume_can_0rtt(const resume* r, int ticket_valid, int tp_compatible);

/* Returns 1 when the stored ticket remains usable after a Retry. A Retry never
 * invalidates resumption. RFC 9000 8.1 / 17.2.5. */
int resume_after_retry(const resume* r, int retry_received);

#endif
