#ifndef TLS_HANDSHAKE_ROLES_SERVER_SERVER_IMPL_H
#define TLS_HANDSHAKE_ROLES_SERVER_SERVER_IMPL_H

/* Internal to the server*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "common/platform/keylog/keylog.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server.h"
#include "tls/handshake/roles/srvfin/hsdone.h"
#include "tls/handshake/roles/srvfin/verify.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/lifecycle/idledrive/idlenego.h"
#include "transport/conn/loop/crecv/message.h"

/* The expanded 1-RTT keys start empty: xkeys_sync builds them from this
 * connection's own keys, and a slot's earlier connection leaves none
 * behind (RFC 9001 6.5 asks the same of discarded keys). In this header so
 * every build that takes server.c gets it with it. */
static inline void server_reset_xkeys(wired_server* s) {
  xkeys_wipe(&s->kx_send);
  for (usz i = 0; i < sizeof s->kx_recv / sizeof s->kx_recv[0]; i++) {
    xkeys_wipe(&s->kx_recv[i]);
  }
}

/* RFC 8446 4.1.2: legacy_version(2) precedes ClientHello.random, both after
 * the 4-byte handshake header (HS_HEADER) put_prefix wrote them at. */
#define SRV_CH_RANDOM_OFF (HS_HEADER + 2)

/* RFC 8446 4 / A.2: wired_server.hs_wait, the next client handshake
 * message expected once the flight is out. */
#define SRV_WAIT_FIN 0  /* client Finished */
#define SRV_WAIT_CERT 1 /* client Certificate (CertificateRequest sent) */
#define SRV_WAIT_CV 2   /* client CertificateVerify */

/* RFC 8446 6.2 alerts the client authentication pieces close with. */
#define CAUTH_BAD_CERTIFICATE 42
#define CAUTH_ILLEGAL_PARAMETER 47
#define CAUTH_DECODE_ERROR 50
#define CAUTH_DECRYPT_ERROR 51
#define CAUTH_UNSUPPORTED_EXTENSION 110
#define CAUTH_CERTIFICATE_REQUIRED 116

/* The handshake message body past its 4-byte header (len >= HS_HEADER: the
 * feed hands on complete messages only). */
static inline wired_span server_cauth_body(const u8* msg, usz len) {
  return wired_span_of(msg + HS_HEADER, len - HS_HEADER);
}

const tls_hash* server_srv_hash(const wired_server* s);
int             server_srv_latch(wired_server* s, u8 alert);
int             server_srv_collect(wired_server* s, const u8* frames, usz len);
int             server_cauth_on_cert(wired_server* s, const u8* msg, usz len);
int             server_cauth_on_cv(wired_server* s, const u8* msg, usz len);
usz             server_srv_tr_add(wired_server* s, const u8* msg, usz len);
int             server_srv_verify_finished(
    wired_server* s, const u8* msg, usz len, u8* c_traffic);

#endif
