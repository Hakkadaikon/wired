#ifndef APP_HTTP3_SERVER_SRVLOOP_RESPOND_IMPL_H
#define APP_HTTP3_SERVER_SRVLOOP_RESPOND_IMPL_H

/* Internal to the respond*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/srvkeys/srvkeys.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/respond.h"
#include "app/http3/server/srvloop/send.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/clock/clock.h"
#include "tls/handshake/core/tls/newsessionticket.h"
#include "tls/keys/keyring/keyring.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_build.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ncid.h"
#include "transport/recovery/detect/ackgen/ackrange.h"
#include "transport/recovery/detect/ackgen/ackrangeconv.h"
#include "transport/recovery/detect/recovery/ackdelay.h"
#include "transport/stream/data/appdata/stream_send.h"

#define WIRED_SRVLOOP_RESP_STREAM 0
#define WIRED_SRVLOOP_CTRL_STREAM              \
  3 /* RFC 9114 6.2.1: first server uni stream \
     */

/* RFC 8446 4.6.1: encode a fresh NewSessionTicket message (fixed 2h
 * lifetime; issued_at is the server's wall clock at issuance, recorded so a
 * later 0-RTT attempt can be checked for freshness -- RFC 8446 4.2.11.1 /
 * 8.3, ticket_freshness_ok) carrying s's real resumption_master_secret
 * (RFC 8446 7.1). wired_server_resumption_secret only succeeds once
 * confirmed, which every caller here always is. Returns the encoded
 * message length in msg, or 0 on failure. */
/* RFC 9001 4.6.1: a QUIC server that supports 0-RTT always advertises
 * 0xffffffff here -- QUIC bounds 0-RTT via transport parameters, not this
 * TLS field (RFC 8446 4.2.10). A raw-QUIC connection is never admitted in
 * 0-RTT (sdrv_early_allowed), so its ticket omits the extension (0) rather
 * than invite early data that would only be refused. */
#define WIRED_SRVLOOP_MAX_EARLY_DATA_SIZE 0xffffffff

#define WIRED_SRVLOOP_BODY_MAX                                                \
  1024 /* ponytail: app response body cap; raise here if a handler needs more \
        */

int srvloop_emit_handshake_ack(const wired_srvloop_conn* c, wired_obuf* out);
int srvloop_build_settings_frame(
    const wired_server* s, wired_srvloop* l, wired_obuf* out);
int srvloop_confirm_payload(const wired_srvloop_conn* c, wired_obuf* out);
usz srvloop_app_ack_append(wired_srvloop* l, u8* buf, usz cap);
usz srvloop_app_ack_append_if_due(wired_srvloop* l, u8* buf, usz cap);
int srvloop_response_frame(wired_srvloop* l, int got_request, wired_obuf* out);
int srvloop_confirm_then_maybe_200(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out);
int srvloop_emit_ack_only(const wired_srvloop_conn* c, wired_obuf* out);

#endif
