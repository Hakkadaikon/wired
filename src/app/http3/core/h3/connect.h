#ifndef QUIC_H3_CONNECT_H
#define QUIC_H3_CONNECT_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "common/platform/sys/syscall.h"

/* Pseudo-header presence flags a CONNECT request is checked against. */
typedef struct {
  int has_method_connect;
  int has_authority;
  int has_scheme;
  int has_path;
} quic_h3_connect_flags;

/* RFC 9114 4.4. A CONNECT request omits the :scheme and :path pseudo-header
 * fields and MUST include the :authority pseudo-header; :method is "CONNECT".
 * Returns 1 if the presence flags satisfy this, 0 otherwise. */
int quic_h3_connect_ok(const quic_h3_connect_flags *f);

/* RFC 9114 4.4. Validate a decoded request as a well-formed CONNECT: :method is
 * exactly "CONNECT", :authority present, :scheme and :path absent. Derives the
 * presence flags from r and applies quic_h3_connect_ok. Returns 1 if valid
 * (tunnel may proceed), 0 if it must be treated as malformed. */
int quic_h3_connect_req_ok(const quic_h3reqdrive_req *r);

/* RFC 9110 9.3.6. A 2xx response to CONNECT establishes the tunnel; any other
 * status does not. Returns 1 for 200..299, 0 otherwise. */
int quic_h3_connect_established(u16 status);

/* RFC 9114 4.4 / RFC 9110 9.3.6. Forward-only CONNECT tunnel lifecycle. A
 * validated request reaches VALIDATED; a 2xx response moves it once to
 * ESTABLISHED, a >=3xx response to FAILED; relay is permitted only from
 * ESTABLISHED; a close is terminal and never returns to RELAY. */
typedef enum {
  QUIC_H3_TUNNEL_REQ = 0,
  QUIC_H3_TUNNEL_VALIDATED,
  QUIC_H3_TUNNEL_ESTABLISHED,
  QUIC_H3_TUNNEL_FAILED,
  QUIC_H3_TUNNEL_RELAY,
  QUIC_H3_TUNNEL_CLOSED
} quic_h3_tunnel;

void quic_h3_tunnel_init(quic_h3_tunnel *st);
void quic_h3_tunnel_validated(quic_h3_tunnel *st);
/* Apply a response status. Returns 1 if it established the tunnel (2xx, once),
 * 0 otherwise (already established, failed, or wrong state). */
int quic_h3_tunnel_response(quic_h3_tunnel *st, u16 status);
/* Enter relay. Returns 1 if relay began (only from ESTABLISHED), 0 otherwise.
 */
int  quic_h3_tunnel_relay(quic_h3_tunnel *st);
void quic_h3_tunnel_close(quic_h3_tunnel *st);

#endif
