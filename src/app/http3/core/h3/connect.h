#ifndef H3_CONNECT_H
#define H3_CONNECT_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "common/platform/sys/syscall.h"

/** Pseudo-header presence flags a CONNECT request is checked against. */
typedef struct {
  int has_method_connect;
  int has_authority;
  int has_scheme;
  int has_path;
} h3_connect_flags;

/* RFC 9114 4.4. A CONNECT request omits the :scheme and :path pseudo-header
 * fields and MUST include the :authority pseudo-header; :method is "CONNECT".
 * Returns 1 if the presence flags satisfy this, 0 otherwise. */
int h3_connect_ok(const h3_connect_flags* f);

/* RFC 9110 9.3.6: 1 if r's :method is exactly "CONNECT" (methods are
 * case-sensitive, RFC 9110 9.1), 0 otherwise. */
int h3_connect_is_method(const wired_h3reqdrive_req* r);

/* RFC 9114 4.4. Validate a decoded request as a well-formed CONNECT: :method is
 * exactly "CONNECT", :authority present, :scheme and :path absent. Derives the
 * presence flags from r and applies h3_connect_ok. Returns 1 if valid
 * (tunnel may proceed), 0 if it must be treated as malformed. */
int h3_connect_req_ok(const wired_h3reqdrive_req* r);

/* RFC 9220 3. A server MUST NOT accept a :protocol pseudo-header unless it
 * has sent SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (settings_enabled non-zero).
 * Returns 1 if r carries no :protocol, or :protocol is present and settings_
 * enabled is non-zero; 0 if :protocol is present but not negotiated. */
int h3_connect_protocol_ok(const wired_h3reqdrive_req* r, int settings_enabled);

#endif
