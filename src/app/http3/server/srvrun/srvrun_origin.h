#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_ORIGIN_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_ORIGIN_H

#include "app/http3/server/srvrun/srvrun_impl.h"

/* RFC 9110 7.4 / 15.5.20: status, or 421 for an https request whose
 * origin the connection's certificate does not cover (srvrun_origin.c). */
u16 srvrun_origin_status(const srvrun_conn* c, u16 status);

#endif
