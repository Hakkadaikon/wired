/* word_list's TU-shared declarations: wired_server.c (the history demo, CLI
 * and entry point) and static_file.c (--root mode and the access log). */
#ifndef WORD_LIST_H
#define WORD_LIST_H

#include "wired.h"

/* Application/driver configuration, resolved once at startup from argv and
 * handed to app_on_request as its opaque ctx. --root selects static file
 * mode; absent, the demo history mode runs unchanged (back-compat). driver
 * carries which of the four run paths wired_srvdriver_run takes. */
typedef struct {
  const char*         root;       /**< document root, or 0 for history mode */
  const char*         index;      /**< index file name for dir requests */
  const char*         access_log; /**< access log path, or 0 to disable */
  const char*         cert_path;  /**< cert.pem path (--cert) */
  const char*         key_path;   /**< key.pem path (--key) */
  wired_srvdriver_opt driver;     /**< resolved driver selection + knobs */
} app_config;

/* One access-log line per request (static_file.c). */
void wl_access_log(
    const app_config* cfg,
    wired_span        method,
    wired_span        path,
    u64               status,
    u64               nbytes);

/* Static-file mode: one round of path's file into body_out (static_file.c).
 */
u64 wl_serve_static(
    const app_config* cfg,
    wired_span        path,
    u64               offset,
    wired_obuf*       body_out,
    const char**      content_type,
    int*              more,
    u64*              total_size);

#endif
