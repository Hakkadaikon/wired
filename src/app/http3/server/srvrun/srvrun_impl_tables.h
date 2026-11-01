#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_TABLES_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_TABLES_H

/* Internal to srvrun: a slot's big tables, handed back on free (Issue
 * #174, srvrun_free.c) and walked in member order (srvrun_retry.c). */

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"

void srvrun_release_tables(wired_srvrun_env* env, srvrun_conn* c, int i);
void srvrun_tables_each(srvrun_conn* c, void (*fn)(void* p, usz n));

#endif
