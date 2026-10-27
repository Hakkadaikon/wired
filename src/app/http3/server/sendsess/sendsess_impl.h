#ifndef APP_HTTP3_SERVER_SENDSESS_SENDSESS_IMPL_H
#define APP_HTTP3_SERVER_SENDSESS_SENDSESS_IMPL_H

/* Internal to the sendsess*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/sendsess/sendsess.h"
#include "common/bytes/util/num.h"
#include "transport/recovery/detect/recovery/lossdetect.h"

/* Clear log entry i's inflight flag and take it out of the running
 * inflight_n / inflight_len totals (i must be in flight). */
void sendsess_clear_inflight(wired_sendsess* s, usz i);

#endif
