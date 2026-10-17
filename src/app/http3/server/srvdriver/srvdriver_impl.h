#ifndef APP_HTTP3_SERVER_SRVDRIVER_SRVDRIVER_IMPL_H
#define APP_HTTP3_SERVER_SRVDRIVER_SRVDRIVER_IMPL_H

/* Internal to the srvdriver*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/srvdriver/srvdriver.h"
#include "app/http3/server/srvpin/srvpin.h"
#include "common/platform/cliargs/cliargs.h"
#include "common/platform/exit/exit.h"

typedef int (*srvdriver_load_fn)(int, char**, wired_srvdriver_opt*);

typedef int (*srvdriver_run_fn)(
    wired_srvboot_id*,
    wired_srvrun_handler,
    wired_srvrun_obs,
    const wired_srvdriver_opt*);

int srvdriver_load_kind(int argc, char** argv, wired_srvdriver_opt* opt);
int srvdriver_parse_head(int argc, char** argv, wired_srvdriver_opt* opt);
int srvdriver_run_threads(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt);

#endif
