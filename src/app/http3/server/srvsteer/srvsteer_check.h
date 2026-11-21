#ifndef WIRED_SRVSTEER_SRVSTEER_CHECK_H
#define WIRED_SRVSTEER_SRVSTEER_CHECK_H

#include "app/http3/server/srvsteer/srvsteer.h"
#include "app/http3/server/srvthreads/srvthreads.h"
#include "app/http3/server/srvworkers/srvworkers.h"

/* Compile-time pin, included from srvsteer.c only: a worker count past the
 * steer fd table is refused by srvsteer_want (the run then falls back to
 * the kernel hash), and the table must cover everything either driver may
 * ask for. Lives in its own header so the drivers' .c files carry no extra
 * Halstead volume for it. */
_Static_assert(
    WIRED_SRVWORKERS_MAX <= SRVSTEER_MAX, "steer fd table covers all workers");
_Static_assert(
    WIRED_SRVTHREADS_MAX <= SRVSTEER_MAX, "steer fd table covers all threads");

#endif
