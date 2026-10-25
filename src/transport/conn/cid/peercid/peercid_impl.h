#ifndef TRANSPORT_CONN_CID_PEERCID_PEERCID_IMPL_H
#define TRANSPORT_CONN_CID_PEERCID_PEERCID_IMPL_H

/* Internal to the peercid*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/diag/error/error.h"
#include "transport/conn/cid/peercid/peercid.h"
#include "transport/conn/cid/sresetdrive/detect.h"

void peercid_drop(peercid* p, peercid_entry* e);

#endif
