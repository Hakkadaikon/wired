#ifndef TRANSPORT_CONN_CID_PEERCID_PEERCID_IMPL_H
#define TRANSPORT_CONN_CID_PEERCID_PEERCID_IMPL_H

/* Internal to the peercid*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/diag/error/error.h"
#include "transport/conn/cid/peercid/peercid.h"
#include "transport/conn/cid/sresetdrive/detect.h"

/* Retire e: queue its RETIRE_CONNECTION_ID and free it. 0 (e kept) when
 * the retire queue is full. */
int peercid_drop(peercid* p, peercid_entry* e);
/* Queue seq for retirement: 0, or CONNECTION_ID_LIMIT_ERROR when full. */
int peercid_owe_err(peercid* p, u64 seq);
/* 1 if seq was retired here (owed or sent) within 64 of rpt either side. */
int peercid_retired(const peercid* p, u64 seq);
/* Raise rpt to rpt (> p->rpt), shifting the retired record with it. */
void peercid_slide(peercid* p, u64 rpt);

#endif
