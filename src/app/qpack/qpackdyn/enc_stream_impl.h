#ifndef APP_QPACK_QPACKDYN_ENC_STREAM_IMPL_H
#define APP_QPACK_QPACKDYN_ENC_STREAM_IMPL_H

/* Internal to the enc_stream*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpack/string.h"
#include "app/qpack/qpackdyn/cstr.h"
#include "app/qpack/qpackdyn/enc_stream.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"

/* One whole encoder instruction: its bytes, the leading integer's length
 * and value, and which instruction the leading byte selected. */
typedef struct {
  wired_span     b;
  usz            n;
  u64            v;
  qpack_enc_kind kind;
} enc_ins;

/* The T bit sits just above the 6-bit name index. */
#define QPACK_ENC_NAMEREF_T 0x40

/* RFC 9204 4.2: the encoder stream's type. */
#define QDYN_ENC_STREAM_TYPE 0x02

int qdyn_enc_keep(wired_obuf* sc, wired_span src);
int qdyn_enc_insert_value(
    qpack_dyn* t, const wired_obuf* sc, wired_span b, usz off);
int qdyn_enc_capacity(const enc_ins* i, qpack_dyn* t, u64 max);
int qdyn_do_nameref(const enc_ins* i, qpack_dyn* t, u64 max);
int qdyn_rx_has(const qdyn_encrx* rx, usz i);
int qdyn_rx_land(qdyn_encrx* rx, u64 off, wired_span d);

extern usz (*const enc_ends[4])(wired_span, usz);

#endif
