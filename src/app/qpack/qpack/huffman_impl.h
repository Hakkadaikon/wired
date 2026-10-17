#ifndef APP_QPACK_QPACK_HUFFMAN_IMPL_H
#define APP_QPACK_QPACK_HUFFMAN_IMPL_H

/* Internal to the huffman*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/qpack/qpack/huffman.h"

#define HUFF_MAXLEN 30

/* Running decode state: a bit accumulator (acc) of nbits bits, plus the
 * output cursor (out, capacity dcap). ok stays 1 until a rule is broken. */
typedef struct {
  u32 acc;
  u32 nbits;
  u8* out;
  usz dcap;
  usz olen;
  int ok;
} hctx;

void qpack_step_bit(hctx* c, u32 bit);

#endif
