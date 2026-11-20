/* libFuzzer harness for the QPACK dynamic-table Indexed Field Line decoder
 * (RFC 9204 4.5.2). Hosted build only — mirrors tests/run.c's unity-include
 * style, but this file itself may use the standard library since it lives
 * outside src/.
 *
 * The decoder resolves a dynamic reference (T=0) against a live dynamic-
 * table entry, so a table with at least one inserted entry is required to
 * reach that path. Seed the table with one fixed entry, then fuzz the field
 * line bytes: both the static-table (T=1) and dynamic-table (T=0) branches,
 * plus truncation/non-indexed rejection, are reachable from data alone.
 *
 * An input of 10 bytes or more spends its trailing 8 bytes (little-endian)
 * on the section's Base, so index arithmetic against a large Base -- the
 * RFC 9204 3.2.5/3.2.6 overflow/underflow rejections -- is reachable too.
 * The threshold sits above the pre-existing corpus inputs (at most 9
 * bytes), so their meaning is unchanged. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "app/qpack/qpack/dynget.c"
#include "app/qpack/qpack/dyntable.c"
#include "app/qpack/qpack/fieldline.c"
#include "app/qpack/qpack/insertcount.c"
#include "app/qpack/qpack/integer.c"
#include "app/qpack/qpack/prefix.c"
#include "app/qpack/qpack/relindex.c"
#include "app/qpack/qpack/static_table.c"
#include "app/qpack/qpackdyn/field_decode.c"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const u8* buf  = (const u8*)data;
  usz       n    = (usz)size;
  u64       base = 1;
  if (n >= 10) {
    n -= 8;
    memcpy(&base, buf + n, 8);
  }

  qpack_dyn table;
  qpack_dyn_init(&table, 4096);

  qpack_field seed = {
      wired_span_of((const u8*)"seed-name", 9),
      wired_span_of((const u8*)"seed-value", 10),
  };
  qpack_dyn_insert(&table, &seed);

  qdyn_src src = {&table, base, wired_span_of(buf, n), /* ric */ 1};

  qpack_field out;
  usz         consumed;
  qdyn_decode_field(&src, &out, &consumed);

  return 0;
}
