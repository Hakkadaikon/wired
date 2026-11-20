#include "app/qpack/qpack/relindex.h"

#include "common/bytes/util/num.h"

/* RFC 9204 3.2.5 */
int qpack_rel_to_abs(u64 base, u64 rel, u64* abs) {
  u64 top;
  return u64_sub_ok(base, rel, &top) && u64_sub_ok(top, 1, abs);
}

/* RFC 9204 3.2.6 */
int qpack_postbase_to_abs(u64 base, u64 postbase, u64* abs) {
  return u64_add_ok(base, postbase, abs);
}
