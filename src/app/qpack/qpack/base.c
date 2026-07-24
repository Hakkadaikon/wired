#include "app/qpack/qpack/base.h"

/* RFC 9204 4.5.1.2 */
u64 quic_qpack_base(u64 ric, int sign, u64 delta_base) {
  if (sign == 0) return ric + delta_base;
  return ric - delta_base - 1;
}

/* RFC 9204 4.5.1.2 */
int quic_qpack_base_valid(u64 ric, int sign, u64 delta_base) {
  if (sign == 0) return 1;
  return ric > delta_base;
}
