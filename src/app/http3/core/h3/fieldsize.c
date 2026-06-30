#include "app/http3/core/h3/fieldsize.h"

/* RFC 9114 4.2.2 */
int quic_h3_field_section_ok(u64 size, u64 max_size) {
  if (max_size == 0) return 1;
  return size <= max_size;
}
