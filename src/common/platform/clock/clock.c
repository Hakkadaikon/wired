#include "common/platform/clock/clock.h"

/* The civil year/month/day clock_civil writes. */
typedef struct {
  u64 y, m, d;
} clock_ymd;

/* Days since 1970-01-01 to civil y/m/d (Howard Hinnant, civil_from_days).
 * The month term mp counts from March so leap days land at year end; a
 * January/February date (mp >= 10) belongs to the next civil year. */
static void clock_civil(u64 days, clock_ymd *out) {
  u64 z = days + 719468, era = z / 146097, doe = z - era * 146097;
  u64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  u64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  u64 mp  = (5 * doy + 2) / 153;
  out->d  = doy - (153 * mp + 2) / 5 + 1;
  out->m  = mp < 10 ? mp + 3 : mp - 9;
  out->y  = yoe + era * 400 + (mp >= 10);
}

u64 quic_clock_epoch_to_ymdhms(u64 secs) {
  u64       days = secs / 86400, rem = secs % 86400;
  clock_ymd ymd;
  clock_civil(days, &ymd);
  return ((ymd.y * 100 + ymd.m) * 100 + ymd.d) * 1000000 +
         (rem / 3600) * 10000 + (rem / 60 % 60) * 100 + rem % 60;
}

u64 quic_clock_ymdhms(void) {
  quic_timespec ts;
  if (syscall3(SYS_clock_gettime, QUIC_CLOCK_REALTIME, &ts, 0) != 0) return 0;
  return quic_clock_epoch_to_ymdhms((u64)ts.sec);
}
