#include "common/platform/clock/clock.h"

#include "common/bytes/util/bytes.h"

/* The civil year/month/day clock_civil writes. */
typedef struct {
  u64 y, m, d;
} clock_ymd;

/* Days since 1970-01-01 to civil y/m/d (Howard Hinnant, civil_from_days).
 * The month term mp counts from March so leap days land at year end; a
 * January/February date (mp >= 10) belongs to the next civil year. */
static void clock_civil(u64 days, clock_ymd* out) {
  u64 z = days + 719468, era = z / 146097, doe = z - era * 146097;
  u64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  u64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  u64 mp  = (5 * doy + 2) / 153;
  out->d  = doy - (153 * mp + 2) / 5 + 1;
  out->m  = mp < 10 ? mp + 3 : mp - 9;
  out->y  = yoe + era * 400 + (mp >= 10);
}

u64 clock_epoch_to_ymdhms(u64 secs) {
  u64       days = secs / 86400, rem = secs % 86400;
  clock_ymd ymd;
  clock_civil(days, &ymd);
  return ((ymd.y * 100 + ymd.m) * 100 + ymd.d) * 1000000 +
         (rem / 3600) * 10000 + (rem / 60 % 60) * 100 + rem % 60;
}

u64 clock_ymdhms(void) {
  timespec ts = {0};
  if (wired_arch_clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return clock_epoch_to_ymdhms((u64)ts.sec);
}

u64 wired_clock_epoch_secs(void) {
  timespec ts = {0};
  if (wired_arch_clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return (u64)ts.sec;
}

/* Two decimal digits of v % 100 at p. */
static void clock_put2(u8* p, u64 v) {
  p[0] = (u8)('0' + v / 10 % 10);
  p[1] = (u8)('0' + v % 10);
}

/* "hh:mm:ss GMT" for rem seconds into the day, at p. */
static void clock_put_time(u8* p, u64 rem) {
  clock_put2(p, rem / 3600);
  p[2] = ':';
  clock_put2(p + 3, rem / 60 % 60);
  p[5] = ':';
  clock_put2(p + 6, rem % 60);
  bytes_memcpy(p + 8, " GMT", 4);
}

/* RFC 9110 5.6.7: day-name "," SP date1 SP time-of-day SP "GMT", with
 * day 0 (1970-01-01) a Thursday. */
void clock_imf_fixdate(u64 secs, u8* out) {
  static const char wday[] = "ThuFriSatSunMonTueWed";
  static const char mon[]  = "JanFebMarAprMayJunJulAugSepOctNovDec";
  u64               days   = secs / 86400;
  clock_ymd         ymd;
  clock_civil(days, &ymd);
  bytes_memcpy(out, wday + days % 7 * 3, 3);
  bytes_memcpy(out + 3, ", ", 2);
  clock_put2(out + 5, ymd.d);
  out[7] = ' ';
  bytes_memcpy(out + 8, mon + (ymd.m - 1) * 3, 3);
  out[11] = ' ';
  clock_put2(out + 12, ymd.y / 100);
  clock_put2(out + 14, ymd.y);
  out[16] = ' ';
  clock_put_time(out + 17, secs % 86400);
}
