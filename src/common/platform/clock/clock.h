#ifndef CLOCK_H
#define CLOCK_H

#include "common/platform/sys/syscall.h"

/** CLOCK_REALTIME (linux clockid). */
#define CLOCK_REALTIME 0

/** A kernel timespec: seconds and nanoseconds since the UNIX epoch, the
 * struct clock_gettime(2) fills. */
typedef struct {
  i64 sec;  /**< whole seconds since the UNIX epoch */
  i64 nsec; /**< nanoseconds past sec, [0, 1e9) */
} timespec;

/** Civil UTC time as packed decimal YYYYMMDDHHMMSS (the convention of
 * x509_validity_ok) from UNIX epoch seconds. Proleptic Gregorian, no
 * leap seconds.
 * @param secs UNIX epoch seconds
 * @return packed decimal YYYYMMDDHHMMSS */
u64 clock_epoch_to_ymdhms(u64 secs);

/** The current wall-clock UTC as packed decimal YYYYMMDDHHMMSS, read via
 * clock_gettime(CLOCK_REALTIME).
 * @return packed decimal YYYYMMDDHHMMSS, or 0 on syscall failure */
u64 clock_ymdhms(void);

/** The current wall-clock UTC as raw UNIX epoch seconds, read via
 * clock_gettime(CLOCK_REALTIME). Unlike clock_ymdhms, this is
 * arithmetic-friendly (e.g. computing a validity window's end as now + N
 * days before formatting either bound).
 * @return UNIX epoch seconds, or 0 on syscall failure */
u64 wired_clock_epoch_secs(void);

/** Octets of an IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"). */
#define CLOCK_IMF_FIXDATE_LEN 29

/** RFC 9110 5.6.7: UNIX epoch seconds as an IMF-fixdate, the HTTP Date
 * format (no NUL terminator).
 * @param secs UNIX epoch seconds
 * @param out receives CLOCK_IMF_FIXDATE_LEN octets */
void clock_imf_fixdate(u64 secs, u8* out);

#endif
