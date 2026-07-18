#ifndef QUIC_CLOCK_H
#define QUIC_CLOCK_H

#include "common/platform/sys/syscall.h"

/** CLOCK_REALTIME (linux clockid). */
#define QUIC_CLOCK_REALTIME 0

/** A kernel timespec: seconds and nanoseconds since the UNIX epoch, the
 * struct clock_gettime(2) fills. */
typedef struct {
  i64 sec;  /**< whole seconds since the UNIX epoch */
  i64 nsec; /**< nanoseconds past sec, [0, 1e9) */
} quic_timespec;

/** Civil UTC time as packed decimal YYYYMMDDHHMMSS (the convention of
 * quic_x509_validity_ok) from UNIX epoch seconds. Proleptic Gregorian, no
 * leap seconds.
 * @param secs UNIX epoch seconds
 * @return packed decimal YYYYMMDDHHMMSS */
u64 quic_clock_epoch_to_ymdhms(u64 secs);

/** The current wall-clock UTC as packed decimal YYYYMMDDHHMMSS, read via
 * clock_gettime(CLOCK_REALTIME).
 * @return packed decimal YYYYMMDDHHMMSS, or 0 on syscall failure */
u64 quic_clock_ymdhms(void);

/** The current wall-clock UTC as raw UNIX epoch seconds, read via
 * clock_gettime(CLOCK_REALTIME). Unlike quic_clock_ymdhms, this is
 * arithmetic-friendly (e.g. computing a validity window's end as now + N
 * days before formatting either bound).
 * @return UNIX epoch seconds, or 0 on syscall failure */
u64 quic_clock_epoch_secs(void);

#endif
