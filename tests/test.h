#ifndef QUIC_TEST_H
#define QUIC_TEST_H

/* Tiny assert-based harness. Hosted build only. */
#include <stdio.h>

static int quic_test_fails = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      quic_test_fails++;                                     \
    }                                                        \
  } while (0)

#define TEST_REPORT()                                                \
  (quic_test_fails ? (printf("%d failure(s)\n", quic_test_fails), 1) \
                   : (printf("all tests passed\n"), 0))

#endif
