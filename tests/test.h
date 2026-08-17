#ifndef TEST_H
#define TEST_H

/* Tiny assert-based harness. Hosted build only. */
#include <stdio.h>

static int wired_test_fails = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      wired_test_fails++;                                    \
    }                                                        \
  } while (0)

#define TEST_REPORT()                                                  \
  (wired_test_fails ? (printf("%d failure(s)\n", wired_test_fails), 1) \
                    : (printf("all tests passed\n"), 0))

#endif
