#include "test.h"

/* The accept rule: policy AND first use, never one alone. */
static void test_zerortt_accept_rule(void) {
  CHECK(zerortt_replay_ok(1, 1) == 1);
  CHECK(zerortt_replay_ok(1, 0) == 0);
  CHECK(zerortt_replay_ok(0, 1) == 0);
  CHECK(zerortt_replay_ok(0, 0) == 0);
}

void test_zerortt_policy(void) { test_zerortt_accept_rule(); }
