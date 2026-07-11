#include "common/platform/thread/thread.h"

#include "test.h"

/* Thread bodies must not call libc: a raw clone(2) thread has no TLS setup,
 * so only direct syscalls and compiler atomics are safe inside fn. */

static volatile u32 thread_one_val;

static void thread_one_fn(void* arg) {
  (void)arg;
  __atomic_store_n(&thread_one_val, 42u, __ATOMIC_RELEASE);
}

/* Single thread: start, join, side effect visible, handle scrubbed. Join
 * returning at all is the live-system bridge for the join protocol. */
static void test_thread_single(void) {
  wired_thread t = {0, 0, 0};
  CHECK(wired_thread_start(&t, thread_one_fn, 0) == 0);
  CHECK(wired_thread_join(&t) == 0);
  CHECK(__atomic_load_n(&thread_one_val, __ATOMIC_ACQUIRE) == 42u);
  CHECK(t.tid == 0);
  CHECK(t.stack == 0);
}

static volatile u32 thread_slot[2];

static void thread_slot0_fn(void* arg) {
  (void)arg;
  __atomic_store_n(&thread_slot[0], 7u, __ATOMIC_RELEASE);
}

static void thread_slot1_fn(void* arg) {
  (void)arg;
  __atomic_store_n(&thread_slot[1], 9u, __ATOMIC_RELEASE);
}

/* Two threads alive at once, each writing its own slot; both join. */
static void test_thread_pair(void) {
  wired_thread a = {0, 0, 0};
  wired_thread b = {0, 0, 0};
  CHECK(wired_thread_start(&a, thread_slot0_fn, 0) == 0);
  CHECK(wired_thread_start(&b, thread_slot1_fn, 0) == 0);
  CHECK(wired_thread_join(&a) == 0);
  CHECK(wired_thread_join(&b) == 0);
  CHECK(__atomic_load_n(&thread_slot[0], __ATOMIC_ACQUIRE) == 7u);
  CHECK(__atomic_load_n(&thread_slot[1], __ATOMIC_ACQUIRE) == 9u);
}

/* Argument plumbing: a struct pointer travels through arg, the thread
 * writes results back, and its tid differs from the caller's. */
typedef struct {
  i64 in;
  i64 out;
  i64 tid;
} thread_arg_box;

static void thread_arg_fn(void* arg) {
  thread_arg_box* box = (thread_arg_box*)arg;
  box->out            = box->in * 2;
  box->tid            = wired_thread_tid();
}

static void test_thread_arg(void) {
  thread_arg_box box = {21, 0, 0};
  wired_thread   t   = {0, 0, 0};
  CHECK(wired_thread_start(&t, thread_arg_fn, &box) == 0);
  CHECK(wired_thread_join(&t) == 0);
  CHECK(box.out == 42);
  CHECK(box.tid > 0);
  CHECK(box.tid != wired_thread_tid());
}

/* gettid on the calling thread is a positive kernel tid. */
static void test_thread_tid(void) { CHECK(wired_thread_tid() > 0); }

void test_thread(void) {
  test_thread_tid();
  test_thread_single();
  test_thread_pair();
  test_thread_arg();
}
