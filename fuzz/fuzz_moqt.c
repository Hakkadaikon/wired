/* libFuzzer harness for the MoQT codecs (draft-ietf-moq-transport-19):
 * varints (SS1.4.1), Key-Value-Pairs (SS10.2), the control-message
 * envelope + the eight message codecs (SS10), the data-stream decoders
 * (SS11.4), and the session state machine (SS3.3) fed with the events the
 * decoded control stream produces. Hosted build only — mirrors
 * tests/run.c's unity-include style, but this file itself may use the
 * standard library since it lives outside src/. */
#include <stddef.h>
#include <stdint.h>

#include "app/moqt/ctl/moqctl.c"
#include "app/moqt/data/moqdata.c"
#include "app/moqt/kvp/moqkvp.c"
#include "app/moqt/sess/moqsess.c"
#include "app/moqt/vi/moqvi.c"

/* Decode one control message body by its envelope type (SS10). */
static void fuzz_ctl_body(u64 type, wired_span body) {
  usz off = 0;
  if (type == MOQCTL_T_SETUP) {
    moqctl_setup m;
    moqctl_setup_take(body, &off, &m);
  } else if (type == MOQCTL_T_SUBSCRIBE) {
    moqctl_subscribe m;
    moqctl_subscribe_take(body, &off, &m);
  } else if (type == MOQCTL_T_SUBSCRIBE_OK) {
    moqctl_subscribe_ok m;
    moqctl_subscribe_ok_take(body, &off, &m);
  } else if (type == MOQCTL_T_PUBLISH) {
    moqctl_publish m;
    moqctl_publish_take(body, &off, &m);
  } else if (type == MOQCTL_T_REQUEST_OK) {
    moqctl_request_ok m;
    moqctl_request_ok_take(body, &off, &m);
  } else if (type == MOQCTL_T_REQUEST_ERROR) {
    moqctl_request_error m;
    moqctl_request_error_take(body, &off, &m);
  } else if (type == MOQCTL_T_PUBLISH_DONE) {
    moqctl_publish_done m;
    moqctl_publish_done_take(body, &off, &m);
  } else if (type == MOQCTL_T_GOAWAY) {
    moqctl_goaway m;
    moqctl_goaway_take(body, &off, &m);
  }
}

/* Walk the input as a control stream (SS10 envelope), feeding the session
 * state machine the event each outcome produces (SS3.3): the first SETUP
 * establishes, a decode violation or unknown type is a malformed-control
 * event, GOAWAY drives the shutdown path. */
static void fuzz_ctl_stream(wired_span in) {
  moqsess sess;
  moqsess_init(&sess);
  moqsess_step(&sess, MOQSESS_EV_SENT_SETUP);

  usz off = 0;
  for (;;) {
    u64        type;
    wired_span body;
    int        r = moqctl_peek_type(in, &off, &type, &body);
    if (r == MOQCTL_INSUFFICIENT) break;
    if (r != MOQCTL_OK) {
      moqsess_step(&sess, MOQSESS_EV_MALFORMED_CTRL);
      break;
    }
    fuzz_ctl_body(type, body);
    if (type == MOQCTL_T_SETUP) moqsess_step(&sess, MOQSESS_EV_RECV_SETUP);
    if (type == MOQCTL_T_GOAWAY) moqsess_step(&sess, MOQSESS_EV_RECV_GOAWAY);
    moqsess_should_buffer(&sess);
    moqsess_established(&sess);
    moqsess_may_reject_request(&sess);
  }
  moqsess_step(&sess, MOQSESS_EV_CTRL_CLOSED);
}

/* Reinterpret the same bytes as a data stream (SS11.4): classify, decode
 * the SUBGROUP_HEADER, then chain Object decodes until the bytes run out. */
static void fuzz_data_stream(wired_span in) {
  usz off = 0;
  int kind = moqdata_classify(in, &off);
  if (kind != MOQDATA_STREAM_SUBGROUP) return;

  moqdata_subhdr h;
  if (moqdata_subhdr_take(in, &off, &h) != MOQDATA_OK) return;
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  moqdata_obj    obj;
  while (moqdata_obj_take(in, &off, &seq, &obj) == MOQDATA_OK) {
    moqdata_subhdr_resolve(&h, obj.object_id);
  }
}

/* And as a bare varint / KVP list (SS1.4.1 / SS10.2). */
static void fuzz_primitives(wired_span in) {
  usz off = 0;
  u64 v;
  moqvi_take(in, &off, &v);

  usz    koff      = 0;
  u64    prev_type = 0;
  moqkvp kv;
  while (moqkvp_take(in, &koff, &prev_type, &kv) == MOQKVP_OK) {}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  wired_span in = wired_span_of((const u8 *)data, (usz)size);
  fuzz_ctl_stream(in);
  fuzz_data_stream(in);
  fuzz_primitives(in);
  return 0;
}
