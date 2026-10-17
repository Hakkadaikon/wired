#include "app/moqt/run/moqtswitch_impl.h"

u64 moqtsw_upd_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  moqtsw_req r = {idx, t, s, 0, s ? s->request_id : 0};
  return moqtsw_verdict(hub, ops, &r, params);
}
