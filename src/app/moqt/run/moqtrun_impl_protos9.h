#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART10_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART10_H

#include "app/moqt/run/moqtrun_impl_protos8.h"

int moqtrun_fsel_pass(
    const wired_moqtrun_rngrow* rows, usz n, const moqtrun_fsel_obj* o);
moqctl_loc moqtrun_fsel_skip(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  from,
    moqctl_loc                  end);
moqctl_loc moqtrun_fsel_fskip(
    moqcache* c, const wired_moqtrun_fetch* f, moqctl_loc from, moqctl_loc end);
void moqtrun_fsel_keep(
    wired_moqtrun_fetch* f, const wired_moqtrun_rngrow* rows, usz n);
usz moqtrun_fsel_rows(const moqctl_params* params, wired_moqtrun_rngrow* rows);
int moqtrun_fsel_up_pass(const wired_moqtrun_fetch* f, const moqfetch_obj* o);

#endif
