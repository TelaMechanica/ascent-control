#ifndef ASCENT_LEGACY_PRO_CV610_REGS_H
#define ASCENT_LEGACY_PRO_CV610_REGS_H
#include "legacy_pro_core.h"
#include "ot_common_sns.h"

/* Cache of published requests, never a readback or applied-state observation.
 * The caller owns serialization and physical bus/profile admission. */
struct lp_cv610_reg_cache {
    uint32_t has_emitted;
    unsigned fps;
    int bus;
    struct lp_write last_emitted[7];
};
/* Build one group-held exposure/gain transaction for the CV610 ISP scheduler.
 * The incoming SDK config flag controls reinitialization, as on stock drivers.
 * No register is written by this function. It does not configure CSI or clocks. */
int lp_cv610_build_registers(struct lp_cv610_reg_cache *cache, unsigned fps,
                            int bus, float gain, uint32_t lines,
                            ot_isp_sns_regs_info *output);
#endif
