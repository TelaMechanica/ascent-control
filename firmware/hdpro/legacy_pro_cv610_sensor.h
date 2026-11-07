#ifndef ASCENT_LEGACY_PRO_CV610_SENSOR_H
#define ASCENT_LEGACY_PRO_CV610_SENSOR_H
#include "ot_sns_ctrl.h"
/* B051 sensor object. Numeric SDK ID is an internal registration identifier;
 * it is not an independently read chip ID or a physical-sensor assertion. */
#define LP_CV610_SENSOR_ID 385
extern ot_isp_sns_obj g_sns_legacy_pro_obj;
int lp_cv610_last_error(ot_vi_pipe pipe);
/* Board clock/CSI admission and image integration remain separate obligations. */
#endif
