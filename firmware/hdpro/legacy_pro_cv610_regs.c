#include "legacy_pro_cv610_regs.h"
#include <stddef.h>

/* Public interface layouts are independently checked against B051 stock-driver
 * construction/output, not accepted merely because a header compiles. */
_Static_assert(sizeof(ot_isp_sns_regs_info)==1664,"CV610 register ABI changed");
_Static_assert(sizeof(ot_isp_i2c_data)==24,"CV610 I2C ABI changed");
_Static_assert(offsetof(ot_isp_sns_regs_info,i2c_data)==28,"CV610 register offset changed");
_Static_assert(offsetof(ot_isp_sns_regs_info,config)==1660,"CV610 config offset changed");

int lp_cv610_build_registers(struct lp_cv610_reg_cache *cache, unsigned fps,
                            int bus, float gain, uint32_t lines,
                            ot_isp_sns_regs_info *output)
{
    const struct lp_mode *mode=lp_get_mode(fps);
    struct lp_write request[7];
    size_t i;
    int dirty;
    volatile unsigned char *bytes;
    if (!cache || !output || !mode || bus<0 || bus>127) return LP_EINVAL;
    if (lp_encode_controls(gain,lines,mode->vmax,request)!=LP_OK) return LP_EINVAL;
    dirty=!cache->has_emitted || !output->config || cache->fps!=fps || cache->bus!=bus;
    if (cache->has_emitted)
        for (i=0;i<7;++i)
            if (cache->last_emitted[i].address!=request[i].address ||
                cache->last_emitted[i].value!=request[i].value) dirty=1;
    bytes=(volatile unsigned char *)output;
    for (i=0;i<sizeof(*output);++i) bytes[i]=0;
    output->sns_type=OT_ISP_SNS_TYPE_I2C;
    output->reg_num=7;
    /* These timing parameters remain hardware-unqualified. Zero per-register
     * delay keeps all bytes and group release in the same scheduler batch. */
    output->cfg2_valid_delay_max=2;
    output->com_bus.i2c_dev=(td_s8)bus;
    for (i=0;i<7;++i) {
        output->i2c_data[i].update=dirty?TD_TRUE:TD_FALSE;
        output->i2c_data[i].dev_addr=0x34; /* SDK uses 8-bit address; wire uses 0x1a. */
        output->i2c_data[i].reg_addr=request[i].address;
        output->i2c_data[i].addr_byte_num=2;
        output->i2c_data[i].data=request[i].value;
        output->i2c_data[i].data_byte_num=1;
        cache->last_emitted[i]=request[i];
    }
    /* Published is narrower than applied: there is no hardware acknowledgement. */
    output->config=TD_FALSE;
    cache->fps=fps;
    cache->bus=bus;
    cache->has_emitted=1;
    return LP_OK;
}
