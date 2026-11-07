#include "legacy_pro_cv610_sensor.h"
#include "legacy_pro_cv610_regs.h"
#include "legacy_pro_linux_io.h"
#include "ot_common_ae.h"
#include "ot_common_awb.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

/* No MPI implementation is copied. These declarations match the checked SDK
 * interfaces and the stock B051 entrypoints used by the existing drivers. */
extern td_s32 ot_mpi_isp_sensor_reg_callback(ot_vi_pipe,const ot_isp_sns_attr_info *,const ot_isp_sns_register *);
extern td_s32 ot_mpi_isp_sensor_unreg_callback(ot_vi_pipe,ot_sensor_id);
extern td_s32 ot_mpi_ae_sensor_reg_callback(ot_vi_pipe,const ot_isp_3a_alg_lib *,const ot_isp_sns_attr_info *,const ot_isp_ae_sensor_register *);
extern td_s32 ot_mpi_ae_sensor_unreg_callback(ot_vi_pipe,const ot_isp_3a_alg_lib *,ot_sensor_id);
extern td_s32 ot_mpi_awb_sensor_reg_callback(ot_vi_pipe,const ot_isp_3a_alg_lib *,const ot_isp_sns_attr_info *,const ot_isp_awb_sensor_register *);
extern td_s32 ot_mpi_awb_sensor_unreg_callback(ot_vi_pipe,const ot_isp_3a_alg_lib *,ot_sensor_id);

_Static_assert(sizeof(void *)==4,"CV610 target must use 32-bit pointers");
_Static_assert(sizeof(ot_isp_sns_obj)==48,"B051 object ABI");
_Static_assert(sizeof(ot_isp_sns_register)==48,"B051 ISP callback ABI");
_Static_assert(sizeof(ot_isp_ae_sensor_register)==56,"B051 AE callback ABI");
_Static_assert(sizeof(ot_isp_awb_sensor_register)==4,"B051 AWB callback ABI");
_Static_assert(sizeof(ot_isp_ae_sensor_default)==3680,"B051 AE defaults ABI");
_Static_assert(sizeof(ot_isp_awb_sensor_default)==408,"B051 AWB defaults ABI");
_Static_assert(sizeof(ot_isp_cmos_default)==344,"B051 ISP defaults ABI");
_Static_assert(sizeof(ot_isp_cmos_black_level)==216,"B051 black-level ABI");

struct context {
    struct lp_device core;
    struct lp_cv610_reg_cache cache;
    atomic_uint fps,lines,gain_code;
    atomic_int error;
    atomic_flag control_guard;
    int bus,bus_set,registered;
};
static struct context contexts[4];
#include "legacy_pro_gain_q10.inc"
static void zero(void *ptr,size_t count)
{
    volatile unsigned char *p=(volatile unsigned char *)ptr;
    size_t i;for(i=0;i<count;++i)p[i]=0;
}
static struct context *get(ot_vi_pipe pipe) { return pipe>=0 && pipe<4?&contexts[pipe]:0; }
static int writer(void *opaque,uint8_t slave,const uint8_t *bytes,size_t count)
{
    struct context *c=(struct context *)opaque;
    return lp_linux_write((unsigned)(c-contexts),c->bus,slave,bytes,count);
}
static int delay(void *opaque,uint32_t us) { (void)opaque;return lp_linux_delay(us); }
int lp_cv610_last_error(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);return c?atomic_load(&c->error):LP_EINVAL;
}
static void global_init(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);
    if (!c)return;
    if (c->core.state==LP_STARTED) { atomic_store(&c->error,LP_ESTATE);return; }
    zero(&c->cache,sizeof(c->cache));
    c->core.mode=0;c->core.state=LP_UNCONFIGURED;c->core.transport_result=0;
    c->core.transport=(struct lp_transport){writer,delay,c};
    atomic_store(&c->fps,60);atomic_store(&c->lines,1122);atomic_store(&c->gain_code,0);
    atomic_store(&c->error,0);atomic_flag_clear(&c->control_guard);
}
static void sensor_init(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);int r;
    if(!c)return;
    /* An SDK callback repetition is not authorization to retry a partial
     * transaction or reprogram a running sensor. Explicit global init after
     * exit owns a fresh attempt. Keep the original error until then. */
    if(atomic_load(&c->error))return;
    if(c->core.state!=LP_UNCONFIGURED){atomic_store(&c->error,LP_ESTATE);return;}
    if(!c->bus_set || c->bus<0){atomic_store(&c->error,LP_ESTATE);return;}
    r=lp_configure(&c->core,atomic_load(&c->fps));
    if(!r)r=lp_start(&c->core);
    atomic_store(&c->error,r);
}
static void sensor_exit(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);int r,stopped,closed;
    if(!c)return;
    r=atomic_load(&c->error);
    if(c->core.state==LP_FAULT && !r)r=LP_EIO;
    if(c->core.state==LP_STARTED || c->core.state==LP_STANDBY){stopped=lp_stop(&c->core);if(!r)r=stopped;}
    closed=lp_linux_close((unsigned)pipe);
    if(!r && closed)r=LP_EIO;
    c->core.mode=0;c->core.state=r?LP_FAULT:LP_UNCONFIGURED;
    atomic_store(&c->error,r);c->cache.has_emitted=0;
}
static td_s32 image_mode(ot_vi_pipe pipe,const ot_isp_cmos_sns_image_mode *mode)
{
    struct context *c=get(pipe);unsigned fps;
    if(!c || !mode || mode->width!=1920 || mode->height!=1080)return TD_FAILURE;
    if(mode->fps==60.0F)fps=60;else if(mode->fps==100.0F)fps=100;else return TD_FAILURE;
    if(c->core.state==LP_STARTED && atomic_load(&c->fps)!=fps)return TD_FAILURE;
    if(atomic_load(&c->fps)!=fps)c->cache.has_emitted=0;
    atomic_store(&c->fps,fps);return TD_SUCCESS;
}
static td_s32 wdr_mode(ot_vi_pipe pipe,td_u8 mode)
{
    return get(pipe) && mode==OT_WDR_MODE_NONE?TD_SUCCESS:TD_FAILURE;
}
static td_s32 isp_default(ot_vi_pipe pipe,ot_isp_cmos_default *output)
{
    if(!get(pipe) || !output)return TD_FAILURE;
    zero(output,sizeof(*output));
    /* Diagnostic baseline only: ISP algorithm seeds remain SDK defaults.
     * No unrelated sensor's calibration is presented as HD Pro calibration. */
    output->sns_max_resolution.max_width=1920;output->sns_max_resolution.max_height=1080;
    output->sns_mode.sns_id=LP_CV610_SENSOR_ID;output->sns_mode.sns_mode=0;
    return TD_SUCCESS;
}
static td_s32 black_level(ot_vi_pipe pipe,ot_isp_cmos_black_level *output)
{
    unsigned i,j;
    if(!get(pipe) || !output)return TD_FAILURE;
    zero(output,sizeof(*output));
    /* Programmed black level60 in a provisional RAW10 profile, normalized to
     * the SDK's14-bit domain. Physical level/RAW format still require bench. */
    output->user_black_level_en=TD_TRUE;
    for(i=0;i<OT_ISP_WDR_MAX_FRAME_NUM;++i)
        for(j=0;j<OT_ISP_BAYER_CHN_NUM;++j)output->user_black_level[i][j]=960;
    return TD_SUCCESS;
}
static td_s32 clamp_info(ot_vi_pipe pipe,td_bool *enabled)
{
    if(!get(pipe) || !enabled)return TD_FAILURE;
    *enabled=TD_TRUE;return TD_SUCCESS;
}
static td_s32 registers(ot_vi_pipe pipe,ot_isp_sns_regs_info *output)
{
    struct context *c=get(pipe);int result;unsigned gain;
    if(!c || !output || c->bus<0 || atomic_load(&c->error))return TD_FAILURE;
    if(atomic_flag_test_and_set_explicit(&c->control_guard,memory_order_acquire))return TD_FAILURE;
    gain=atomic_load(&c->gain_code);
    result=lp_cv610_build_registers(&c->cache,atomic_load(&c->fps),c->bus,
                                  (float)lp_gain_q10[gain]/1024.0F,
                                  atomic_load(&c->lines),output);
    atomic_flag_clear_explicit(&c->control_guard,memory_order_release);
    return result?TD_FAILURE:TD_SUCCESS;
}
static void pixel_detect(ot_vi_pipe pipe,td_bool enabled)
{
    struct context *c=get(pipe);
    /* Calibration is not silently emulated. Disabling an inactive calibration
     * is harmless; enabling this unsupported path makes the error observable. */
    if(c && enabled)atomic_store(&c->error,LP_EINVAL);
}
static td_s32 ae_default(ot_vi_pipe pipe,ot_isp_ae_sensor_default *out)
{
    struct context *c=get(pipe);unsigned fps;
    if(!c || !out)return TD_FAILURE;
    fps=atomic_load(&c->fps);zero(out,sizeof(*out));
    out->fps=(float)fps;out->full_lines_std=1125;out->full_lines_max=1125;out->full_lines=1125;
    out->lines_per500ms=1125*fps/2;out->hmax_times=1000000000U/(1125*fps);
    out->init_int_time=1122;out->init_again=1024;out->init_dgain=1024;out->init_isp_dgain=256;
    out->max_int_time=1123;out->min_int_time=2;out->max_int_time_target=1123;out->min_int_time_target=2;
    out->int_time_accu.accu_type=OT_ISP_AE_ACCURACY_LINEAR;out->int_time_accu.accuracy=1;
    out->min_again=1024;out->max_again=lp_gain_q10[719];
    out->min_again_target=out->min_again;out->max_again_target=out->max_again;
    out->again_accu.accu_type=OT_ISP_AE_ACCURACY_TABLE;out->again_accu.accuracy=1;
    out->min_dgain=1024;out->max_dgain=1024;out->min_dgain_target=1024;out->max_dgain_target=1024;
    out->dgain_accu.accu_type=OT_ISP_AE_ACCURACY_TABLE;out->dgain_accu.accuracy=1;
    out->isp_dgain_shift=8;out->min_isp_dgain_target=256;out->max_isp_dgain_target=256;
    out->ae_compensation=0x38;out->ae_run_interval=1;
    return TD_SUCCESS;
}
static void fps_set(ot_vi_pipe pipe,td_float fps,ot_isp_ae_sensor_default *out)
{
    struct context *c=get(pipe);
    if(!c)return;
    if(fps!=(float)atomic_load(&c->fps) || !out){atomic_store(&c->error,LP_EINVAL);return;}
    (void)ae_default(pipe,out);
}
static void slow_frame(ot_vi_pipe pipe,td_u32 lines,ot_isp_ae_sensor_default *out)
{
    struct context *c=get(pipe);
    if(!c)return;
    if(lines!=1125 || !out){atomic_store(&c->error,LP_EINVAL);return;}
    (void)ae_default(pipe,out);
}
static void exposure(ot_vi_pipe pipe,td_u32 lines)
{
    struct context *c=get(pipe);if(!c)return;
    if(lines<2)lines=2;
    if(lines>1123)lines=1123;
    atomic_store(&c->lines,lines);
}
static void gain_update(ot_vi_pipe pipe,td_u32 again,td_u32 dgain)
{
    struct context *c=get(pipe);if(!c)return;
    if(again>719 || dgain!=0){atomic_store(&c->error,LP_EINVAL);return;}
    atomic_store(&c->gain_code,again);
}
static void again_table(ot_vi_pipe pipe,td_u32 *linear,td_u32 *code)
{
    unsigned lo=0,hi=719,mid;
    if(!get(pipe) || !linear || !code)return;
    while(lo<hi){mid=(lo+hi+1)/2;if(lp_gain_q10[mid]<=*linear)lo=mid;else hi=mid-1;}
    *linear=lp_gain_q10[lo];*code=lo;
}
static void dgain_table(ot_vi_pipe pipe,td_u32 *linear,td_u32 *code)
{
    if(!get(pipe) || !linear || !code)return;
    *linear=1024;*code=0;
}
static void exposure_range(ot_vi_pipe pipe,td_u16 manual,td_u32 *ratio,
                           ot_isp_ae_int_time_range *range,td_u32 *longest)
{
    (void)manual;(void)ratio;
    if(!get(pipe) || !range || !longest)return;
    zero(range,sizeof(*range));range->int_time_min[0]=2;range->int_time_max[0]=1123;*longest=1123;
}
static void fswdr(ot_vi_pipe pipe,ot_isp_ae_fswdr_attr *attr)
{
    struct context *c=get(pipe);
    if(c && (!attr || attr->fswdr_mode!=0))atomic_store(&c->error,LP_EINVAL);
}
static td_s32 awb_default(ot_vi_pipe pipe,ot_isp_awb_sensor_default *out)
{
    unsigned i,j;
    static const td_s32 curve[6]={-37,293,0,179537,128,-123691};
    if(!get(pipe) || !out)return TD_FAILURE;
    zero(out,sizeof(*out));
    /* Provisional reference-family AWB curve, not owned-camera calibration.
     * Curve/offset facts checked against pinned OpenIPC IMX385 reference. */
    out->wb_ref_temp=4900;out->gain_offset[0]=0x1c3;out->gain_offset[1]=256;
    out->gain_offset[2]=256;out->gain_offset[3]=0x1d4;
    for(i=0;i<6;++i)out->wb_para[i]=curve[i];
    out->agc_tbl.valid=TD_TRUE;
    for(i=0;i<OT_ISP_AUTO_ISO_NUM;++i)out->agc_tbl.saturation[i]=0x80;
    /* Neutral matrices avoid representing another module's fitted CCM as this
     * module's calibration. Color quality is explicitly not qualified. */
    out->ccm.ccm_tab_num=3;
    for(i=0;i<3;++i){out->ccm.ccm_tab[i].color_temp=(td_u16)(i==0?4900:i==1?3770:2640);
        for(j=0;j<9;++j)out->ccm.ccm_tab[i].ccm[j]=(j==0 || j==4 || j==8)?256:0;}
    out->awb_run_interval=2;return TD_SUCCESS;
}
static td_s32 bus_info(ot_vi_pipe pipe,ot_isp_sns_commbus bus)
{
    struct context *c=get(pipe);
    if(!c || bus.i2c_dev<0 || c->core.state==LP_STARTED)return TD_FAILURE;
    if(c->bus!=bus.i2c_dev && lp_linux_close((unsigned)pipe))return TD_FAILURE;
    c->bus=bus.i2c_dev;c->bus_set=1;c->cache.has_emitted=0;return TD_SUCCESS;
}
static void standby(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);if(c)atomic_store(&c->error,lp_stop(&c->core));
}
static void restart(ot_vi_pipe pipe)
{
    struct context *c=get(pipe);if(c)atomic_store(&c->error,lp_start(&c->core));
}
static td_s32 write_reg(ot_vi_pipe pipe,td_u32 address,td_u32 value)
{
    struct context *c=get(pipe);uint8_t bytes[3];int r;
    if(!c || !c->bus_set || c->bus<0 || atomic_load(&c->error) || address>65535 || value>255)return TD_FAILURE;
    bytes[0]=(uint8_t)(address>>8);bytes[1]=(uint8_t)address;bytes[2]=(uint8_t)value;
    r=lp_linux_write((unsigned)pipe,c->bus,0x1a,bytes,3);
    if(r!=3){atomic_store(&c->error,LP_EIO);return TD_FAILURE;}return TD_SUCCESS;
}
static td_s32 read_reg(ot_vi_pipe pipe,td_u32 address)
{
    struct context *c=get(pipe);if(!c || !c->bus_set || c->bus<0 || address>65535)return TD_FAILURE;
    return lp_linux_read((unsigned)pipe,c->bus,(uint16_t)address);
}
static td_s32 register_callbacks(ot_vi_pipe pipe,ot_isp_3a_alg_lib *ae,ot_isp_3a_alg_lib *awb)
{
    struct context *c=get(pipe);ot_isp_sns_register isp;ot_isp_ae_sensor_register ar;
    ot_isp_awb_sensor_register wr;ot_isp_sns_attr_info attr={LP_CV610_SENSOR_ID};int r;
    if(!c || !ae || !awb || c->registered)return TD_FAILURE;
    if(!c->bus_set)c->bus=-1;
    global_init(pipe);zero(&isp,sizeof(isp));zero(&ar,sizeof(ar));zero(&wr,sizeof(wr));
    isp.sns_exp.pfn_cmos_sns_init=sensor_init;isp.sns_exp.pfn_cmos_sns_exit=sensor_exit;
    isp.sns_exp.pfn_cmos_sns_global_init=global_init;isp.sns_exp.pfn_cmos_set_image_mode=image_mode;
    isp.sns_exp.pfn_cmos_set_wdr_mode=wdr_mode;isp.sns_exp.pfn_cmos_get_isp_default=isp_default;
    isp.sns_exp.pfn_cmos_get_isp_black_level=black_level;isp.sns_exp.pfn_cmos_get_blc_clamp_info=clamp_info;
    isp.sns_exp.pfn_cmos_get_sns_reg_info=registers;isp.sns_exp.pfn_cmos_set_pixel_detect=pixel_detect;
    ar.sns_exp.pfn_cmos_get_ae_default=ae_default;ar.sns_exp.pfn_cmos_fps_set=fps_set;
    ar.sns_exp.pfn_cmos_slow_framerate_set=slow_frame;ar.sns_exp.pfn_cmos_inttime_update=exposure;
    ar.sns_exp.pfn_cmos_gains_update=gain_update;ar.sns_exp.pfn_cmos_again_calc_table=again_table;
    ar.sns_exp.pfn_cmos_dgain_calc_table=dgain_table;ar.sns_exp.pfn_cmos_get_inttime_max=exposure_range;
    ar.sns_exp.pfn_cmos_ae_fswdr_attr_set=fswdr;wr.sns_exp.pfn_cmos_get_awb_default=awb_default;
    r=ot_mpi_isp_sensor_reg_callback(pipe,&attr,&isp);
    if(r){atomic_store(&c->error,r);return r;}
    c->registered=1;
    r=ot_mpi_ae_sensor_reg_callback(pipe,ae,&attr,&ar);
    if(r){
        if(!ot_mpi_isp_sensor_unreg_callback(pipe,LP_CV610_SENSOR_ID))c->registered=0;
        atomic_store(&c->error,r);return r;
    }
    c->registered|=2;
    r=ot_mpi_awb_sensor_reg_callback(pipe,awb,&attr,&wr);
    if(r){
        if(!ot_mpi_ae_sensor_unreg_callback(pipe,ae,LP_CV610_SENSOR_ID))c->registered&=~2;
        if(!ot_mpi_isp_sensor_unreg_callback(pipe,LP_CV610_SENSOR_ID))c->registered&=~1;
        atomic_store(&c->error,r);return r;
    }
    c->registered|=4;return TD_SUCCESS;
}
static td_s32 unregister_callbacks(ot_vi_pipe pipe,ot_isp_3a_alg_lib *ae,ot_isp_3a_alg_lib *awb)
{
    struct context *c=get(pipe);
    if(!c || !ae || !awb || !c->registered)return TD_FAILURE;
    if((c->registered&4) && !ot_mpi_awb_sensor_unreg_callback(pipe,awb,LP_CV610_SENSOR_ID))c->registered&=~4;
    if((c->registered&2) && !ot_mpi_ae_sensor_unreg_callback(pipe,ae,LP_CV610_SENSOR_ID))c->registered&=~2;
    if((c->registered&1) && !ot_mpi_isp_sensor_unreg_callback(pipe,LP_CV610_SENSOR_ID))c->registered&=~1;
    if(c->registered){atomic_store(&c->error,LP_ESTATE);return TD_FAILURE;}
    sensor_exit(pipe);c->bus_set=0;
    return atomic_load(&c->error)?TD_FAILURE:TD_SUCCESS;
}

ot_isp_sns_obj g_sns_legacy_pro_obj={
    .pfn_register_callback=register_callbacks,.pfn_un_register_callback=unregister_callbacks,
    .pfn_set_bus_info=bus_info,.pfn_standby=standby,.pfn_restart=restart,
    .pfn_write_reg=write_reg,.pfn_read_reg=read_reg
};
