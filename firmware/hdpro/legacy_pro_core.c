#include "legacy_pro_core.h"
/* The donor imports log10 already. Its target calling convention still has to
 * be bound by the CV610 adapter; the independent core is built softfp below. */
extern double log10(double);
#include "legacy_pro_programs.inc"

const struct lp_mode *lp_get_mode(unsigned fps)
{
    size_t i;
    for (i=0; i<sizeof(lp_modes)/sizeof(lp_modes[0]); ++i)
        if (lp_modes[i].fps==fps) return &lp_modes[i];
    return 0;
}

int lp_encode_controls(float gain, uint32_t lines, uint32_t vmax,
                       struct lp_write output[7])
{
    uint32_t code, shutter;
    double value;
    if (!output || vmax<4 || vmax>65535) return LP_EINVAL;
    /* Reject NaN/infinity before a floating-to-integer conversion. */
    if (!(gain>=-3.402823466e38F && gain<=3.402823466e38F)) return LP_EINVAL;
    if (gain<1.0F) gain=1.0F;
    if (gain>3981.0F) gain=3981.0F;
    value=log10((double)gain)*200.0;
    code=(uint32_t)value;
    if (code>=720) code=720;
    if (lines<=1) lines=2;
    else if (lines>=vmax-2) lines=vmax-2;
    shutter=vmax-1-lines;
    output[0]=(struct lp_write){0x3001,1,0};
    output[1]=(struct lp_write){0x3014,(uint8_t)code,0};
    output[2]=(struct lp_write){0x3015,(uint8_t)(code>>8),0};
    output[3]=(struct lp_write){0x3020,(uint8_t)shutter,0};
    output[4]=(struct lp_write){0x3021,(uint8_t)(shutter>>8),0};
    output[5]=(struct lp_write){0x3022,0,0};
    output[6]=(struct lp_write){0x3001,0,0};
    return LP_OK;
}

static int valid(const struct lp_device *d)
{
    return d && d->transport.write && d->transport.delay_us;
}

static int emit(struct lp_device *d, const struct lp_write *w)
{
    uint8_t wire[3]={(uint8_t)(w->address>>8),(uint8_t)w->address,w->value};
    int result=d->transport.write(d->transport.context,0x1a,wire,sizeof(wire));
    d->transport_result=result;
    if (result!=(int)sizeof(wire)) { d->state=LP_FAULT; return LP_EIO; }
    if (w->delay_us) {
        result=d->transport.delay_us(d->transport.context,w->delay_us);
        d->transport_result=result;
        if (result) { d->state=LP_FAULT; return LP_EIO; }
    }
    return LP_OK;
}

int lp_configure(struct lp_device *d, unsigned fps)
{
    size_t i;
    const struct lp_mode *mode=lp_get_mode(fps);
    if (!valid(d) || !mode) return LP_EINVAL;
    /* No claim of unchanged hardware after a partially completed transaction. */
    d->state=LP_FAULT;
    d->mode=0;
    for (i=0; i<mode->program_count; ++i)
        if (emit(d,&mode->program[i])!=LP_OK) return LP_EIO;
    d->mode=mode;
    /* The program leaves 0x3000 in standby. Start is a separate write. */
    d->state=LP_STANDBY;
    return LP_OK;
}

int lp_start(struct lp_device *d)
{
    const struct lp_write w={0x3000,0,0};
    if (!valid(d)) return LP_EINVAL;
    if (!d->mode || d->state!=LP_STANDBY) return LP_ESTATE;
    if (emit(d,&w)!=LP_OK) return LP_EIO;
    /* Started means the sensor start write completed, never observed frames. */
    d->state=LP_STARTED;
    return LP_OK;
}

int lp_stop(struct lp_device *d)
{
    const struct lp_write w={0x3000,1,0};
    if (!valid(d)) return LP_EINVAL;
    if (!d->mode || (d->state!=LP_STANDBY && d->state!=LP_STARTED)) return LP_ESTATE;
    if (emit(d,&w)!=LP_OK) return LP_EIO;
    d->state=LP_STANDBY;
    return LP_OK;
}

int lp_set_controls(struct lp_device *d, float gain, uint32_t lines)
{
    struct lp_write program[7];
    size_t i;
    if (!valid(d)) return LP_EINVAL;
    if (!d->mode || (d->state!=LP_STANDBY && d->state!=LP_STARTED)) return LP_ESTATE;
    if (lp_encode_controls(gain,lines,d->mode->vmax,program)!=LP_OK) return LP_EINVAL;
    for (i=0; i<7; ++i)
        if (emit(d,&program[i])!=LP_OK) return LP_EIO;
    return LP_OK;
}
