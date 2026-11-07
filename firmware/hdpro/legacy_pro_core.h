#ifndef ASCENT_LEGACY_PRO_CORE_H
#define ASCENT_LEGACY_PRO_CORE_H
#include <stddef.h>
#include <stdint.h>

/* Offline port component, not an admitted firmware image or qualified camera.
 * Transport callbacks must be supplied by a separately reviewed CV610 adapter.
 * This module never opens a device or selects a board's bus/GPIO/CSI wiring. */
enum lp_state { LP_UNCONFIGURED, LP_STANDBY, LP_STARTED, LP_FAULT };
enum lp_error { LP_OK=0, LP_EINVAL=-1, LP_ESTATE=-2, LP_EIO=-3 };
struct lp_write { uint16_t address; uint8_t value; uint32_t delay_us; };
struct lp_mode {
    uint16_t fps, width, height, sensor_width, sensor_height;
    uint16_t crop_x, crop_y, hmax, vmax;
    const struct lp_write *program;
    size_t program_count;
};
struct lp_transport {
    /* Return exactly count on a complete write; partial writes are errors. */
    int (*write)(void *context, uint8_t slave7, const uint8_t *bytes, size_t count);
    /* Return zero after the requested delay, nonzero on failure. */
    int (*delay_us)(void *context, uint32_t microseconds);
    void *context;
};
struct lp_device {
    struct lp_transport transport;
    const struct lp_mode *mode;
    enum lp_state state;
    int transport_result;
};
const struct lp_mode *lp_get_mode(unsigned fps);
/* Pure encoding: finite gain is clamped as Avatar does; invalid floats refuse.
 * Exposure is in lines. These are sensor register controls, not ISP gain units. */
int lp_encode_controls(float linear_gain, uint32_t exposure_lines, uint32_t vmax,
                       struct lp_write output[7]);
int lp_configure(struct lp_device *device, unsigned fps);
int lp_start(struct lp_device *device);
int lp_stop(struct lp_device *device);
int lp_set_controls(struct lp_device *device, float gain, uint32_t exposure_lines);
#endif
