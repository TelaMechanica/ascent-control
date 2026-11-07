#ifndef ASCENT_LEGACY_PRO_CLOCK_H
#define ASCENT_LEGACY_PRO_CLOCK_H
#include <stdint.h>
/* Candidate CV610 sensor0 frequency selection. This does not establish board
 * wiring or qualify the clock. Reset/enable remain owned by the stock driver. */
uint32_t lp_cv610_clock_value(uint32_t previous);
/* Explicitly called by experimental startup, never at object construction.
 * Returns zero only after mapping, readback and cleanup all succeed. */
int lp_cv610_prepare_clock(void);
#endif
