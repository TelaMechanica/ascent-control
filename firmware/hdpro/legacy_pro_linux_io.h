#ifndef ASCENT_LEGACY_PRO_LINUX_IO_H
#define ASCENT_LEGACY_PRO_LINUX_IO_H
#include <stddef.h>
#include <stdint.h>
int lp_linux_write(unsigned pipe, int bus, uint8_t slave7, const uint8_t *bytes, size_t count);
int lp_linux_read(unsigned pipe, int bus, uint16_t address);
int lp_linux_close(unsigned pipe);
int lp_linux_delay(uint32_t microseconds);
#endif
