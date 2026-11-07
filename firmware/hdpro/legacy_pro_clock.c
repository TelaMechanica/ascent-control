#include "legacy_pro_clock.h"
#include <stddef.h>

extern int open(const char *, int, ...);
extern int close(int);
/* Donor mmap uses a 64-bit, AAPCS-aligned offset (verified at 0x65952..962).
 * Do not substitute a host off_t whose width depends on the build machine. */
extern void *mmap(void *, size_t, int, int, int, int64_t);
extern int munmap(void *, size_t);

uint32_t lp_cv610_clock_value(uint32_t previous)
{
    /* Stock detection changes only bits12..15. Public CV610 clock source
     * assigns selector8 to37.125MHz. Preserve every reset/enable/other bit. */
    return (previous & ~UINT32_C(0xf000)) | UINT32_C(0x8000);
}

int lp_cv610_prepare_clock(void)
{
    const size_t length = 0x10000;
    int fd = open("/dev/mem", 2);
    if (fd < 0) return -1;
    void *mapping = mmap(NULL, length, 3, 1, fd, INT64_C(0x11010000));
    if (mapping == (void *)(uintptr_t)UINT32_MAX || mapping == NULL) {
        (void)close(fd);
        return -1;
    }
    volatile uint32_t *clock = (volatile uint32_t *)((uintptr_t)mapping + 0x8440);
    uint32_t wanted = lp_cv610_clock_value(*clock);
    *clock = wanted;
    __asm__ volatile("dsb sy" ::: "memory");
    /* Readback checks the selector, not the physical frequency or settling. */
    int result = ((*clock & UINT32_C(0xf000)) == UINT32_C(0x8000)) ? 0 : -1;
    if (munmap(mapping, length) != 0) result = -1;
    if (close(fd) != 0) result = -1;
    return result;
}
