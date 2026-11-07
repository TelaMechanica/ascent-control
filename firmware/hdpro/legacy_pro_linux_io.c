#include "legacy_pro_linux_io.h"
/* Linux ARM EABI declarations; no bare-metal/newlib runtime is linked. */
extern int open(const char *, int, ...);
extern int close(int);
extern int ioctl(int, unsigned long, ...);
extern long write(int, const void *, unsigned long);
extern long read(int, void *, unsigned long);
extern int usleep(unsigned int);
static int lp_fd[4]={-1,-1,-1,-1};
static int lp_bus[4]={-1,-1,-1,-1};

static int acquire(unsigned pipe, int bus)
{
    char path[16]={'/','d','e','v','/','i','2','c','-',0};
    unsigned n=9;
    int fd;
    if (pipe>=4 || bus<0 || bus>127) return -1;
    if (lp_fd[pipe]>=0) return lp_bus[pipe]==bus?lp_fd[pipe]:-1;
    if (bus>=100) { path[n++]=(char)('0'+bus/100); path[n++]=(char)('0'+bus/10%10); }
    else if (bus>=10) path[n++]=(char)('0'+bus/10);
    path[n++]=(char)('0'+bus%10); path[n]=0;
    fd=open(path,2,0);
    if (fd<0) return -1;
    /* I2C_SLAVE_FORCE expects the 7-bit address, unlike the ISP descriptor. */
    if (ioctl(fd,0x0706UL,0x1a)<0) { (void)close(fd); return -1; }
    lp_fd[pipe]=fd; lp_bus[pipe]=bus;
    return fd;
}
int lp_linux_write(unsigned pipe, int bus, uint8_t slave7, const uint8_t *bytes, size_t count)
{
    int fd;
    if (slave7!=0x1a || !bytes || count!=3) return -1;
    fd=acquire(pipe,bus);
    return fd<0?-1:(int)write(fd,bytes,(unsigned long)count);
}
int lp_linux_read(unsigned pipe, int bus, uint16_t address)
{
    uint8_t bytes[2]={(uint8_t)(address>>8),(uint8_t)address};
    uint8_t value=0;
    int fd=acquire(pipe,bus);
    if (fd<0 || write(fd,bytes,2)!=2 || read(fd,&value,1)!=1) return -1;
    return value;
}
int lp_linux_close(unsigned pipe)
{
    int fd,result;
    if (pipe>=4) return -1;
    fd=lp_fd[pipe]; lp_fd[pipe]=-1; lp_bus[pipe]=-1;
    if (fd<0) return 0;
    result=close(fd);
    return result;
}
int lp_linux_delay(uint32_t microseconds) { return usleep(microseconds); }
