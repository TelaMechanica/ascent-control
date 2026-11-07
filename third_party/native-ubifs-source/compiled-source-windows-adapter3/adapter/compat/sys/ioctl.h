/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASCENT_IOCTL_H
#define ASCENT_IOCTL_H
#include <errno.h>
static int ioctl(int fd, unsigned long op, ...){(void)fd;(void)op;errno=ENOTSUP;return -1;}
#define _IO(a,b) 0
#define _IOR(a,b,c) 0
#define _IOW(a,b,c) 0
#define _IOWR(a,b,c) 0
#endif
