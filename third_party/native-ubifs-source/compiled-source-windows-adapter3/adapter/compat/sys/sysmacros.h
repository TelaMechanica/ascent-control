/* SPDX-License-Identifier: GPL-2.0-only */
#define major(x) (((x)>>8)&0xfff)
#define minor(x) ((x)&0xff)
#define makedev(x,y) (((x)<<8)|(y))
