/* SPDX-License-Identifier: GPL-2.0-only */
#include <windows.h>
#include <bcrypt.h>
static void uuid_generate_random(unsigned char *out){if(BCryptGenRandom(NULL,out,16,BCRYPT_USE_SYSTEM_PREFERRED_RNG))abort();out[6]=(out[6]&15)|64;out[8]=(out[8]&63)|128;}
static void uuid_unparse_upper(const unsigned char *u,char *out){sprintf(out,"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]);}
