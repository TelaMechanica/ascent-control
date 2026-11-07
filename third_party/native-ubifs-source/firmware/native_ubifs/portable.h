/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASCENT_PORTABLE_H
#define ASCENT_PORTABLE_H
#ifndef VERSION
#define VERSION "2.2.0"
#endif
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
typedef long long loff_t;
#ifndef S_IFLNK
#define S_IFLNK 0120000
#define S_ISLNK(m) (((m)&0170000)==0120000)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m)&0170000)==0140000)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m) (((m)&0170000)==0060000)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m)&0170000)==0010000)
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef S_IRGRP
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#define S_IRWXU 0700
#endif
#ifndef st_atim
/* Actual output metadata is taken directly from JSON, not this native stat. */
#endif
static wchar_t *ascent_wide(const char *s){int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,NULL,0);if(!n){errno=EINVAL;return NULL;}wchar_t *p=malloc(n*sizeof(*p));if(!p)return NULL;if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,p,n)){free(p);return NULL;}return p;}
static int ascent_open(const char *path,int flags,...){int mode=0600;if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);}wchar_t *p=ascent_wide(path);if(!p)return -1;int fd=_wopen(p,flags|O_BINARY,mode);free(p);return fd;}
static FILE *ascent_fopen(const char *path,const char *mode){wchar_t *p=ascent_wide(path),*m=ascent_wide(mode);if(!p||!m){free(p);free(m);return NULL;}FILE *f=_wfopen(p,m);free(p);free(m);return f;}
static int ascent_stat(const char *path,struct stat *s){wchar_t *p=ascent_wide(path);if(!p)return -1;struct _stat64 st;int result=_wstat64(p,&st);free(p);if(result)return result;memset(s,0,sizeof(*s));s->st_mode=st.st_mode;s->st_size=st.st_size;s->st_nlink=st.st_nlink;s->st_mtime=st.st_mtime;s->st_atime=st.st_atime;s->st_ctime=st.st_ctime;return 0;}
static char *ascent_realpath(const char *path,char *resolved){wchar_t *p=ascent_wide(path);if(!p)return NULL;wchar_t *r=_wfullpath(NULL,p,0);free(p);if(!r)return NULL;int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,r,-1,NULL,0,NULL,NULL);if(!n){free(r);return NULL;}if(resolved&&n>PATH_MAX){free(r);errno=ENAMETOOLONG;return NULL;}char *out=resolved?resolved:malloc(n);if(!out){free(r);return NULL;}WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,r,-1,out,n,NULL,NULL);free(r);return out;}
static ssize_t getline(char **line,size_t *capacity,FILE *f){if(!line||!capacity){errno=EINVAL;return -1;}if(!*line||!*capacity){*capacity=256;*line=malloc(*capacity);if(!*line)return -1;}size_t n=0;int ch;while((ch=fgetc(f))!=EOF){if(n+1>=*capacity){if(*capacity>16*1024*1024){errno=EOVERFLOW;return -1;}char *p=realloc(*line,*capacity*2);if(!p)return -1;*line=p;*capacity*=2;}(*line)[n++]=ch;if(ch=='\n')break;}if(!n&&ch==EOF)return -1;(*line)[n]=0;return n;}
static ssize_t ascent_pread(int fd,void *buf,size_t count,off_t at){if(count>INT_MAX){errno=EINVAL;return -1;}__int64 saved=_lseeki64(fd,0,SEEK_CUR);if(saved<0||_lseeki64(fd,at,SEEK_SET)<0)return -1;ssize_t n=_read(fd,buf,(unsigned)count);int saved_errno=errno;if(_lseeki64(fd,saved,SEEK_SET)<0)return -1;errno=saved_errno;return n;}
static ssize_t ascent_pwrite(int fd,const void *buf,size_t count,off_t at){if(count>INT_MAX){errno=EINVAL;return -1;}__int64 saved=_lseeki64(fd,0,SEEK_CUR);if(saved<0||_lseeki64(fd,at,SEEK_SET)<0)return -1;ssize_t n=_write(fd,buf,(unsigned)count);int saved_errno=errno;if(_lseeki64(fd,saved,SEEK_SET)<0)return -1;errno=saved_errno;return n;}
static int ascent_dirfd(DIR *dir){(void)dir;errno=ENOTSUP;return -1;}
#define pread ascent_pread
#define pwrite ascent_pwrite
#define dirfd ascent_dirfd
static int ascent_readlink(const char *p,char *b,size_t s){(void)p;(void)b;(void)s;errno=ENOTSUP;return -1;}
#define open ascent_open
#define fopen ascent_fopen
#undef stat
#define stat(p,s) ascent_stat(p,s)
#define lstat(p,s) ascent_stat(p,s)
#define realpath ascent_realpath
#define readlink ascent_readlink
#undef lseek
#define lseek _lseeki64
#else
#include <uuid/uuid.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#endif
