/* SPDX-License-Identifier: GPL-2.0-only
 * ASCENT inventory adapter. Third-party mkfs retains its original notices. */
#ifndef ASCENT_INVENTORY_H
#define ASCENT_INVENTORY_H
struct ascent_entry {
 char *path,*type,*target,*content_file;
 unsigned long long mode,uid,gid,nlink,flags,size;
 long long atime,mtime,ctime;
 unsigned int ansec,mnsec,cnsec;
 int parent,visited;
};
static struct ascent_entry *ascent_entries, *ascent_active;
static size_t ascent_count;
#endif
