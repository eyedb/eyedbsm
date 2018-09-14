/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2008 SYSRA
   
   EyeDB is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   
   EyeDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA 
*/

/*
   Author: Eric Viara <viara@sysra.com>
*/


#ifndef _EYEDBLIB_M_MEM_H
#define _EYEDBLIB_M_MEM_H

#include <sys/types.h>
#include <iostream>
#include <vector>

enum m_MapFlags {
  M_LOCAL_FS_MODE = 0x1,
  M_NFS_FIX_FTRUNCATE_MODE = 0x2,
  M_NFS_FIX_TRUNCATE_MODE = 0x4,
  M_NFS_FIX_MUNMAP_REMAP_MODE = 0x8,
  M_NFS_FIX_NO_CLOSE_FD_MODE = 0x10,
  M_NFS_FIX_MEMCHECK_MODE = 0x20,
  M_VERBOSE_MODE = 0x1000
};

typedef struct m_Map m_Map;

extern m_Map *m_mmap(caddr_t addr, size_t len, int prot, int flags,
		     int fildes, off_t off, caddr_t *p, const char *file,
		     off_t startns, off_t endns, m_Map* map = NULL);

extern int m_munmap(m_Map *map, caddr_t addr, size_t len);

extern u_int m_data_margin_set(u_int data_margin);

extern void m_init(void);
extern void m_init_flags(unsigned int flags);
extern void m_access(m_Map *map);
extern void m_lock(m_Map *m);
extern void m_unlock(m_Map *m);
extern void m_gtrig_set(m_Map *m, void (*gtrig)(void *client_data), void *client_data);
  
extern void *m_malloc(size_t len);
extern void *m_calloc(size_t nelem, size_t elsize);
extern void *m_realloc(void *ptr, size_t size);
extern void m_free(void *ptr);

extern void m_abort(void);
extern void m_abort_msg(const char *fmt, ...);
extern void m_mmaps_garbage(void);
extern void m_maptrace(std::ostream &);

extern size_t m_get_totalsize();
extern size_t m_get_maxsize();
extern void m_set_maxsize(size_t);

extern void m_display();
extern void m_unmmap_all();

extern void m_munmap_for_remap(int fd, std::vector<m_Map*>& m_map_v);
extern m_Map* m_remap(const std::vector<m_Map*>& m_map_v);

#endif
