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

extern size_t m_get_maxsize();
extern void m_set_maxsize(size_t);

#endif
