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

#include <sys/types.h>
#include <iostream>
#include <eyedblib/m_mem.h>

/*
#define USE_MMAP_TRACK_BUG
#define USE_MMAP_SYNC

// WARNING: flag may be safer to be kept
//#define USE_MMAP_NO_CLOSE_FD

// choose only one of the following
#define USE_MMAP_FTRUNCATE
//#define USE_MMAP_TRUNCATE
//#define USE_MMAP_UNMAP_REMAP

//#define MMAP_SYNC_FLAGS (MS_SYNC|MS_INVALIDATE)

//#define USE_MMAP_CHECK
*/

extern unsigned int m_mmap_flags;

#define MMAP_MMAP_FLAGS (MAP_SHARED|MAP_NORESERVE)
#define MMAP_SYNC_FLAGS (MS_SYNC)

