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


#ifndef _EYEDBSM_XM_MALLOC_H
#define _EYEDBSM_XM_MALLOC_H

namespace eyedbsm {

  typedef struct XMMap XMMap;

  struct XMHandle {
    XMMap *map;
    struct Mutex *mp;
    int fd;
    void *x;
  };

  typedef unsigned int XMOffset;

  extern XMHandle *XMCreate(char *, unsigned int, void *);
  extern XMHandle *XMOpen(char *, void *x);
  extern void XMInit(XMHandle *);
  extern void XMClose(XMHandle *);

  extern void  *XMAlloc(XMHandle *, unsigned int);
  extern void  *XMAllocZero(XMHandle *, unsigned int);
  extern void  *XMRealloc(XMHandle *, void *, unsigned int);
  extern int   XMFree(XMHandle *, void *);

  extern int   XMGetSize(XMHandle *, void *);
  extern void  XMShowMemory(XMHandle *);
  extern int   XMCheckMemory(XMHandle *);
  extern void  XMGetInfo(XMHandle *, int *, int *, int *, int *);
  extern void  XMLock(XMHandle *);
  extern void  XMUnlock(XMHandle *);

#define XM_ADDR_(MAP, OFFSET) \
        ((OFFSET) ? ((char *)(MAP) + (OFFSET)) : (char *)0)

#define XM_OFFSET_(MAP, ADDR) \
	((eyedbsm::XMOffset)((ADDR) ? ((char *)(ADDR) - (char *)(MAP)) : 0))

#define XM_ADDR(XMH, OFFSET) XM_ADDR_((XMH)->map, OFFSET)

#define XM_OFFSET(XMH, ADDR) XM_OFFSET_((XMH)->map, ADDR)

#define XM_NULLOFFSET ((eyedbsm::XMOffset)0)

}

#endif
