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


#ifndef _EYEDBLIB_STD_MALLOC_H
#define _EYEDBLIB_STD_MALLOC_H

typedef struct STDMap STDMap;

typedef struct STDHandle STDHandle;

typedef void (*STDAllocTrigger)(STDHandle *, void *, unsigned, void *);
typedef void (*STDFreeTrigger)(STDHandle *, void *, unsigned, void *);
typedef void (*STDReallocTrigger)(STDHandle *, void *, unsigned, unsigned, void *);

struct STDHandle {
  /* private */
  STDMap *map;
  unsigned int idx;
  int  trace;
  long user_ctx;
  int  stop_size;
  int  counter;
  int  stop_counter;
  STDAllocTrigger alloc_trig;
  void *alloc_user_data;
  STDFreeTrigger free_trig;
  void *free_user_data;
  STDReallocTrigger realloc_trig;
  void *realloc_user_data;
  int fd;
};

typedef unsigned int STDOffset;

extern STDHandle *STDCreate(char *, int);
extern STDHandle *STDOpen(char *);
extern void STDInit(STDHandle *);
extern void STDClose(STDHandle *);

extern void  *STDAlloc(STDHandle *, unsigned int);
extern void  *STDAllocZero(STDHandle *, unsigned int);
extern void  *STDRealloc(STDHandle *, void *, unsigned int);
extern int   STDFree(STDHandle *, void *);

extern int   STDGetSize(STDHandle *, void *);
extern void  STDShowMemory(STDHandle *);
extern int   STDCheckMemory(STDHandle *);
extern void  STDGetInfo(STDHandle *, int *, int *, int *, int *);
extern void  STDLock(STDMap *);
extern void  STDUnlock(STDMap *);
extern STDHandle *STDGetDefaultHandle();

extern void STDTraceSet(STDHandle *, int);
extern int  STDTraceGet(STDHandle *);
extern void STDUserContextSet(STDHandle *, int user_ctx);
extern long STDUserContextGet(STDHandle *);
extern long STDIdxGet(STDHandle *);
extern void STDStopOnSize(STDHandle *, int stop_size);
extern void STDStopOnCounter(STDHandle *, int stop_counter);

extern STDAllocTrigger STDAllocTriggerSet(STDHandle *, STDAllocTrigger,
					  void *user_data);
extern STDFreeTrigger STDFreeTriggerSet(STDHandle *, STDFreeTrigger,
					void *user_data);
extern STDReallocTrigger STDReallocTriggerSet(STDHandle *, STDReallocTrigger,
					      void *user_data);

#define STD_ADDR_(MAP, OFFSET) \
        ((OFFSET) ? ((char *)(MAP) + (OFFSET)) : (char *)0)

#define STD_OFFSET_(MAP, ADDR) \
	((STDOffset)((ADDR) ? ((char *)(ADDR) - (char *)(MAP)) : 0))

#define STD_ADDR(STDH, OFFSET) STD_ADDR_((STDH)->map, OFFSET)

#define STD_OFFSET(STDH, ADDR) STD_OFFSET_((STDH)->map, ADDR)

#define STD_NULLOFFSET ((STDOffset)0)

#endif
