/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2018 SYSRA
   
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


#define XM_CHECK
/*#define XM_MEM_ZERO*/
/*#define XM_TRACE*/
#define XM_ALIGN8
/*#define XM_BESTFIT*/
#define XM_CONCURRENT
#define XM_ESM_MUTEX
#define XM_FLOPT

#include <eyedbsmconfig.h>

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef XM_ESM_MUTEX
#include <eyedbsm_p.h>
#include <mutex.h>
#elif defined(XM_CONCURRENT)
#include <pthread.h>
#endif

#include "xm_alloc.h"
#include <eyedblib/m_mem.h>
#include "lib/m_mem_p.h"

namespace eyedbsm {

#define XM_MAGIC           ((unsigned int)0xEF18D467)
#define XM_ZERO            ((unsigned char )0xb1)
#define XM_OP(MAP, OFFSET) ((XMOverhead *)XM_ADDR_(MAP, OFFSET))
#define XM_OVERHEAD         sizeof(XMOverhead)
#define XM_NFL              12

#ifdef XM_ESM_MUTEX
#define XM_LOCK(M)          if ((M)->x) MUTEX_LOCK_VOID((M)->mp, 0)
#define XM_UNLOCK(M)        if ((M)->x) MUTEX_UNLOCK((M)->mp, 0)
#elif defined(XM_CONCURRENT)
#define XM_LOCK(M)          pthread_mutex_lock(&(M)->mp)
#define XM_UNLOCK(M)        pthread_mutex_unlock(&(M)->mp)
#else
#define XM_LOCK(M)
#define XM_UNLOCK(M)
#endif

typedef struct {
#ifdef XM_CHECK
  unsigned int magic;
#endif
  unsigned int free:1, size:31;
  XMOffset prevmap, prev, next;
#if defined(XM_CHECK) && defined(XM_ALIGN8)
  int pad;
#endif
} XMOverhead;

struct XMMap {
#ifdef XM_ESM_MUTEX
  MutexP mp;
#elif defined(XM_CONCURRENT)
  pthread_mutex_t mp;
#endif
  unsigned int magic;
  int heapsize;
  int totalsize;
  XMOffset freelist[XM_NFL];
  XMOffset heap;
  XMOffset dataup;
  int used_cells, free_cells;
  XMOffset upmap;
};

#define __XM_ALIGN1(N)

#define __XM_ALIGN4(N) \
  if ((N) & 0x3) \
    N = ((N) & ~0x3) + 0x4

#define __XM_ALIGN8(N) \
  if ((N) & 0x7) \
    N = ((N) & ~0x7) + 0x8

#ifdef XM_ALIGN8
#define XM_ALIGN __XM_ALIGN8
#else
#define XM_ALIGN __XM_ALIGN4
#endif

/* utility functions */
static int
XMCheckMap(XMHandle *xmh, int silent);

static void
XMErrorHere(XMMap *map)
{
  utlog("LOG_ALLOC error map=%o\n", map);
  /*
  if (map)
    XMCheckMap(map, 0);
  */
  /*  abort(); */
}

#ifdef XM_FLOPT

static char *xm_fl;
static unsigned int xm_max_fl_size;

static void
XMInitFLIdx()
{
  static int init;

  if (!init)
    {
      unsigned int n, idx;
      xm_max_fl_size = 1 << (XM_NFL+1);
      xm_fl = (char *)m_malloc(sizeof(char) * (xm_max_fl_size+1));
      
      for (n = 0, idx = 0; n < xm_max_fl_size+1; n++)
	{
	  xm_fl[n] = idx;
	  if (n && !(n & (unsigned int)((1 << (idx+3))-1)))
	    idx++;
	}
      init = 1;
    }
}

#define XMGetFreelist(SZ) ((SZ) > xm_max_fl_size ? (XM_NFL-1) : xm_fl[SZ])

#else

#define XMInitFLIdx()

static int
XMGetFreelist(unsigned int size)
{
  int n, sz;

  for (n = 0, sz = 8; n < XM_NFL; n++, sz <<= 1)
    if (size <= sz)
      return n;

  return XM_NFL - 1;
}
#endif

static void *XMMallocRealize(XMMap *, unsigned int);

static int
XMCheckAllZero(char *p, unsigned int size, int silent)
{
  unsigned char *q = (unsigned char *)p;
  int i, errors = 0;

  for (i = 0; i < size; i++)
    if (*q++ != XM_ZERO)
      {
	if (!silent)
	  {
	    if (!errors)
	      utlog("LOG_ALLOC check_memory: error non zero (=0x%x) cell 0x%x, size = %d {\n", XM_ZERO, p, size);
	    utlog("\t[%d] = %p\n", i, *(q-1));
	  }
	errors++;
      }

  if (!silent && errors)
    utlog("}\n");

  return errors;
}

#define _MAGIC_(I) (MAGIC + (I)*0x101)

#define SET_MAGIC(OP)   ((OP)->magic = XM_MAGIC)
#define CHECK_MAGIC(OP) ((OP)->magic == XM_MAGIC)
#define RESET_MAGIC(OP) ((OP)->magic = 0)

static void
XMMutexInit(XMHandle *xmh)
{
  XMMap *map = xmh->map;
#ifdef XM_CONCURRENT
  pthread_mutexattr_t mattr;
  pthread_mutexattr_init(&mattr);
#ifdef HAVE_PTHREAD_MUTEXATTR_SETPSHARED
#ifdef _POSIX_THREAD_PROCESS_SHARED
  pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#endif
#endif

#ifdef XM_ESM_MUTEX
  xmh->mp = (Mutex *)m_calloc(sizeof(Mutex), 1);
  mutexInit((DbDescription *)xmh->x, xmh->mp, &map->mp, "xm_alloc");
  /*se_mutexInit(xmh->x, 0, &map->mp, "xm_alloc");*/
#else
  pthread_mutex_init(&map->mp, &mattr);
#endif

#endif
}

static void
XMMutexLightInit(XMHandle *xmh)
{
  XMMap *map = xmh->map;

#ifdef XM_ESM_MUTEX
  xmh->mp = (Mutex *)m_calloc(sizeof(Mutex), 1);
  mutexLightInit((DbDescription *)xmh->x, xmh->mp, &map->mp);
#endif
}

static void
XMHeapInit(XMHandle *xmh, XMOffset data, unsigned int size)
{
  XMMap *map = xmh->map;
  int which;
  XMOverhead *op;

#ifdef XM_ALIGN8
  size &= ~0x7;
#endif
  memset(map, 0, sizeof(*map));

  /*if (xmh->x)*/ /* disconnected the 4/09/01 */
    XMMutexInit(xmh);

  map->magic          = XM_MAGIC;
  map->heapsize       = size;
  map->heap           = data;
#ifdef XM_MEM_ZERO
  memset((char *)map + data, XM_ZERO, size);
#endif
  which = XMGetFreelist(size-XM_OVERHEAD);
  map->freelist[which] = map->heap;

  op = XM_OP(map, map->freelist[which]);
  op->size = map->heapsize - XM_OVERHEAD;
  map->dataup  = map->heap + map->heapsize - 1;
  op->next = 0;
  op->prev = 0;
  op->free = 1;
  op->prevmap = 0;
  map->upmap   = map->freelist[which];
#ifdef XM_CHECK
  SET_MAGIC(op);
#endif
  map->totalsize = op->size;

#ifdef XM_TRACE
  utlog("LOG_ALLOC creating heap ADDR %p, SIZE %p\n", data, size);
#endif
  map->used_cells = 0;
  map->free_cells  = 1;
}

static int
XMCheckMap(XMHandle *xmh, int silent)
{
#ifdef XM_CHECK
  XMMap *map = xmh->map;
  char *end = XM_ADDR_(map, map->heap) + map->heapsize, *p;
  int cnt_free = 0, cnt_alloc = 0, errors = 0, size_free = 0, size_alloc = 0,
    zero_errors = 0, which, ncnt_free = 0, ncnt_alloc = 0;
  XMOverhead *op;
  int maxfreesize = 0;

  XM_LOCK(xmh);
  printf("Log Memory Allocator [total size = %u, addr = %p] {\n",
	 map->totalsize, map);
  utlog("LOG_ALLOC Log Memory Allocator [addr = %p] {\n", map);
  for (p = XM_ADDR_(map, map->heap); p < end; )
    {
      op = (XMOverhead *)p;
      if (!CHECK_MAGIC(op))
	{
	  errors++;
	  if (!silent)
	    {
	      printf("check_memory: error cell #%d [p = %p], [magic = %p]\n",
		     cnt_free+cnt_alloc, p + XM_OVERHEAD, op->magic);
	      utlog("LOG_ALLOC error cell #%d [p = %p], [magic = %p]\n",
		     cnt_free+cnt_alloc, p + XM_OVERHEAD, op->magic);
	    }
	}
      else
	{
	  if (op->free)
	    {
	      cnt_free++;
	      size_free += op->size;
	      if (op->size > maxfreesize)
		maxfreesize = op->size;
#ifdef XM_MEM_ZERO
	      zero_errors += XMCheckAllZero(p + XM_OVERHEAD, op->size, 0);
#endif
	    }
	  else
	    {
	      cnt_alloc++;
	      size_alloc += op->size;
#if 0
	      printf("Used Size -> %d\n", op->size);
#endif
	    }

#ifdef XM_ALIGN8
	  if (op->size & 0x7)
	    {
	      printf("check_memory: error size %d\n", op->size);
	      utlog("LOG_ALLOC error size %d\n", op->size);
	      errors++;
	    }
#endif
	}
      p += op->size + XM_OVERHEAD;
    }

  for (which = 0; which < XM_NFL; which++)
    {
      XMOverhead *pop = 0;
      op = XM_OP(map, map->freelist[which]);

      while (op)
	{
	  if (XM_OP(map, op->prev) != pop)
	    {
	      printf("mem_check_memory: link error in #%d p = %p\n",
		     which, (char *)(op)+XM_OVERHEAD);
	      utlog("LOG_ALLOC link error in #%d p = %p\n",
		     which, (char *)(op)+XM_OVERHEAD);
	      errors++;
	    }

	  if (!op->free)
	    {
	      printf("mem_check_memory: free cell expected %p\n", op);
	      utlog("LOG_ALLOC free cell expected %p\n", op);
	      errors++;
	    }

	  ncnt_free++;

	  pop = op;
	  op = XM_OP(map, op->next);
	}
    }

  if (ncnt_free != cnt_free)
    {
      errors++;
      printf("free count incohency %d versus %d\n", cnt_free, ncnt_free);
      utlog("LOG_ALLOC free count incohency %d versus %d\n", cnt_free, ncnt_free);
    }
  
  /* check prevmap */
  ncnt_free = 0;
  ncnt_alloc = 0;

  for (op = XM_OP(map, map->upmap); op; op = XM_OP(map, op->prevmap))
    {
      if (!CHECK_MAGIC(op))
	{
	  errors++;
	  if (!silent)
	    {
	      printf("check_memory: error cell #%d [p = %p], [magic = %p]\n",
		     ncnt_free+ncnt_alloc, p + XM_OVERHEAD, op->magic);
	      utlog("LOG_ALLOC error cell #%d [p = %p], [magic = %p]\n",
		    ncnt_free+ncnt_alloc, p + XM_OVERHEAD, op->magic);
	    }
	}

      if (op->free)
	ncnt_free++;
      else
	ncnt_alloc++;
    }

  if (ncnt_free != cnt_free)
    {
      errors++;
      printf("free count incohency for prevmap %d versus %d\n", cnt_free, ncnt_free);
      utlog("LOG_ALLOC free count incohency for prevmap %d versus %d\n", cnt_free, ncnt_free);
    }

  if (ncnt_alloc != cnt_alloc)
    {
      errors++;
      printf("alloc count incohency for prevmap %d versus %d\n",
	     cnt_alloc, ncnt_alloc);
      utlog("LOG_ALLOC alloc count incohency for prevmap %d versus %d\n",
	    cnt_alloc, ncnt_alloc);
    }

  if (!silent)
    {
      printf("\tFatal Errors  : %d\n", errors);
      utlog("LOG_ALLOC \tFatal Errors  : %d\n", errors);
#ifdef XM_MEM_ZERO
      printf("\tZeroed Errors : %d\n", zero_errors);
      utlog("LOG_ALLOC \tZeroed Errors : %d\n", zero_errors);
#endif
      printf("\tFree Cells    : %d\n", cnt_free);
      utlog("LOG_ALLOC \tFree Cells    : %d\n", cnt_free);
      printf("\tUsed Cells    : %d\n", cnt_alloc);
      utlog("LOG_ALLOC \tUsed Cells    : %d\n", cnt_alloc);
      printf("\tFree Bytes    : %d\n", size_free);
      utlog("LOG_ALLOC \tFree Bytes    : %d\n", size_free);
      printf("\tUsed Bytes    : %d\n", size_alloc);
      utlog("LOG_ALLOC \tUsed Bytes    : %d\n", size_alloc);
      printf("\t*Used Bytes*  : %d\n",
	     size_alloc + (cnt_alloc + cnt_free) * XM_OVERHEAD);
      utlog("LOG_ALLOC \t*Used Bytes*  : %d\n",
	    size_alloc + (cnt_alloc + cnt_free) * XM_OVERHEAD);
      printf("\tMax Free Size : %d\n", maxfreesize);
      utlog("LOG_ALLOC \tMax Free Size : %d\n", maxfreesize);
    }

  printf("}\n");
  utlog("LOG_ALLOC }\n");
  XM_UNLOCK(xmh);
  return errors;
#else
  return 0;
#endif
}

int
XMCheckMemory(XMHandle *xmh)
{
#ifdef XM_CHECK
  return XMCheckMap(xmh, 0);
#else
  XMShowMemory(xmh);
  return 0;
#endif
}

void
XMShowMemory(XMHandle *xmh)
{
  XMMap *map = xmh->map;
  XM_LOCK(xmh);
  printf("Log Memory Allocator [addr = %p] {\n", map);
  printf("\tFree Cells : %d\n", map->free_cells);
  printf("\tUsed Cells : %d\n", map->used_cells);
  printf("\tFree Bytes : %d [%d Kb]\n",
	 map->totalsize, (map->totalsize)/1024);
  printf("\tUsed Bytes : %d [%d Kb]\n",
	 (map->heapsize - map->totalsize),
	 ((map->heapsize - map->totalsize))/1024);
  printf("}\n");
  XM_UNLOCK(xmh);
}

void
XMGetInfo(XMHandle *xmh, int *free_cells, int *used_cells, int *used, int *left)
{
  XMMap *map = xmh->map;
  XM_LOCK(xmh);
  if (free_cells)
    *free_cells = map->free_cells;
  if (used_cells)
    *used_cells = map->used_cells;
  if (used)
    *used = (map->heapsize - map->totalsize);
  if (left)
    *left = map->totalsize;
  XM_UNLOCK(xmh);
}

XMHandle *
XMCreate(char *addr, unsigned int size, void *x)
{
  XMHandle *xmh;

  XMInitFLIdx();

  /*  utlog("LOG_ALLOC XMCreate(%p)\n", addr);*/

  xmh = (XMHandle *)m_calloc(sizeof(XMHandle), 1);
  xmh->map = (XMMap *)addr;
  xmh->x = x;
  XMHeapInit(xmh, sizeof(XMMap), size - sizeof(XMMap));

  return xmh;
}

XMHandle *
XMOpen(char *addr, void *x)
{
  XMHandle *xmh;

  XMInitFLIdx();

  xmh = (XMHandle *)m_calloc(sizeof(XMHandle), 1);
  xmh->x = x;
  xmh->map = (XMMap *)addr;

  /* added the 6/12/00 */
  if (xmh->x)
    XMMutexLightInit(xmh); /* changed XMMutexInit to XMMutexLightInit the 4/09/01 */
  /* ... */

  if (xmh->map->magic != XM_MAGIC)
    return (XMHandle *)0;

  return xmh;
}

void
XMInit(XMHandle *xmh)
{
  /*if (xmh->x)*/ /* disconnected the 4/09/01 */
    XMMutexInit(xmh);
}

void
XMClose(XMHandle *xmh)
{
  free(xmh);
}

static
int XMExtendMap(XMHandle *xmh, unsigned int nbytes)
{
  return 0;
#if 0
  int incsize = 4096, which;
  void *x;
  XMOverhead *freelist;


  while (incsize <= nbytes+OVERHEAD)
    incsize += 4096;

  x = sbrk(incsize);

#ifdef XMZERO
  memset(x, ZERO, incsize);
#endif

#ifdef XM_TRACE
  utlog("LOG_ALLOC XMExtendMap(%p, nbytes = %d, incsize = %d) -> %p\n", map, nbytes, incsize, x);
#endif

  if (!x)
    return 0;

  which = XMGetFreelist(incsize-OVERHEAD);

  freelist            = map->freelist[which];

  if (!map->heap)
    map->heap = x;

  map->freelist[which]       = (XMOverhead *)(map->heap + map->heapsize);

  map->freelist[which]->next = freelist;
  map->freelist[which]->prev = 0;
  map->freelist[which]->prevmap = map->upmap;

  if (freelist)
    freelist->prev             = map->freelist[which];

  map->freelist[which]->free = 1;
#ifdef XM_CHECK
  SET_MAGIC(map->freelist[which]);
#endif
  map->heapsize       += incsize;
  map->freelist[which]->size = incsize - XM_OVERHEAD;
  map->dataup         = (unsigned int)&map->heap[map->heapsize-1];
  map->totalsize      += incsize - XM_OVERHEAD;
  map->upmap          = map->freelist[which];
  map->free_cells++;
#endif
  return 1;
}

void
XMLock(XMHandle *xmh)
{
  XM_LOCK(xmh);
}

void
XMUnlock(XMHandle *xmh)
{
  XM_UNLOCK(xmh);
}

void *XMAllocZero(XMHandle *xmh, unsigned int nbytes)
{
  void *p;

  p = XMAlloc(xmh, nbytes);

  if (p)
    memset(p, 0, nbytes);

  return p;
}

/*
 * XMAlloc(XMMap *map, nbytes): allocates nbytes of memory in statical heap
*/

void *XMAlloc(XMHandle *xmh, unsigned int nbytes)
{
  void *p;
  XMMap *map = xmh->map;

  if (!nbytes)
    {
      utlog("LOG_ALLOC XMAlloc(nbytes=0)\n");
      return 0;
    }

  XM_ALIGN(nbytes);

  XM_LOCK(xmh);
  p = XMMallocRealize(map, nbytes);
  XM_UNLOCK(xmh);

#ifdef XM_TRACE
  utlog("LOG_ALLOC XMAlloc(%p, %d) = %p [%d]\n", map, nbytes, p,
	  map->heapsize - map->totalsize);
#endif
#ifdef XM_MEM_ZERO
  if (p)
    memset(p, 0, nbytes);
#endif
  if (!p)
    {
      if (XMExtendMap(xmh, nbytes))
	return XMAlloc(xmh, nbytes);
      utlog("LOG_ALLOC allocation failed for byte count = %d\n", nbytes);
      printf("LOG_ALLOC allocation failed for byte count = %d\n", nbytes);
      XMCheckMap(xmh, 0);
      return 0;
    }
  return p;
}

void *XMRealloc(XMHandle *xmh, void *p, unsigned int nbytes)
{
  XMOverhead *op = (XMOverhead *)((char *)p - XM_OVERHEAD);
  void *r;
  int osize;

  if (!p)
    return XMAlloc(xmh, nbytes);

  if (op->free)
    {
      utlog("LOG_ALLOC realloc failed [op->free] byte count = %d\n", nbytes);
      XMErrorHere(0);
      return 0;
    }

#ifdef XM_CHECK
  if (!CHECK_MAGIC(op))
    {
      utlog("LOG_ALLOC XMRealloc: op->magic != XM_MAGIC realloc(%d)\n", nbytes);
      XMErrorHere(0);
      return 0;
    }
#endif

  XM_ALIGN(nbytes);

  osize = op->size;

  if (osize >= nbytes)
    return p;

  if (!(r = XMAlloc(xmh, nbytes)))
    return 0;

  memcpy(r, p, osize);
#ifdef XM_MEM_ZERO
  memset((char *)r + osize, 0, nbytes - osize);
#endif
  XMFree(xmh, p);

#ifdef XM_TRACE
  utlog("LOG_ALLOC m_realloc(%p, %x, %d) = %x\n", xmh, p, nbytes, r);
#endif
  return r;
}

static void
XMSuppressFL(XMMap *map, XMOverhead *op)
{
  if (op->prev)
    XM_OP(map, op->prev)->next = op->next;
  else
    map->freelist[XMGetFreelist(op->size)] = op->next;

  if (op->next)
    XM_OP(map, op->next)->prev = op->prev;

  op->free = 0;
  map->free_cells--;
}

static void
XMSuppress(XMMap *map, XMOverhead *op)
{
  XMSuppressFL(map, op);

  if ((char *)(op)+op->size+XM_OVERHEAD == XM_ADDR_(map, map->dataup) + 1)
    map->upmap = op->prevmap;
  else
    {
      XMOverhead *top = (XMOverhead *)((char *)(op) + op->size + XM_OVERHEAD);
      top->prevmap = op->prevmap;
    }
}

static void
XMInsert(XMMap *map, XMOverhead *op)
{
  int which = XMGetFreelist(op->size);
  XMOverhead *freelist = XM_OP(map, map->freelist[which]);

#ifdef XM_CHECK
  if (freelist)
    assert(CHECK_MAGIC(freelist));
#endif

  map->freelist[which] = XM_OFFSET_(map, op);
  op->prev = 0;
  op->next = XM_OFFSET_(map, freelist);

  if (freelist)
    freelist->prev = XM_OFFSET_(map, op);

#ifdef XM_MEM_ZERO
  memset((char *)(op) + XM_OVERHEAD, XM_ZERO, op->size);
#endif
#ifdef XM_CHECK
  SET_MAGIC(op);
#endif
  op->free = 1;
  map->free_cells++;

  if ((char *)(op) + op->size + XM_OVERHEAD == XM_ADDR_(map, map->dataup) + 1)
    map->upmap = XM_OFFSET_(map, op);
  else
    {
      XMOverhead *top = (XMOverhead *)((char *)(op) + op->size + XM_OVERHEAD);
      top->prevmap = XM_OFFSET_(map, op);
    }
}

static void
XMFreeCell(XMMap *map, XMOverhead *op)
{
  XMOverhead *next, *prev;
  int *x;
  char *top;

#ifdef XM_MEM_ZERO
  memset((char *)(op) + XM_OVERHEAD, XM_ZERO, op->size);
#endif

  next = (XMOverhead *)((char *)op + op->size + XM_OVERHEAD);
  if ((char *)next >= XM_ADDR_(map, map->dataup))
    next = 0;

  prev = XM_OP(map, op->prevmap);

#ifdef XM_CHECK
  if (prev && !CHECK_MAGIC(prev))
    {
      utlog("LOG_ALLOC XMFree: prevmap not good magic!\n");
      XMErrorHere(map);
    }
#endif

  if (prev && prev->free && next && next->free)
    {
      XMSuppress(map, prev);
      XMSuppress(map, next);
      map->totalsize += op->size + 2 * XM_OVERHEAD;
      prev->size += op->size + next->size + 2 * XM_OVERHEAD;
      XMInsert(map, prev);
#ifdef XM_MEM_ZERO
      memset(next, XM_ZERO, XM_OVERHEAD);
      memset(op, XM_ZERO, XM_OVERHEAD);
#endif
    }
  else if (prev && prev->free)
    {
      XMSuppress(map, prev);
      map->totalsize += op->size + XM_OVERHEAD;
      prev->size += op->size + XM_OVERHEAD;
      XMInsert(map, prev);
#ifdef XM_MEM_ZERO
      memset(op, XM_ZERO, XM_OVERHEAD);
#endif
    }
  else if (next && next->free)
    {
      XMSuppress(map, next);
      map->totalsize += op->size + XM_OVERHEAD;
      op->size += next->size + XM_OVERHEAD;
      XMInsert(map, op);
#ifdef XM_MEM_ZERO
      memset(next, XM_ZERO, XM_OVERHEAD);
#endif
    }
  else
    {
      map->totalsize += op->size;
      XMInsert(map, op);
    }
}

int
XMFree(XMHandle *xmh, void *p)
{
  XMOverhead *op = (XMOverhead *)((char *)p - XM_OVERHEAD), *freelist;
  XMMap *map = xmh->map;
  unsigned int size, which;

  if (!p)
    return 0;

#ifdef XM_CHECK
  if (!CHECK_MAGIC(op))
    {
      utlog("LOG_ALLOC XMFree: op->magic != XM_MAGIC m_s_free(%x)\n", p);
      XMErrorHere(map);
      return 0;
    }
#endif

  if (op->free)
    {
      utlog("LOG_ALLOC XMFree(%p): pointer not allocated\n", p);
      XMErrorHere(0);
      return 0;
    }

  size = op->size;

  XM_LOCK(xmh);
  XMFreeCell(map, op);
  map->used_cells--;
  XM_UNLOCK(xmh);

#ifdef TRACE
  utlog("LOG_ALLOC XMFree(%p, %x, %d)\n", map, p, size);
#endif
  return size;
}

int
XMGetSize(XMHandle *xmh, void *p)
{
  XMOverhead *op = (XMOverhead *)((char *)p - XM_OVERHEAD);
  unsigned int size;

  if (!p || op->free)
    return 0;

#ifdef XM_CHECK
  if (!CHECK_MAGIC(op))
    {
      utlog("LOG_ALLOC op->magic != XM_MAGIC m_s_free(%x)\n", p);
      return 0;
    }
#endif

  return op->size;
}

static void *
XMMallocRealize(XMMap *map, unsigned int nbytes)
{
  XMOverhead *op, *bestfit;
  unsigned int sdiff, sizediff = (unsigned int)0xFFFFFFFF;
  int which = XMGetFreelist(nbytes), lo = 0;

  bestfit = 0;

  if (which < XM_NFL - 1)
    which++;

 loop:
  for ( ; which < XM_NFL; which++)
    {
      op = XM_OP(map, map->freelist[which]);

      while(op)
	{
#ifdef XM_CHECK
	  if (!CHECK_MAGIC(op))
	    {
	      utlog("LOG_ALLOC XMMallocRealize: invalid magics for %p\n", op);
	      XMErrorHere(map);
	      return 0;
	    }

	  if (!op->free)
	    {
	      utlog("LOG_ALLOC XMMallocRealize: not free %d\n", nbytes);
	      XMErrorHere(map);
	      op = XM_OP(map, op->next);
	      continue;
	    }
#endif	  
	  
	  /*	  if ((sdiff = (unsigned int)(op->size - nbytes)) >= 0)*/
	  if ((int)(sdiff = (op->size - nbytes)) >= 0)
	    {
	      if (sdiff < sizediff)
		{
		  bestfit = op;
		  sizediff = sdiff;
		  if (!sdiff)
		    break;
#ifndef XM_BESTFIT
		  goto out;
#endif
		}
	    }

	  op = XM_OP(map, op->next);
	}
    }

 out:
  if (!bestfit)
    {
      which = XMGetFreelist(nbytes);
      if (!lo && which < XM_NFL - 1)
	{
	  lo = 1;
	  goto loop;
	}
      return 0;
    }

  if (sizediff <= XM_OVERHEAD)
    {
      XMSuppressFL(map, bestfit);
      map->totalsize -= bestfit->size;
      map->used_cells++;
      return (void *)((char *)bestfit + XM_OVERHEAD);
    }
  else
    {
      XMOverhead *top = (XMOverhead *)((char *)bestfit + nbytes + XM_OVERHEAD);

      if ((char *)top < XM_ADDR_(map, map->dataup))
	{
	  top->size = bestfit->size - nbytes - XM_OVERHEAD;
	  top->prevmap = XM_OFFSET_(map, bestfit);
	  XMInsert(map, top);
	}

      XMSuppressFL(map, bestfit);

      bestfit->size = nbytes;

      map->totalsize -= (nbytes + XM_OVERHEAD);
      map->used_cells++;
      return (void *)((char *)bestfit + XM_OVERHEAD);
    }
}

}
