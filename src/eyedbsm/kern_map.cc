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

#include <eyedbsmconfig.h>

#include <sys/types.h>

#include "kern_p.h"

//#define TRACE1

#define ABS(x) ((off_t)( (long long)(x) > 0 ? (long long)(x) : -(long long)(x) ))
#define DIST(MMD, s, e) ABS((MMD)->s_start - (s))
#define IS_IN(x,y,z) ( (x) >= (y) && (x) < (z) )
/*#define ESM_MMAP_WIDE_SEGMENT   1000*/
/*
#define ESM_MMAP_WIDE_SEGMENT   2000
#define ESM_MMAP_WIDE_2_SEGMENT (ESM_MMAP_WIDE_SEGMENT >> 1)
*/

namespace eyedbsm {

  void
  hdl_release(MmapH *hdl)
  {
    MmapDesc *mmd = hdl->mmd;

    if (mmd && mmd->locked)
      {
	//printf("hdl_release mmd=%p, pos=%d, npts=%d\n", mmd, hdl->pos, mmd->npts);
	mmd->pts[hdl->pos] = 0;
	*hdl->pt = 0;
	if (!--mmd->npts)
	  {
	    mmd->locked = False;
	    m_unlock(mmd->m);
	  }
      }
  }


  static void
  garb_trig(void *arg)
  {
    MmapDesc *mmd = (MmapDesc *)arg;
#ifdef TRACE
    utlog("garb_trig %x mapaddr 0x%x %d\n", mmd, mmd->mapaddr, mmd->locked);
#endif
    ESM_ASSERT_ABORT(!mmd->locked, 0, 0);
    mmd->ismapped = False;
    mmd->ref = 0;
    mmd->locked = False;
  }

  static void display_dmd(DatDesc *dmd)
  {
    MmapDesc *mmd, *mmd1, *fmmd = 0, *mmend = &dmd->mmd[MAX_MMAP_SEGMENTS];

    unsigned int n = 0;
    for (mmd = dmd->mmd; mmd < mmend; mmd++, n++) {
      if (mmd->ismapped) {
	fprintf(stdout, "segment #%u %llx - %llx (%s)\n", n, mmd->s_start, mmd->s_end,
		mmd->locked ? "locked" : "not locked");
      }
    }
  }

  static void check_dmd(DatDesc *dmd)
  {
    MmapDesc *mmd, *mmd1, *fmmd = 0, *mmend = &dmd->mmd[MAX_MMAP_SEGMENTS];
    unsigned int n;

    bool should_display = false;
    for (mmd = dmd->mmd, n = 0; mmd < mmend; mmd++, n++) {
      if (mmd->ismapped) {
	off_t ws_start = mmd->s_start, ws_end = mmd->s_end;
	unsigned int m = n + 1;
	for (mmd1 = dmd->mmd + m; mmd1 < mmend; mmd1++, m++) {
	  if (mmd1->ismapped)	{
#if 1
	    if (IS_IN(ws_start, mmd1->s_start, mmd1->s_end)) {
	      fprintf(stdout, "multimap segment #%u start: %llx in #%u %llx - %llx (%s)\n", n, ws_start, m, mmd1->s_start, mmd1->s_end, mmd1->locked ? "locked" : "not locked");
	      should_display = true;
	    }

	    if (IS_IN(ws_end-1, mmd1->s_start, mmd1->s_end)) {
	      fprintf(stdout, "multimap segment #%u end: %llx in #%u %llx - %llx (%s)\n", n, ws_end, m, mmd1->s_start, mmd1->s_end, mmd1->locked ? "locked" : "not locked");
	      should_display = true;
	    }
#else
	    ESM_ASSERT_ABORT(!IS_IN(ws_start, mmd1->s_start, mmd1->s_end), 0, 0);
	    ESM_ASSERT_ABORT(!IS_IN(ws_end-1, mmd1->s_start, mmd1->s_end), 0, 0);
#endif
	  }
	}
      }
    }

    if (should_display)
      display_dmd(dmd);
  }

  static MmapDesc *
  find_segment(register DatDesc *dmd, off_t ws_start, off_t ws_end)
  {
    off_t delta = 0, uv;
    unsigned long ref = curref+1;

    MmapDesc *mmd, *fmmd = 0, *mmend = &dmd->mmd[MAX_MMAP_SEGMENTS];

    for (mmd = dmd->mmd; mmd < mmend; mmd++) {
      if (mmd->ismapped && !mmd->locked) {
	if (mmd->ref < ref)
	  if ((uv = DIST(mmd, ws_start, ws_end)) > delta) {
	    ref = mmd->ref;
	    fmmd = mmd;
	  }
      }
    }
		
    ESM_ASSERT_ABORT(fmmd, 0, 0);
  
    SEGMENT_UNMAP(fmmd);
    return fmmd;
  }

  static void stop_it_man() {}

  static int
  mmd_add(MmapDesc *mmd, char **pt)
  {
    char ***p;
    int pos;

    if (mmd->npts >= mmd->nalloc) {
      int inc = 6;
      if (!mmd->nalloc)	{
	mmd->nalloc = inc;
	mmd->pts = (char ***)m_calloc(sizeof(char **)*mmd->nalloc, 1);
      }
      else {
	mmd->nalloc += inc;
	mmd->pts = (char ***)m_realloc(mmd->pts, sizeof(char **)*mmd->nalloc);
	memset(mmd->pts+(mmd->nalloc-inc), 0, sizeof(char **)*inc);
      }
    }

    for (p = mmd->pts, pos = 0; pos < mmd->nalloc; p++, pos++)
      if (!*p) {
	mmd->pts[pos] = pt;
	mmd->npts++;
	mmd->locked = True;
	assert(mmd->npts < 6); /* garde-fou stupide */
	//printf("mmd_add mmd=%p, pos=%d, npts=%d\n", mmd, pos, mmd->npts);
	return pos;
      }
    ESM_ASSERT_ABORT(0, 0, 0);
  }

  /*
    OPTIMISATION:
    on pourrait ajouter dans vd, le champ `all_mapped' qui indique
    que toute la base est mappée.
    cela permettrait de ne pas rentrer dans cette fonction slot2addr.
    #define SLOT2ADDR(dbh, ws_start, size, pt, ...) \
    (dbh->vd->all_mapped ? (char *)(((ws_start - mmd->s_start) * sizeslot) +
    mmd->mapaddr) : slot2addr(dbh, ws_start, ...)
    Bien sur, la gestion du all_mapped doit etre siouks!
    Et notamment tenir compte de l'extension d'un volume en ecriture.
  */

  char *
  oidloc2addr(const DbHandle *dbh, const OidLoc &oidloc, size_t size, char **pt, MmapH *hdl, size_t *up)
  {
    return slot2addr(dbh, oidloc.ns, oidloc.datid, size, pt, hdl, up);
  }

  char *
  slot2addr(const DbHandle *dbh, off_t ws_start, short datid, size_t size, char **pt, MmapH *hdl, size_t *up)
  {
    //ESM_ASSERT_ABORT(size > 0, 0, 0);

    if (ws_start == (off_t) (-NS_OFFSET))
      return (char *)0;

    MapHeader t_mp = DAT2MP(dbh, datid);
    MapHeader *mp = &t_mp;
    DatDesc *dmd = &dbh->vd->dmd[datid];

    size_t sizeslot = x2h_u32(mp->sizeslot());

    if (dmd->m_dat) {
      hdl->mmd = 0;
      if (up) {*up = 0;}
      return (char *)((ws_start * sizeslot) + dmd->addr);
    }

    off_t delta_left = 0xffffffff, delta_right = 0xffffffff;
    MmapDesc *mmd, *mmend, *fmmd = 0, *mmd_left, *mmd_right;
    int fop, inc, inc1, v, wide, wide2, n;
    off_t startslot, ws_end, start, end, wa_start, wa_end, dum, uv,
      t_start, t_end;
    int nreloc=0;
    int pow2 = x2h_u32(mp->pow2());
    MmapDesc *mmd_reloc[MAX_MMAP_SEGMENTS];
    Mutex *mt = SLT_MTX(dbh);
    unsigned int xid = dbh->vd->xid;
    int x;
    Status status;
    TransactionContext *trctx = DBH2TRCTX(dbh);

    ws_end = ws_start + (off_t)((size + sizeslot-1) >> pow2);

    startslot = 0;

    mmend = &dmd->mmd[MAX_MMAP_SEGMENTS];

    /* try to find a segment which includes interval [ws_start, ws_end] */
    t_start = ws_start;
    t_end   = ws_end;

  try_again:
    /* WARNING (8/01/99): locks are not set in case of the database is opened in
       transless mode: but is this really a problem?
       in a more general way, this lock is useful only in multi-threaded
       environment and not in multi-processus environment because mmap()
       operation is private to the process!
       so, this mutex could be a static mutex (i.e. static Mutex mp) */
    /*
      if (NEED_LOCK(trctx))
      MUTEX_LOCK_VOID(mt, xid);
    */

    for (mmd = dmd->mmd; mmd < mmend; mmd++) {
      if (mmd->ismapped) {
	Boolean left = False, right = False;

	if (IS_IN(t_start, mmd->s_start, mmd->s_end))
	  left = True;
	if (IS_IN(t_end-1, mmd->s_start, mmd->s_end))
	  right = True;

	if (left && right) { /* this segment includes the interval: returns */
	  mmd->ref = ++curref;
	  m_access(mmd->m);
	  hdl->mmd = mmd;
	  hdl->pos = mmd_add(mmd, pt);
	  hdl->pt  = pt;
	  /*
	    if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mt, xid);
	  */
	  if (up) {
	    *up = mmd->s_end;
	  }
	  return (char *)(((ws_start - mmd->s_start) * sizeslot) +
			  mmd->mapaddr);
	}
	else if (left || right) {/* the interval crosses the segment:
				    must unmmaped this segment */
	  if (mmd->locked) {
	    caddr_t t_addr = mmd->mapaddr;
#ifdef TRACE1
	    printf("should relocate really!\n");
#endif
	    mmd_reloc[nreloc++] = mmd;
	    if (left)
	      t_start = mmd->s_start;
	    else if (right)
	      t_end = mmd->s_end;

	    IDB_LOG(IDB_LOG_MMAP,
		    ("slot2addr: interval cross segment [1]: must unmap\n"));

	    SEGMENT_UNMAP(mmd);
	    mmd->mapaddr = t_addr;

	    mmd->locked = True;

	    /*
	      if (NEED_LOCK(trctx))
	      MUTEX_UNLOCK(mt, xid);
	    */
	    IDB_LOG(IDB_LOG_MMAP, ("slot2addr: must try again\n"));
	    goto try_again;
	  }
	  else {
	    IDB_LOG(IDB_LOG_MMAP,
		    ("slot2addr: interval cross segment [2]: must unmap\n"));
	    SEGMENT_UNMAP(mmd);
	  }
	}
      }
      /* else if (!mmd->locked) optimisation (11/09/98) : */
      else if (!fmmd && !mmd->locked) /* finds a free segment: keeps it */
	fmmd = mmd;
    }

    /* if no segment free,  find a segment */
    if (!fmmd) {
      IDB_LOG(IDB_LOG_MMAP, ("slot2addr: no more segment available\n"));
      fmmd = find_segment(dmd, t_start, t_end);
    }

    /*
      wide  = ESM_MMAP_WIDE_SEGMENT   * pgsize;
      wide2 = ESM_MMAP_WIDE_2_SEGMENT * pgsize;
    */
    wide  = dbh->vd->mapwide;
    wide2 = dbh->vd->mapwide2;

    /* convert slot to offset ... */
    wa_start = (t_start - startslot) * sizeslot;
    wa_end   = (t_end   - startslot) * sizeslot;

    /* and round on a page boundary */
    wa_start = (wa_start/pgsize) * pgsize;
    wa_end   = ((wa_end+pgsize-1)/pgsize) * pgsize;

    /* to get the immediate left and right neighbours of the
       interval [t_start, t_end] */
    mmd_left = mmd_right = 0;
    for (mmd = dmd->mmd; mmd < mmend; mmd++) {
      if (mmd->ismapped) {
	if ((long long)((uv = t_start - mmd->s_end)) >= 0 && uv < delta_left) {
	  delta_left = uv;
	  mmd_left = mmd;
	}
	if ((long long)((uv = mmd->s_start - t_end)) >= 0 && uv < delta_right) {
	  delta_right = uv;
	  mmd_right = mmd;
	}
      }
    }

    if (!mmd_left) {
      if (((long long)(start = wa_start - wide2)) >= 0)
	inc = wide2;
      else {
	inc = 0;
	start = 0;
      }
    }
    else {
      off_t leftend = mmd_left->a_end;
      for (inc = wide2; inc >= 0; inc -= pgsize) {
	start = wa_start - inc;
	if (((long long)start) >= 0 && start >= leftend)
	  break;
      }
    
      ESM_ASSERT_ABORT(inc >= 0, mt, xid);
    }

    if (!mmd_right)
      end = wa_end + wide - inc;
    else {
      off_t rightstart = mmd_right->a_start;
      for (inc1 = wide-inc; inc1 >= 0; inc1 -= pgsize) {
	end = wa_end + inc1;
	if (end <= rightstart)
	  break;
      }
    
      ESM_ASSERT_ABORT(inc1 >= 0, mt, xid);
    }

    fop = ((dbh->vd->flags & VOLREAD) ? PROT_READ : PROT_READ|PROT_WRITE);

#ifdef TRACE1
    printf("%s: eyedbsm MMAP start=0x%x, end=0x%x, wa_start=0x%x, wa_end=0x%x, inc=0x%x, size=0x%x, ws_start=%d\n",
	   get_time(), start, end, wa_start, wa_end, inc, size, ws_start);
#endif

    IDB_LOG(IDB_LOG_MMAP_DETAIL, ("slot2addr needs memory segment\n"));
    if (!(fmmd->m = m_mmap(0, end-start, fop, MMAP_MMAP_FLAGS, dmd->fd,
			   start, &fmmd->mapaddr, dmd->file, ws_start,
			   ws_start+size-1))) {
      /*
	if (NEED_LOCK(trctx))
	MUTEX_UNLOCK(mt, xid);
      */
      IDB_LOG(IDB_LOG_MMAP, ("slot2addr: m_mmap failed definitively in slot2addr %p\n",
			     fmmd->m));
      return (char *)0;
    }

#ifdef TRACE1
    printf("mmapaddr 0x%x\n", fmmd->mapaddr);
#endif

    m_gtrig_set(fmmd->m, garb_trig, fmmd);
    m_lock(fmmd->m);

    fmmd->a_start  = start;
    fmmd->a_end    = end;
    fmmd->s_start  = (start>>pow2) + startslot;
    fmmd->s_end    = (end>>pow2) + startslot;
    fmmd->ismapped = True;

    hdl->mmd = fmmd;
    hdl->pos = mmd_add(fmmd, pt);
    hdl->pt  = pt;

    for (n = 0; n < nreloc; n++) {
      MmapDesc *mmd = mmd_reloc[n];
      char ***p;
      int cnt = mmd->npts, pos;

#ifdef TRACE1
      printf("mmd->npts %d\n", mmd->npts);
#endif

      for (p = mmd->pts, pos = 0; pos < mmd->nalloc; p++, pos++) {
	if (*p) {
#ifdef TRACE1
	  printf("must reloc 0x%x (0x%x) 0x%x\n", *p, **p,
		 mmd->mapaddr);
	  printf("START %d %d\n", mmd->s_start, fmmd->s_start);
#endif
	  if (mmd->s_start >= fmmd->s_start) {
#ifdef TRACE1
	    printf("hips!\n");
#endif
	    /*
	    **p = (char *)((mmd->s_start - fmmd->s_start)*sizeslot+
	    (u_long)fmmd->mapaddr+
	    ((u_long)**p)-((u_long)mmd->mapaddr));
	    */
	    **p = (char *)((mmd->s_start - fmmd->s_start) * sizeslot +
			   (fmmd->mapaddr + (off_t)**p) -
			   mmd->mapaddr);
#ifdef TRACE1
	    printf("after 0x%x\n", **p);
#endif
	    memset(mmd->pts, 0, sizeof(char **)*mmd->nalloc);
	    mmd->npts = 0;
	    mmd->locked = False;
	  }
	  if (!--cnt)
	    break;
	}
      }
    }

#ifdef TRACE1
    printf("new mapped [%d]: %d %d %x %x (%x) %d\n", dmd->fd,
	   fmmd->s_start, fmmd->s_end, start, end, fmmd, startslot);
#endif

    // 18/09/07: disconnected because it seems that this check is not good
    // but warning...
#if 0
    check_dmd(dmd);
#endif
    fmmd->ref = ++curref;

    /*
      if (NEED_LOCK(trctx))
      MUTEX_UNLOCK(mt, xid);
    */

    /* added the 2/07/99 because of a bug in EMBL importation */
    if (up) {
      *up = fmmd->s_end;
    }
    return (char *)(((ws_start - fmmd->s_start) * sizeslot) + fmmd->mapaddr);
  }
}
