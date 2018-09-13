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

//#define LINKMAP_SUPPORT

#include "kern_p.h"

#ifdef LINKMAP_SUPPORT

#define TOP_CELL(VD, DATID) ((LinkmapCell *)VD->dmp_addr[DATID])
#define CELL(TOP, W) ((TOP)[W])
#define WHICH_CELL(TOP, TC) \
 (((long)(TC) - (long)&CELL(TOP, 0)) / sizeof(LinkmapCell))

#define InvalidCell (u_int)-1

#endif

namespace eyedbsm {

#ifdef LINKMAP_SUPPORT
  static void
  cellFree(DbDescription *vd, short datid, LinkmapCell *cell)
  {
    MapHeader *mp = DAT2MP_(vd, datid);
    LinkmapCell *top = TOP_CELL(vd, datid);

    if (cell == &CELL(top, mp->LMH.firstcell))
      mp->LMH.firstcell = cell->next;

    if (cell->prev != InvalidCell)
      CELL(top, cell->prev).next = cell->next;

    if (cell->next != InvalidCell)
      CELL(top, cell->next).prev = cell->prev;

    cell->size = 0;
  }

  static LinkmapCell *
  cellFreeGet(DbDescription *vd, short datid)
  {
    MapHeader *mp = DAT2MP_(vd, datid);
    LinkmapCell *cell;
    LinkmapCell *top = TOP_CELL(vd, datid);
    int wcell;

    for (cell = &CELL(top, 0), wcell = 0; wcell < MAX_FREE_CELLS;
	 cell++, wcell++)
      if (!cell->size)
	return cell;
    return 0;
  }

  static void
  cellInsert(DbDescription *vd, NS ns, short datid, size_t size)
  {
    MapHeader *mp = DAT2MP_(vd, datid);
    LinkmapCell *cell, *pcell;
    int wcell;
    LinkmapCell *top = TOP_CELL(vd, datid);

#ifdef ESM_DBG1
    printf("cellInsert %d %d\n", ns, size);
#endif
    pcell = 0;
    if (mp->LMH.firstcell == InvalidCell)
      {
	/* means that there are no more free cell */
#ifdef ESM_DBG1
	printf("NO MORE FREE CELL!\n");
#endif
	mp->LMH.firstcell = 0;
	cell = &CELL(top, 0);
	cell->size = size;
	cell->ns = ns;
	cell->prev = cell->next = InvalidCell;
      }
    else
      for (cell = &CELL(top, mp->LMH.firstcell), wcell = mp->LMH.firstcell; ; )
	{
#ifdef ESM_DBG1
	  printf("INSERT 0x%x %d %d %d %d\n", cell, cell->size, cell->ns, cell->prev,
		 cell->next);
#endif	
	  assert(cell->size);

	  if (cell->ns >= ns + size)
	    {
	      /* four cases:
		 1) prev cell merges with new cell
		 -> does not change link
		 2) next cell merges with new cell
		 -> does not change link
		 3) next and prev cells merge with new cell
		 -> changes link
		 4) no merge
		 -> changes link
	      */

	      if (pcell && pcell->ns + pcell->size == ns &&
		  ns + size == cell->ns)
		{
#ifdef ESM_DBG1
		  printf("MUST MERGE ALL!\n");
#endif
		  pcell->size += size + cell->size;
		  cellFree(vd, datid, cell);
		}
	      else if (pcell && pcell->ns + pcell->size == ns)
		{
#ifdef ESM_DBG1
		  printf("MERGE PREVIOUS!\n");
#endif
		  pcell->size += size;
		}
	      else if (ns + size == cell->ns)
		{
#ifdef ESM_DBG1
		  printf("MERGE NEXT!\n");
#endif
		  cell->ns = ns;
		  cell->size += size;
		}
	      else
		{
		  LinkmapCell *ncell = cellFreeGet(vd, datid);
		  int which = WHICH_CELL(top, ncell);
#ifdef ESM_DBG1
		  printf("NO MERGE\n");
#endif
		  ncell->size = size;
		  ncell->ns = ns;
		  ncell->prev = (pcell ? WHICH_CELL(top, pcell) : InvalidCell);
		  ncell->next = WHICH_CELL(top, cell);

		  if (pcell)
		    pcell->next = which;
		  else
		    mp->LMH.firstcell = which;

		  cell->prev = which;
		}

	      break;
	    }

	  if ((wcell = cell->next) == InvalidCell)
	    {
	      LinkmapCell *ncell = cellFreeGet(vd, datid);
	      int which = WHICH_CELL(top, ncell);

	      ncell->size = size;
	      ncell->ns = ns;
	      ncell->prev = WHICH_CELL(top, cell);
	      ncell->next = InvalidCell;

	      cell->next = which;

#ifdef ESM_DBG1
	      printf("DO SOMETHING!\n");
#endif
	      return;
	    }
	
	  pcell = cell;
	  cell = &CELL(top, wcell);
	}
  }

  static void
  ESM_cellsTraceRealize(DbHandle *dbh, short datid)
  {
    MapHeader *mp = DAT2MP(dbh, datid);
    DbDescription *vd = dbh->vd;
    LinkmapCell *cell;
    LinkmapCell *top = TOP_CELL(vd, datid);
    int wcell, n = 0, ns = -1;

    if (mp->mtype == LinkmapType)
      {
	size_t size = 0;
	printf("\n--------------- Cells Tracing --------------------\n");
	if (mp->LMH.firstcell == InvalidCell)
	  printf("\t\tNo more free cell\n");
	else
	  for (cell = &CELL(top, mp->LMH.firstcell), wcell = mp->LMH.firstcell; ; )
	    {
	      n++;
	      ESM_ASSERT_ABORT(cell->size, 0, 0);
	    
	      size += cell->size;
	      printf("Free cell[%d] size %d, ns %d, prev %d, next %d\n",
		     wcell, cell->size, cell->ns, cell->prev, cell->next);
	    
	      ESM_ASSERT_ABORT((int)cell->ns > ns, 0, 0);
	      if ((wcell = cell->next) == InvalidCell)
		break;

	      ns = cell->ns;
	      cell = &CELL(top, wcell);
	    }
	printf("\n%d cells found, total free size %d [whole %d]\n", n, size,
	       size - cell->size);
	printf("--------------------------------------------------\n\n");
      }
  }
#endif

  static Status
  mapAllocRealize(DbHandle const *dbh, MapHeader *xmp, short datid, size_t size, NS *pns, NS *pneedslots, NS *pmax_free_slots)
  {
    x2h_prologue(xmp, mp);
    DbDescription *vd = dbh->vd;
    size_t _needslots = SZ2NS(size, mp);
    NS needslots = (NS)_needslots;
    if (_needslots != needslots) {
      size_t maxslots = 1ULL << (sizeof(NS)*8);
      return statusMake(ERROR, "Object size=%llu is too large (maximum of slots has been reached: max=%llu, needed_slots=%llu). Maxixum size is: %llu", size, maxslots , _needslots, (maxslots-3)*mp->sizeslot());
    }
    assert((unsigned long long)needslots*mp->sizeslot() >= size);
    Status se;

    *pns = INVALID_NS;

    NS max_free_slots = 0;
    if (pneedslots)
      *pneedslots = needslots;
    if (pmax_free_slots)
      *pmax_free_slots = 0;

    switch(mp->mtype()) {
    case BitmapType:
      {
	char *start = vd->dmp_addr[datid];
	char *end = vd->dmp_addr[datid] + mp->nslots() / BITS_PER_BYTE;
	char *s;
	NS ns, nb, o;

	unsigned long ds = mp->u_bmh_slot_cur()/BITS_PER_BYTE;
	for (s = start + ds, nb = (mp->u_bmh_slot_cur()/BITS_PER_BYTE)*BITS_PER_BYTE, o = 0; s < end; s++, ds++) {
	  if (ds >= x2h_u32(LASTNSBLKALLOC(dbh, datid))) {
	    if (se = nsFileSizeExtends(dbh, datid, ds)) {
	      h2x_epilogue(xmp, mp);
	      return se;
	    }
	  }

	  char v = *s;
	  for (int b = BITS_PER_BYTE-1; b >= 0; b--) {
	    if (!(v & (1 << b))) {
	      if (!o) {
		ns = nb;
	      }
	      o++;
	      if (o > max_free_slots) {
		max_free_slots = o;
	      }

	      if (o == needslots) {
		int obj_count = mp->mstat_u_bmstat_obj_count()++;
			
		mapMark(vd, ns, datid, needslots, 1);

		mp->u_bmh_slot_cur() = nb+1;
		if (nb > mp->u_bmh_slot_lastbusy())
		  mp->u_bmh_slot_lastbusy() = nb;
		mp->u_bmh_retry() = False;
		mp->mstat_u_bmstat_busy_size() += size;
		mp->mstat_u_bmstat_busy_slots() += needslots;
		mp->mstat_u_bmstat_hole_size() += mp->sizeslot() - 
		  (size & ((1 << mp->pow2()-1)));
		h2x_epilogue(xmp, mp);
		*pns = ns;
		//printf("returning %d\n", ns);
		return Success;
	      }
	    } else if (o) {
	      o = 0;
	    }
	    nb++;
	  }
	}
	
	if (!mp->u_bmh_retry()) {
	  mp->u_bmh_retry() = True;
	  mp->u_bmh_slot_cur() = 0;
	  h2x_epilogue(xmp, mp);
	  return mapAllocRealize(dbh, xmp, datid, size, pns, pneedslots, pmax_free_slots);
	}

	h2x_epilogue(xmp, mp);
	*pns = INVALID_NS;
	if (pmax_free_slots)
	  *pmax_free_slots = max_free_slots;
	return Success;
      }

#ifdef LINKMAP_SUPPORT
    case LinkmapType:
      {
	/*#define BEST_FIT*/
	LinkmapCell *top = TOP_CELL(vd, datid);
	int cnt = 0;
	LinkmapCell *cell;
#ifdef BEST_FIT
	LinkmapCell *kcell = 0;
#endif
	int wcell = mp->LMH.firstcell;
	for (cell = &CELL(top, wcell); ; cnt++)
	  {
#ifdef ESM_DBG1
	    printf("CELL 0x%x %d %d %d %d\n", cell, cell->size, cell->ns, cell->prev,
		   cell->next);
#endif
#ifdef BEST_FIT
	    if (cell->size == needslots)
	      {
		NS ns = cell->ns;
		cellFree(vd, cell);
		*pns = ns;
		return Success;
	      }
	    else if (!kcell && cell->size > needslots)
	      kcell = cell;
#else
	    if (cell->size >= needslots)
	      {
		NS ns = cell->ns, n_size, n_ns;

		n_size = cell->size - needslots;
		n_ns = cell->ns + needslots;

		cellFree(vd, datid, cell);

		if (n_size > 0)
		  cellInsert(vd, n_ns, datid, n_size);

#ifdef ESM_DBG1
		printf("linkmap mapAlloc: %d loops for %d\n", cnt, needslots);
#endif
		*pns = ns;
		return Success;
	      }
#endif

	    if ((wcell = cell->next) == InvalidCell)
	      {
#ifdef BEST_FIT
		if (kcell)
		  {
		    NS ns = kcell->ns, n_size, n_ns;

		    n_size = kcell->size - needslots;
		    n_ns = kcell->ns + needslots;

		    cellFree(vd, kcell);

		    if (n_size > 0)
		      cellInsert(vd, n_ns, n_size);

		    *pns = ns;
		    return Success;
		  }
		else
#endif
		  {
		    *pns = INVALID_NS;
		    return Success;
		  }
	      }
	    cell = &CELL(top, wcell);
	  }
      }
#endif

    default:
      ESM_ASSERT_ABORT(0, 0, 0);
    }

    h2x_epilogue(xmp, mp);
    *pns = INVALID_NS;
    return Success;
  }

  Status
  mapAlloc(DbHandle const *dbh, short datid, size_t size, NS *pns, NS *pneedslots, NS *pmax_free_slots)
  {
    MapHeader t_mp = DAT2MP(dbh, datid);
    MapHeader *mp = &t_mp;

    Mutex *mt = MAP_MTX(dbh);
    unsigned int xid = dbh->vd->xid;
    Status se;
    TransactionContext *trctx = DBH2TRCTX(dbh);

    if (NEED_LOCK(trctx))
      MUTEX_LOCK_VOID(mt, xid);
    se = mapAllocRealize(dbh, mp, datid, size, pns, pneedslots, pmax_free_slots);
    if (NEED_LOCK(trctx))
      MUTEX_UNLOCK(mt, xid);

    return se;
  }

  void
  mapFree(DbDescription *vd, NS ns, short datid, size_t size)
  {
    MapHeader t_mp = DAT2MP_(vd, datid);
    MapHeader *xmp = &t_mp;
    x2h_prologue(xmp, mp);

    int needslots = SZ2NS(size, mp);

    switch(mp->mtype())
      {
      case BitmapType:
	mapMark(vd, ns, datid, needslots, 0);
	mp->mstat_u_bmstat_obj_count()--;
	mp->mstat_u_bmstat_busy_size() -= size;
	mp->mstat_u_bmstat_busy_slots() -= needslots;
	mp->mstat_u_bmstat_hole_size() -= mp->sizeslot() - 
	  (size & ((1 << mp->pow2())-1));
	break;

#ifdef LINKMAP_SUPPORT
      case LinkmapType:
	cellInsert(vd, ns, datid, needslots);
	break;
#endif

      default:
	ESM_ASSERT_ABORT(0, 0, 0);
      }

    //printf("Ns free [%d, %d[\n", ns, ns+needslots);
    h2x_epilogue(xmp, mp);
  }

#define MARK_OPTIM
  //#define MARK_SECURE

  void
  mapMark(DbDescription *vd, NS ns, short datid, size_t needslots, int value)
  {
    MapHeader t_mp = DAT2MP_(vd, datid);
    MapHeader *mp = &t_mp;
    char *s;
    char *start = vd->dmp_addr[datid];
    char *end = vd->dmp_addr[datid] + x2h_u32(mp->nslots()) / BITS_PER_BYTE;
    size_t o = 0;
    size_t nb;

    //printf("marking %s from ns=%d\n", value ? "busy" : "free", ns);
    for (s = start + ns/BITS_PER_BYTE, nb = (ns/BITS_PER_BYTE)*BITS_PER_BYTE; s < end; s++) {
      // 27/05/02: optimized by writing directly *s = 0xff
      // when BITS_PER_BYTE ...
#ifdef MARK_OPTIM
      if (needslots - o > BITS_PER_BYTE && nb >= ns) {
	//printf("optimisation %d %d %d %d\n", needslots, o, nb, ns);
	if (value) {
#ifdef MARK_SECURE
	  assert(!*s);
#endif
	  *s = 0xff;
	}
	else {
#ifdef MARK_SECURE
	  assert(*s == 0xff);
#endif
	  *s = 0;
	}
	o += BITS_PER_BYTE;
	nb += BITS_PER_BYTE;
      }
      else
#endif
	for (int b = BITS_PER_BYTE-1; b >= 0; b--) {
	  if (o >= needslots)
	    return;

	  if (nb >= ns) {
	    if (value) {
#ifdef MARK_SECURE
	      assert(!(*s & (1 << b)));
#endif
	      *s |= (1 << b);
	    }
	    else {
#ifdef MARK_SECURE
	      if (!(*s & (1 << b)))
		printf("start = %p, end = %p, needslots = %d, nb = %d, "
		       "ns = %d, o = %d, *start = %d, *s = %d\n",
		       start, end, needslots, nb, ns, o, *start, *s);
	      assert((*s & (1 << b)));
#endif
	      *s &= ~(1 << b);
	    }
	    o++;
	  }
	  nb++;
	}
    }
  }

  // born again from idb 1994 version
  NS
  mapNextBusyGet(DbDescription *vd, short datid, NS ns)
  {
    MapHeader t_mp = DAT2MP_(vd, datid);
    MapHeader *mp = &t_mp;
    char *s, *start = vd->dmp_addr[datid],
      *end = vd->dmp_addr[datid] + x2h_u32(mp->nslots()) / BITS_PER_BYTE;
    int nb, b, o = 0;

    size_t lastbusy = x2h_u32(mp->u_bmh_slot_lastbusy());
    for (s = start + ns/BITS_PER_BYTE,
	   nb = (ns/BITS_PER_BYTE)*BITS_PER_BYTE; s < end; s++)
      {
	// EV patch 26/04/07
	if (nb >= lastbusy)
	  return INVALID_NS;

	char v = *s;
	for (b = BITS_PER_BYTE-1; b >= 0; b--)
	  {
	    if (nb >= ns && (v & (1 << b)))
	      return nb;
	    nb++;
	  }
      }

    return INVALID_NS;
  }

  Status
  ESM_firstOidGet_map(DbHandle const *dbh, short datid, Oid *oid,
		      Boolean *found)
  {
    *found = False;

    if (!check_dbh(dbh))
      return statusMake_s(INVALID_DB_HANDLE);

    DbHeader _dbh(DBSADDR(dbh));
    if (getDatType(&_dbh, datid) != PhysicalOidType)
      return statusMake(ERROR, "cannot use firstOidGet() on a logical "
			"oid type based datafile");

    NS ns;
    if ((ns = mapNextBusyGet(dbh->vd, datid, 0)) == INVALID_NS)
      return Success;

    OidLoc oidloc;

    oidloc.ns = ns;
    oidloc.datid = datid;

    Status s = oidCopySlot_(dbh, oidloc.ns, oidloc, oid, 0);
    if (s) {
      return s;
    }

    // 4/10/05
    oid->setNX(oid->getNX() + NS_OFFSET);

    *found = True;
    return Success;
  }

  Status
  ESM_nextOidGet_map(DbHandle const *dbh, short datid,
		     Oid const *const baseoid, Oid *nextoid,
		     Boolean *found)
  {
    *found = False;

    if (!check_dbh(dbh))
      return statusMake_s(INVALID_DB_HANDLE);

    if (!check_oid(dbh, baseoid))
      return statusMake_s(INVALID_OID);

    DbHeader _dbh(DBSADDR(dbh));
    if (getDatType(&_dbh, datid) != PhysicalOidType)
      return statusMake(ERROR, "cannot use firstOidGet() on a logical "
			"oid type based datafile");

    OidLoc oidloc;
    oidloc.datid = datid;

    oidloc.ns = baseoid->getNX() - NS_OFFSET;

    NS ns = oidLastSlotGet(dbh, oidloc);

    if ((ns = mapNextBusyGet(dbh->vd, datid, ns + 1)) == INVALID_NS)
      return Success;

    oidloc.ns = ns;
    Status s = oidCopySlot_(dbh, oidloc.ns, oidloc, nextoid, 0);
    if (s) {
      return s;
    }
    nextoid->setNX(nextoid->getNX() + NS_OFFSET);

    *found = True;
    return Success;
  }

#ifdef LINKMAP_SUPPORT
  void
  ESM_cellsTrace(DbHandle *dbh)
  {
    unsigned int ndat = x2h_u32(DBSADDR(dbh)->__ndat);
    for (int i = 0; i < ndat; i++)
      if (isDatValid(dbh, i))
	ESM_cellsTraceRealize(dbh, i);
  }
#endif
}
