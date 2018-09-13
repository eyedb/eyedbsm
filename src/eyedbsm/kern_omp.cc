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

#include "kern_p.h"

//#define NX_TRACE
//#define DSP_INVALID_OID
#define SKIP_NX_LOCK

namespace eyedbsm {

  void stop_now()
  {
    int a = 1;
  }

Status oidCopySlot_(DbHandle const *dbh, Oid::NX nx, const OidLoc &oidloc, Oid *oid, size_t *psize)
{
  MmapH hdl;
  ObjectHeader *objh;

  if (nx == 79) {
    stop_now();
  }
  objh = (ObjectHeader *)
    slot2addr(dbh, oidloc.ns, oidloc.datid,
		 sizeof(ObjectHeader), (char **)&objh, &hdl, 0);
  if (!objh) {
    return statusMake(INVALID_OID, "cannot map object ns=%u, datid=%d", oidloc.ns, oidloc.datid);
  }
  oid->setNX(nx);

  //oid->setUnique(x2h_u32(objh->unique));
  if (isV3(dbh)) {
    oid->setUnique(x2h_u32(objh->objh_v3.unique));
  } else {
    oid->setUnique(x2h_u32(objh->objh_v2.unique));
  }

  if (psize) {
    //*psize = x2h_u32(objh->size);
    if (isV3(dbh)) {
      *psize = x2h_u64(objh->objh_v3.size);
    } else {
      *psize = x2h_u32(objh->objh_v2.size);
    }
  }

  /*
  printf("UNIQUE %u %u size=%d ns=%d datid=%d\n", oid->unique, objh->unique,
	 objh->size, oidloc.ns, oidloc.datid);
  */
  hdl_release(&hdl);
  OIDDBIDMAKE(oid, dbh->vd->dbid);
  return Success;
}

Status oidCopySlot(DbHandle const *dbh, Oid::NX nx, Oid *oid, size_t *psize)
{
  return oidCopySlot_(dbh, nx, oidLocGet_(dbh, nx), oid, psize);
}

NS oidLastSlotGet(DbHandle const *dbh, const OidLoc &oidloc)
{
  MapHeader t_mp = DAT2MP(dbh, oidloc.datid);
  MapHeader *mp = &t_mp;

  MmapH hdl;
  ObjectHeader *objh;

  objh = (ObjectHeader *)
    slot2addr(dbh, oidloc.ns, oidloc.datid,
		 sizeof(ObjectHeader), (char **)&objh, &hdl, 0);

  NS lastslot;
  //NS lastslot = SZ2NS_XDR(x2h_u32(objh->size), mp) - 1 + oidloc.ns;
  if (isV3(dbh)) {
    lastslot = SZ2NS_XDR(x2h_u64(objh->objh_v3.size), mp) - 1 + oidloc.ns;
  } else {
    lastslot = SZ2NS_XDR(x2h_u64(objh->objh_v2.size), mp) - 1 + oidloc.ns;
  }

  hdl_release(&hdl);
  return lastslot;
}

Status
nxAlloc(DbHandle const *const dbh, const OidLoc &oidloc_, Oid::NX *pnx)
{
  Mutex *mt = NX_MTX(dbh);
  unsigned int xid = dbh->vd->xid;
  Oid::NX i;
  Oid::NX start, end;
  TransactionContext *trctx = DBH2TRCTX(dbh);

  if (NEED_LOCK(trctx))
    MUTEX_LOCK_VOID(mt, xid);

  start = x2h_u32(CURIDXBUSY(dbh));
  end = x2h_u32(DbHeader(DBSADDR(dbh)).__nbobjs());

  for (;;) {
    void *omp_addr = OIDLOC(dbh->vd->omp_addr, start);
    for (i = start; i < end; i++) {
      if (i >= x2h_u32(LASTIDXBLKALLOC(dbh))) {
	Status se;
	if (se = nxFileSizeExtends(dbh, i)) {
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mt, xid);
	  return se;
	}

      }

      OidLoc oidloc;
      x2h_oidloc(&oidloc, omp_addr);
      if (!oidloc.ns) {
	oidloc.ns = oidloc_.ns+NS_OFFSET;
	oidloc.datid = oidloc_.datid;
#ifdef NX_TRACE
	printf("nxAlloc(%d) -> %d %d\n", i, oidloc_.ns, oidloc_.datid);
#endif
	assert(oidloc.datid >= 0);
	if (x2h_u32(LASTIDXBUSY(dbh)) < i+1) {
	  LASTIDXBUSY(dbh) = h2x_u32(i+1);
	}

	CURIDXBUSY(dbh) = h2x_u32(i+1);
	h2x_oidloc(omp_addr, &oidloc);

	if (NEED_LOCK(trctx))
	  MUTEX_UNLOCK(mt, xid);

	*pnx = i;
	return Success;
      }
      omp_addr = NEXT_OIDLOC(omp_addr);
    }

    if (!start)	{
      CURIDXBUSY(dbh) = h2x_u32(i);
      if (NEED_LOCK(trctx))
	MUTEX_UNLOCK(mt, xid);
      *pnx = Oid::INVALID_NX;
      return Success;
    }
    
    // changed the 21/08/01 (and improved after) because of a catastrophic
    // performance in EMBL import when object number limit has been reached!

    CURIDXBUSY(dbh) = 0;
    start = 0;
    end = x2h_u32(LASTIDXBUSY(dbh));
  }

  return Success;
}

void
nxFree(DbHandle const *const dbh, Oid::NX nx)
{
  Mutex *mt = NX_MTX(dbh);
  unsigned int xid = dbh->vd->xid;
  OidLoc oidloc;
  TransactionContext *trctx = DBH2TRCTX(dbh);

#ifndef SKIP_NX_LOCK
  //printf("nxFree:: locking NX\n");
  if (NEED_LOCK(trctx))
    MUTEX_LOCK_VOID(mt, xid);
#endif

  oidloc.ns = 0;
  oidloc.datid = -1;

  h2x_oidloc(OIDLOC(dbh->vd->omp_addr, nx), &oidloc);

#ifdef NX_TRACE
  printf("nxFree(%d)\n", nx);
#endif

#ifndef SKIP_NX_LOCK
  if (NEED_LOCK(trctx))
    MUTEX_UNLOCK(mt, xid);
#endif
}

void
nxSet(DbHandle const *const dbh, Oid::NX nx, NS ns, short datid)
{
  Mutex *mt = NX_MTX(dbh);
  unsigned int xid = dbh->vd->xid;
  OidLoc oidloc;
  TransactionContext *trctx = DBH2TRCTX(dbh);

#ifndef SKIP_NX_LOCK
  //printf("nxSet: locking NX\n");
  if (NEED_LOCK(trctx))
    MUTEX_LOCK_VOID(mt, xid);
#endif

  oidloc.ns = ns+NS_OFFSET;
  oidloc.datid = datid;

  h2x_oidloc(OIDLOC(dbh->vd->omp_addr, nx), &oidloc);

#ifdef NX_TRACE
  printf("nxSet(%d) -> %d %d\n", nx, ns, datid);
#endif

#ifndef SKIP_NX_LOCK
  if (NEED_LOCK(trctx))
    MUTEX_UNLOCK(mt, xid);
#endif
}

Oid::NX
nxNextBusyGet(DbHandle const *const dbh, Oid::NX nx)
{
  Oid::NX lastidxbusy, i;
  Mutex *mt = NX_MTX(dbh);
  unsigned int xid = dbh->vd->xid;
  TransactionContext *trctx = DBH2TRCTX(dbh);

  if (NEED_LOCK(trctx))
    MUTEX_LOCK_VOID(mt, xid);

  lastidxbusy = x2h_u32(LASTIDXBUSY(dbh));

  void *omp_addr = OIDLOC(dbh->vd->omp_addr, nx);
  for (i = nx; i < lastidxbusy; i++)
    {
      OidLoc oidloc;
      x2h_oidloc(&oidloc, omp_addr);

      if (oidloc.ns)
	{
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mt, xid);
	  return i;
	}
      omp_addr = NEXT_OIDLOC(omp_addr);
    }

  if (NEED_LOCK(trctx))
    MUTEX_UNLOCK(mt, xid);
  return Oid::INVALID_NX;
}

Status
ESM_objectLocationGet(DbHandle const *dbh, const Oid *oid, ObjectLocation *objloc)
{
  OidLoc oidloc = oidLocGet(dbh, oid);
  if (oidloc.ns == INVALID_NS)
    return statusMake(INVALID_OID, "oid %s is invalid",
			 getOidString(oid));
  size_t size; // V3_API_size_t
  // EV : 9/03/06 changed LockS to DefaultLock
  //Status s = ESM_objectSizeGet(dbh, &size, LockS, oid, OPDefault);
  Status s = ESM_objectSizeGet(dbh, &size, DefaultLock, oid, OPDefault);
  if (s) return s;

  DbHeader _dbh(DBSADDR(dbh));
  unsigned int sizeslot = x2h_u32(_dbh.dat(oidloc.datid).mp()->sizeslot());
  unsigned long long offset = oidloc.ns * sizeslot;

  //objloc->is_valid = isValidObject(size) ? True : False;
  if (isV3(dbh)) {
    objloc->is_valid = isValidObject_v3(size) ? True : False;
  } else {
    objloc->is_valid = isValidObject_v2(size) ? True : False;
  }

  if (!objloc->is_valid)
    objloc->size = 0;
  else
    objloc->size = size;
  size += sizeof(ObjectHeader); // added the 26/07/01
  objloc->datid = oidloc.datid;
  objloc->dspid = getDataspace(&_dbh, oidloc.datid);
  objloc->slot_start_num = oidloc.ns;
  objloc->slot_end_num = oidloc.ns + (size-1)/sizeslot;
  size_t nsize = (objloc->slot_end_num - objloc->slot_start_num + 1) * sizeslot;
  objloc->dat_start_pagenum = offset>>pgsize_pow2;
  objloc->dat_end_pagenum = (offset+nsize-1)>>pgsize_pow2;
  if (isPhy(dbh, oid)) {
    objloc->omp_start_pagenum = ~0;
    objloc->omp_end_pagenum = ~0;
  } else {
    objloc->omp_start_pagenum = (oid->getNX() * OIDLOCSIZE)>>pgsize_pow2;
    objloc->omp_end_pagenum = (((oid->getNX() * OIDLOCSIZE)+OIDLOCSIZE)-1)>>pgsize_pow2;
  }
  objloc->dmp_start_pagenum = ((objloc->slot_start_num)/8)>>pgsize_pow2;
  objloc->dmp_end_pagenum = (((objloc->slot_end_num)/8))>>pgsize_pow2;
  return Success;
}

Status
ESM_objectsLocationGet(DbHandle const *dbh, const Oid *oid, ObjectLocation *objloc, unsigned int oid_cnt)
{
  Status s;
  for (int i = 0; i < oid_cnt; i++)
    if (s = ESM_objectLocationGet(dbh, &oid[i], &objloc[i]))
      return s;

  return Success;
}

OidLoc
oidLocGet(DbHandle const *const dbh, const Oid *oid)
{
  if (isPhy(dbh, oid)) {
    OidLoc oidloc;
    getPhyInfo(oid, &oidloc.ns, &oidloc.datid);
    return oidloc;
  }
  return oidLocGet_(dbh, oid->getNX());
}

OidLoc
oidLocGet_(DbHandle const *const dbh, Oid::NX nx)
{
  Mutex *mt = NX_MTX(dbh);
  unsigned int xid = dbh->vd->xid;
  NS ns;
  TransactionContext *trctx = DBH2TRCTX(dbh);

  /* lock is really needed?? */
#ifndef SKIP_NX_LOCK
  //printf("oidLocGet_:: locking NX\n");
  if (NEED_LOCK(trctx))
    MUTEX_LOCK_VOID(mt, xid);
#endif

  OidLoc oidloc;
  memset(&oidloc, 0, sizeof(oidloc)); // added the 21/05/01 to make purify happy

  if (nx == Oid::INVALID_NX || nx > x2h_u32(LASTIDXBUSY(dbh)))
    {
#ifndef SKIP_NX_LOCK
      if (NEED_LOCK(trctx))
	MUTEX_UNLOCK(mt, xid);
#endif
      oidloc.ns = INVALID_NS;
      oidloc.datid = -1;
      return oidloc;
    }

  x2h_oidloc(&oidloc, OIDLOC(dbh->vd->omp_addr, nx));

  oidloc.ns -= NS_OFFSET;

#ifndef SKIP_NX_LOCK
  if (NEED_LOCK(trctx))
    MUTEX_UNLOCK(mt, xid);
#endif

#if 0
  if (oidloc.datid < 0)
    {
      printf("very strange oidloc [%p] 0x%x, %d for nx=%d\n",
	     dbh->vd->omp_addr, oidloc.ns, oidloc.datid, nx);
      for (int i = nx-1; i >= nx-40; i--) {
	x2h_oidloc(&oidloc, OIDLOC(dbh->vd->omp_addr, i));
	if (oidloc.datid < 0)
	  printf("-> very strange oidloc [%p] 0x%x, %d for nx=%d\n",
		 dbh->vd->omp_addr, oidloc.ns, oidloc.datid, i);
	else
	  printf("-> ok for nx=%d\n", i);
      }
    }
  else
    printf("oidloc [%p] 0x%x, %d for nx=%d\n",
	   dbh->vd->omp_addr, oidloc.ns, oidloc.datid, nx);
#endif
  return oidloc;
}

void
ESM_oidsTrace(DbHandle const *const dbh, ESM_oidsTraceAction action, FILE *fd)
{
  //DbHeader *h = dbh->vd->dbs_addr;
  void *omp_addr = dbh->vd->omp_addr;
  int cnt = 0;
  Oid oid, nextoid;
  Boolean found;

  ESM_firstOidGet_omp(dbh, &oid, &found);

  while (found)
    {
      if (action == ESM_allOids)
	fprintf(fd, "%s\n", getOidString(&oid));
      cnt++;
      ESM_nextOidGet_omp(dbh, &oid, &nextoid, &found);
      oid = nextoid;
    }

  fprintf(fd, "Total Oid Count   %d\n", cnt);
}

Status
ESM_nextOidGetDat_omp(DbHandle const *dbh, short datid,
		     Oid *nextoid, Boolean *found)
{
  for (;;) {
    OidLoc oidloc = oidLocGet(dbh, nextoid);
    if (oidloc.datid == datid) {
      *found = True;
      return Success;
    }

    Status s = ESM_nextOidGet_omp(dbh, nextoid, nextoid, found);
    if (s || !*found) return s;
  }
}

Status
ESM_firstOidDatGet(DbHandle const *dbh, short datid, Oid *oid,
		  Boolean *found)
{
  DbHeader _dbh(DBSADDR(dbh));
  if (getDatType(&_dbh, datid) == PhysicalOidType)
    return ESM_firstOidGet_map(dbh, datid, oid, found);
  
  Status s = ESM_firstOidGet_omp(dbh, oid, found);
  if (s || !*found) return s;
  return ESM_nextOidGetDat_omp(dbh, datid, oid, found);
}

Status
ESM_nextOidDatGet(DbHandle const *dbh, short datid,
		 Oid const *const baseoid,
		 Oid *nextoid, Boolean *found)
{
  DbHeader _dbh(DBSADDR(dbh));
  if (getDatType(&_dbh, datid) == PhysicalOidType)
    return ESM_nextOidGet_map(dbh, datid, baseoid, nextoid, found);

  Status s = ESM_nextOidGet_omp(dbh, baseoid, nextoid, found);
  if (s || !*found) return s;
  return ESM_nextOidGetDat_omp(dbh, datid, nextoid, found);
}

Status
ESM_firstOidGet_omp(DbHandle const *dbh, Oid *oid, Boolean *found)
{
  Oid::NX nx;

  *found = False;

  if (!check_dbh(dbh))
    return statusMake_s(INVALID_DB_HANDLE);

  if ((nx = nxNextBusyGet(dbh, 0)) == Oid::INVALID_NX)
    return Success;

  Status s = oidCopySlot(dbh, nx, oid, 0);
  if (s) {
    return s;
  }
  *found = True;
  return Success;
}

Status
ESM_nextOidGet_omp(DbHandle const *dbh, Oid const *const baseoid,
		   Oid *nextoid, Boolean *found)
{
  Oid::NX nx;

  *found = False;
  if (!check_dbh(dbh))
    return statusMake_s(INVALID_DB_HANDLE);

  if (!check_oid(dbh, baseoid))
    return statusMake(INVALID_OID, "%s", getOidString(baseoid));

  if ((nx = nxNextBusyGet(dbh, baseoid->getNX()+1)) == Oid::INVALID_NX)
    return Success;

  Status s = oidCopySlot(dbh, nx, nextoid, 0);
  if (s) {
    return s;
  }
  *found = True;
  return Success;
}

static int no_unique_check = getenv("NO_UNIQUE_CHECK") ? 1 : 0;

ObjectHeader *
oid2objh_(const Oid *oid, NS ns, short datid, const DbHandle *dbh,
	     ObjectHeader **objh, MmapH *hdl, size_t *up,
	     Boolean *oid2addr_failed)
{
  ObjectHeader *hdr;
  ObjectHeader *xobjh = (ObjectHeader *)
    oid2addr_(ns, datid, dbh, sizeof(ObjectHeader), objh, hdl, up);

  *oid2addr_failed = (xobjh ? False : True);

  /*
  printf("UNIQUE_1 %x %x %x\n", xobjh->unique, x2h_u32(xobjh->unique),
	 oid->unique);
  */

  //hdr = (!xobjh || (x2h_u32(xobjh->unique) != oid->getUnique()) ? 0 : xobjh);
  if (isV3(dbh)) {
    hdr = (!xobjh || (x2h_u32(xobjh->objh_v3.unique) != oid->getUnique()) ? 0 : xobjh);
  } else {
    hdr = (!xobjh || (x2h_u32(xobjh->objh_v2.unique) != oid->getUnique()) ? 0 : xobjh);
  }

  if (!hdr) {
    //IDB_LOG(IDB_LOG_MMAP, ("invalid oid: uniques differ: %u %u\n", x2h_u32(xobjh->unique), oid->getUnique()));
    if (isV3(dbh)) {
      IDB_LOG(IDB_LOG_MMAP, ("invalid oid: uniques differ: %u %u\n", x2h_u32(xobjh->objh_v3.unique), oid->getUnique()));
    } else {
      IDB_LOG(IDB_LOG_MMAP, ("invalid oid: uniques differ: %u %u\n", x2h_u32(xobjh->objh_v2.unique), oid->getUnique()));
    }
#ifdef DSP_INVALID_OID
    display_invalid_oid(oid, xobjh);
#endif
    if (no_unique_check)
      hdr = xobjh;
  }

  if (!hdr && xobjh) {
    hdl_release(hdl);
  }
  return hdr;
}

ObjectHeader *
oid2objh(const Oid *oid, const DbHandle *dbh, ObjectHeader **objh,
	    MmapH *hdl, Boolean *oid2addr_failed)
{
  ObjectHeader *hdr;
  ObjectHeader *xobjh = (ObjectHeader *)
    oid2addr(oid, dbh, sizeof(ObjectHeader), objh, hdl);

  *oid2addr_failed = (xobjh ? False : True);

  //hdr = (!xobjh || (x2h_u32(xobjh->unique) != oid->getUnique()) ? 0 : xobjh);
  if (isV3(dbh)) {
    hdr = (!xobjh || (x2h_u32(xobjh->objh_v3.unique) != oid->getUnique()) ? 0 : xobjh);
  } else {
    hdr = (!xobjh || (x2h_u32(xobjh->objh_v2.unique) != oid->getUnique()) ? 0 : xobjh);
  }
#ifdef DSP_INVALID_OID
  if (!hdr)
    display_invalid_oid(oid, xobjh);
#endif

  if (!hdr && xobjh)
    hdl_release(hdl);
  return hdr;
}

int
check_oid(const DbHandle *dbh, const Oid *oid)
{
  OidLoc oidloc = oidLocGet(dbh, oid);
  if (oidloc.ns == INVALID_NS || !isDatValid(dbh, oidloc.datid) ||
      OIDDBIDGET(oid) != dbh->vd->dbid)
    return 0;
  return 1;
}

extern int
oidloc_cmp(const OidLoc &ol1, const OidLoc &ol2)
{
  return ol1.ns == ol2.ns && ol1.datid == ol2.datid;
}

}
