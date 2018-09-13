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

#define NEW_OID_CODE

namespace eyedbsm {

  void x2h_oidloc(OidLoc *oidloc, const void *addr)
  {
    memcpy(oidloc, addr, OIDLOCSIZE);
#ifndef EYEDBLIB_BIG_ENDIAN
    oidloc->ns = x2h_u32(oidloc->ns);
    //oidloc->ns = x2h_u64(oidloc->ns);
    oidloc->datid = x2h_16(oidloc->datid);
#endif
  }

  // #2 argument is conceptually constant
  void h2x_oidloc(void *addr, OidLoc *oidloc)
  {
#ifndef EYEDBLIB_BIG_ENDIAN
    oidloc->ns = h2x_u32(oidloc->ns);
    //oidloc->ns = h2x_u64(oidloc->ns);
    oidloc->datid = h2x_16(oidloc->datid);
#endif
    memcpy(addr, oidloc, OIDLOCSIZE);
  }

  struct OidCode {
    unsigned int x[2];
  };

  void x2h_oid(Oid *hoid, const void *xoid)
  {
#ifndef EYEDBLIB_BIG_ENDIAN

#ifdef NEW_OID_CODE
    OidCode o;
    memcpy(&o, xoid, sizeof(o));

    o.x[0] = x2h_u32(o.x[0]);
    o.x[1] = x2h_u32(o.x[1]);

    hoid->setNX(o.x[0]);
    hoid->setDbID((o.x[1] >> Oid_UNIQUE) & 0x3ff);
    hoid->setUnique(o.x[1] & 0x3fffff);

#else
    unsigned long long l = 0;
    memcpy(&l, xoid, sizeof(l));
    l = x2h_u64(l);

    hoid->setNX(l >> Oid_NX);
    hoid->setDbID((l >> Oid_UNIQUE) & 0x3ff);
    hoid->setUnique(l & 0x3fffff);
#endif


#else
    if (hoid != xoid)
      memcpy(hoid, xoid, sizeof(Oid));
#endif
  }

  void h2x_oid(void *xoid, const Oid *hoid)
  {
#ifndef EYEDBLIB_BIG_ENDIAN

#ifdef NEW_OID_CODE
    OidCode o;
    o.x[0] = h2x_u32(hoid->getNX());
    o.x[1] = h2x_u32(hoid->getDbID() << Oid_UNIQUE | hoid->getUnique());

    memcpy(xoid, &o, sizeof(o));
#else
    unsigned long long l = h2x_u64(((unsigned long long)hoid->getNX() << Oid_NX |
				    hoid->getDbID() << Oid_UNIQUE | hoid->getUnique()));
    memcpy(xoid, &l, sizeof(l));
#endif

#else
    if (hoid != xoid)
      memcpy(xoid, hoid, sizeof(Oid));

#endif
  }

  void x2h_oids(Oid *hoid, const void *xoid, unsigned int cnt)
  {
#ifdef EYEDBLIB_BIG_ENDIAN
    if (hoid != xoid)
#endif
      for (int i = 0; i < cnt; i++)
	x2h_oid(&hoid[i], (char *)xoid+i*sizeof(Oid)); //, &xoid[i]);
  }

  void h2x_oids(void *xoid, const Oid *hoid, unsigned int cnt)
  {
#ifdef EYEDBLIB_BIG_ENDIAN
    if (hoid != xoid)
#endif
      for (int i = 0; i < cnt; i++)
	h2x_oid((char *)xoid+i*sizeof(Oid), &hoid[i]);
  }

  int cmp_oid(const void *xoid, const Oid *hoid)
  {
    Oid hoid_t;
    x2h_oid(&hoid_t, xoid);
    return memcmp(&hoid_t, hoid, sizeof(Oid));
  }

  int cmp_oids(const void *xoid, const Oid *hoid, unsigned int cnt)
  {
    for (int i = 0; i < cnt; i++) {
      Oid hoid_t;
      x2h_oid(&hoid_t, (char *)xoid+i*sizeof(Oid));
      int r = memcmp(&hoid_t, &hoid[i], sizeof(Oid));
      if (r) return r;
    }
  
    return 0;
  }

  unsigned int x2h_getSize_v2(unsigned int size)
  {
    return getSize_v2(x2h_u32(size));
  }

  unsigned int x2h_makeValid_v2(unsigned int size)
  {
    return makeValid_v2(x2h_u32(size));
  }

  size_t x2h_getSize_v3(size_t size)
  {
    return getSize_v3(x2h_u64(size));
  }

  size_t x2h_makeValid_v3(size_t size)
  {
    return makeValid_v3(x2h_u64(size));
  }

  void x2h_mapHeader(MapHeader *hmap, const MapHeader *_xmap)
  {
    MapHeader *xmap = const_cast<MapHeader *>(_xmap);
    hmap->mtype() = x2h_16(xmap->mtype());
    hmap->sizeslot() = x2h_u32(xmap->sizeslot());
    hmap->pow2() = x2h_u32(xmap->pow2());
    hmap->nslots() = x2h_u32(xmap->nslots());
    hmap->nbobjs() = x2h_u32(xmap->nbobjs());
    hmap->mstat_mtype() = x2h_16(xmap->mstat_mtype());

    if (hmap->mtype() == BitmapType) {
      hmap->u_bmh_slot_cur() = x2h_u32(xmap->u_bmh_slot_cur());
      hmap->u_bmh_slot_lastbusy() = x2h_u32(xmap->u_bmh_slot_lastbusy());
      hmap->u_bmh_retry() = x2h_u16(xmap->u_bmh_retry());

      hmap->mstat_u_bmstat_obj_count() = x2h_u32(xmap->mstat_u_bmstat_obj_count());
      hmap->mstat_u_bmstat_busy_slots() = x2h_u32(xmap->mstat_u_bmstat_busy_slots());
      hmap->mstat_u_bmstat_busy_size() = x2h_u64(xmap->mstat_u_bmstat_busy_size());
      hmap->mstat_u_bmstat_hole_size() = x2h_u64(xmap->mstat_u_bmstat_hole_size());
    }
    else if (hmap->mtype() == LinkmapType) {
      abort();
    }
    else
      abort();
  }

  void h2x_mapHeader(MapHeader *xmap, const MapHeader *_hmap)
  {
    MapHeader *hmap = const_cast<MapHeader *>(_hmap);
    unsigned short mtype = hmap->mtype();
    xmap->mtype() = h2x_16(hmap->mtype());
    xmap->sizeslot() = h2x_u32(hmap->sizeslot());
    xmap->pow2() = h2x_u32(hmap->pow2());
    xmap->nslots() = h2x_u32(hmap->nslots());
    xmap->nbobjs() = h2x_u32(hmap->nbobjs());
    xmap->mstat_mtype() = h2x_16(hmap->mstat_mtype());

    if (mtype == BitmapType) {
      xmap->u_bmh_slot_cur() = h2x_u32(hmap->u_bmh_slot_cur());
      xmap->u_bmh_slot_lastbusy() = h2x_u32(hmap->u_bmh_slot_lastbusy());
      xmap->u_bmh_retry() = h2x_u16(hmap->u_bmh_retry());

      xmap->mstat_u_bmstat_obj_count() = h2x_u32(hmap->mstat_u_bmstat_obj_count());
      xmap->mstat_u_bmstat_busy_slots() = h2x_u32(hmap->mstat_u_bmstat_busy_slots());
      xmap->mstat_u_bmstat_busy_size() = h2x_u64(hmap->mstat_u_bmstat_busy_size());
      xmap->mstat_u_bmstat_hole_size() = h2x_u64(hmap->mstat_u_bmstat_hole_size());
    }
    else if (mtype == LinkmapType) {
      abort();
    }
    else
      abort();
  }

  void x2h_datafileDesc(DatafileDesc *hdat,
			const DatafileDesc *_xdat)
  {
    DatafileDesc *xdat = const_cast<DatafileDesc *>(_xdat);
    hdat->__maxsize() = x2h_u32(xdat->__maxsize());
    x2h_mapHeader(hdat->mp(), xdat->mp());
    hdat->__lastslot() = x2h_u32(xdat->__lastslot());
    unsigned short __dspid = xdat->__dspid();
    hdat->__dspid() = x2h_16(xdat->__dspid());

    memcpy(hdat->file(), xdat->file(), L_FILENAME);
    memcpy(hdat->name(), xdat->name(), L_NAME+1);
  }

  void h2x_datafileDesc(DatafileDesc *xdat,
			const DatafileDesc *_hdat)
  {
    DatafileDesc *hdat = const_cast<DatafileDesc *>(_hdat);
    xdat->__maxsize() = h2x_u32(hdat->__maxsize());
    h2x_mapHeader(xdat->mp(), hdat->mp());
    xdat->__lastslot() = h2x_u32(hdat->__lastslot());
    unsigned short __dspid = hdat->__dspid();
    xdat->__dspid() = h2x_16(hdat->__dspid());

    memcpy(xdat->file(), hdat->file(), L_FILENAME);
    memcpy(xdat->name(), hdat->name(), L_NAME+1);
  }


  void x2h_dataspaceDesc(DataspaceDesc *hdsp,
			 const DataspaceDesc *_xdsp)
  {
    DataspaceDesc *xdsp = const_cast<DataspaceDesc *>(_xdsp);
    hdsp->__cur() = x2h_32(xdsp->__cur());
    hdsp->__ndat() = x2h_32(xdsp->__ndat());
    for (int i = 0; i < hdsp->__ndat(); i++)
      hdsp->__datid(i) = x2h_16(xdsp->__datid(i));

    memcpy(hdsp->name(), xdsp->name(), L_NAME+1);
  }

  void h2x_dataspaceDesc(DataspaceDesc *xdsp,
			 const DataspaceDesc *_hdsp)
  {
    DataspaceDesc *hdsp = const_cast<DataspaceDesc *>(_hdsp);
    unsigned int ndat = hdsp->__ndat();

    xdsp->__cur() = h2x_32(hdsp->__cur());
    xdsp->__ndat() = h2x_32(hdsp->__ndat());
    for (int i = 0; i < ndat; i++)
      xdsp->__datid(i) = h2x_16(hdsp->__datid(i));

    memcpy(xdsp->name(), hdsp->name(), L_NAME+1);
  }

  void x2h_dbHeader(DbHeader *hdbh, const DbHeader *_xdbh)
  {
    DbHeader *xdbh = const_cast<DbHeader *>(_xdbh);
    hdbh->__magic() = x2h_u32(xdbh->__magic());
    hdbh->__dbid() = x2h_32(xdbh->__dbid());
    hdbh->__guest_uid() = x2h_32(xdbh->__guest_uid());
    hdbh->state() = xdbh->state();
    memcpy(hdbh->shmfile(), xdbh->shmfile(), L_FILENAME);

    Oid hoid, xoid;
    xoid = xdbh->__prot_uid_oid();
    x2h_oid(&hoid, &xoid);
    hdbh->__prot_uid_oid() = hoid;

    xoid = xdbh->__prot_list_oid();
    x2h_oid(&hoid, &xoid);
    hdbh->__prot_list_oid() = hoid;

    xoid = xdbh->__prot_lock_oid();
    x2h_oid(&hoid, &xoid);
    hdbh->__prot_lock_oid() = hoid;

    hdbh->__nbobjs() = x2h_u32(xdbh->__nbobjs());
    hdbh->__ndat() = x2h_u32(xdbh->__ndat());
    for (int i = 0; i < hdbh->__ndat(); i++) {
      DatafileDesc hd = hdbh->dat(i);
      DatafileDesc xd = xdbh->dat(i);
      x2h_datafileDesc(&hd, &xd);
    }
    hdbh->__ndsp() = x2h_u32(xdbh->__ndsp());
    for (int i = 0; i < hdbh->__ndsp(); i++) {
      DataspaceDesc hd = hdbh->dsp(i);
      DataspaceDesc xd = xdbh->dsp(i);
      x2h_dataspaceDesc(&hd, &xd);
    }
    hdbh->__def_dspid() = x2h_16(xdbh->__def_dspid());
    hdbh->__lastidxbusy() = x2h_u32(xdbh->__lastidxbusy());
    hdbh->__curidxbusy() = x2h_u32(xdbh->__curidxbusy());
    hdbh->__lastidxblkalloc() = x2h_u32(xdbh->__lastidxblkalloc());

    for (int i = 0; i < hdbh->__ndat(); i++)
      hdbh->__lastnsblkalloc(i) = x2h_u32(xdbh->__lastnsblkalloc(i));

    memcpy(hdbh->vre_addr(0), xdbh->vre_addr(0),
	   DbRootEntry_SIZE * MAX_ROOT_ENTRIES);
  }

  void h2x_dbHeader(DbHeader *xdbh, const DbHeader *_hdbh)
  {
    DbHeader *hdbh = const_cast<DbHeader *>(_hdbh);
    unsigned int ndat = hdbh->__ndat();
    unsigned int ndsp = hdbh->__ndsp();

    xdbh->__magic() = h2x_u32(hdbh->__magic());
    xdbh->__dbid() = h2x_32(hdbh->__dbid());
    xdbh->__guest_uid() = h2x_32(hdbh->__guest_uid());
    xdbh->state() = hdbh->state();
    memcpy(xdbh->shmfile(), hdbh->shmfile(), L_FILENAME);
    
    Oid xoid, hoid;

    hoid = hdbh->__prot_uid_oid();
    h2x_oid(&xoid, &hoid);
    xdbh->__prot_uid_oid() = xoid;

    hoid = hdbh->__prot_list_oid();
    h2x_oid(&xoid, &hoid);
    xdbh->__prot_list_oid() = xoid;

    hoid = hdbh->__prot_lock_oid();
    h2x_oid(&xoid, &hoid);
    xdbh->__prot_lock_oid() = xoid;

    xdbh->__nbobjs() = h2x_u32(hdbh->__nbobjs());
    xdbh->__ndat() = h2x_u32(hdbh->__ndat());
    for (int i = 0; i < ndat; i++) {
      DatafileDesc hd = hdbh->dat(i);
      DatafileDesc xd = xdbh->dat(i);
      h2x_datafileDesc(&xd, &hd);
    }
    xdbh->__ndsp() = h2x_u32(hdbh->__ndsp());
    for (int i = 0; i < ndsp; i++) {
      DataspaceDesc hd = hdbh->dsp(i);
      DataspaceDesc xd = xdbh->dsp(i);
      h2x_dataspaceDesc(&xd, &hd);
    }
    xdbh->__def_dspid() = h2x_16(hdbh->__def_dspid());
    xdbh->__lastidxbusy() = h2x_u32(hdbh->__lastidxbusy());
    xdbh->__curidxbusy() = h2x_u32(hdbh->__curidxbusy());
    xdbh->__lastidxblkalloc() = h2x_u32(hdbh->__lastidxblkalloc());
    for (int i = 0; i < ndat; i++)
      xdbh->__lastnsblkalloc(i) = h2x_u32(hdbh->__lastnsblkalloc(i));

    memcpy(xdbh->vre_addr(0), hdbh->vre_addr(0),
	   DbRootEntry_SIZE * MAX_ROOT_ENTRIES);
  }

  void
  x2h_protoids(Oid *prot_lock_oid, Oid *prot_list_oid,
	       Oid *prot_uid_oid, DbHeader *dbh)
  {
    Oid xoid;

    xoid = dbh->__prot_list_oid();
    x2h_oid(prot_list_oid, &xoid);

    xoid = dbh->__prot_lock_oid();
    x2h_oid(prot_lock_oid, &xoid);

    xoid = dbh->__prot_uid_oid();
    x2h_oid(prot_uid_oid, &xoid);
  }

  void
  h2x_protoids(Oid *prot_lock_oid, Oid *prot_list_oid,
	       Oid *prot_uid_oid, DbHeader *dbh)
  {
    Oid xoid;

    h2x_oid(&xoid, prot_list_oid);
    dbh->__prot_list_oid() = xoid;

    h2x_oid(&xoid, prot_lock_oid);
    dbh->__prot_lock_oid() = xoid;

    h2x_oid(&xoid, prot_uid_oid);
    dbh->__prot_uid_oid() = xoid;
  }
}
