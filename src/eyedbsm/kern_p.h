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


#ifndef _SEKERN_P_H
#define _SEKERN_P_H

#define NO_FILE_LOCK

#include <eyedbsmconfig.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include <eyedblib/machtypes.h>
#include <transaction.h>
#include <eyedbsm_p.h>
#include <lock.h>
#include <eyedblib/iassert.h>
#include <xdr_p.h>
#include <xdr_off.h>

#define _ESM_C_

#include <eyedblib/rpc_be.h>
#include <kern.h>
#include <eyedblib/semlib.h>
#include <eyedblib/log.h>
#include <pwd.h>
#include <lib/m_mem_p.h>

namespace eyedbsm {

  struct DBFD {
    int dbsfd, ompfd, shmfd;
    int fd_dat[MAX_DATAFILES], fd_dmp[MAX_DATAFILES];

    DBFD() {
      dbsfd = ompfd = shmfd = -1;
      for (int i = 0; i < MAX_DATAFILES; i++)
	fd_dat[i] = fd_dmp[i] = -1;
    }
  };

  extern const char *
  fileGet(const char *dbfile, const char ext[]);

  extern const char *
  shmfileGet(const char *dbfile);

  extern const char *
  dmpfileGet(const char *volfile);

  extern const char *
  objmapfileGet(const char *dbfile);

  extern Status
  fileSizesGet(const char *file, unsigned long long &filesize,
	       unsigned long long &fileblksize);

  extern Status
  checkVolMaxSize(unsigned maxsize);

  extern Status
  checkDatafileSize(unsigned long long nslots_l,
		    const char *datfile, unsigned int sizeslot,
		    unsigned long long newmaxsize);

  extern Status
  checkDatafile(const char *pr, const char *dbfile, DbHeader *dbh,
		const DbCreateDescription *dbc,
		int i, DBFD *dbfd, mode_t file_mode, gid_t file_gid,
		Boolean can_be_null = False,
		Boolean *is_null = 0, Boolean in_place = False);

  extern Status
  checkNewDatafile(DbHeader *dbh, const char *file,
		   const char *name);

  extern Status
  getFileMaskGroup(mode_t &file_mode, gid_t &file_gid, mode_t file_mask, const char *file_group);

  extern int
  shmfileOpen(const char *dbfile, bool strict_read);
    
  extern Boolean
  filelockS(int fd);

  extern Boolean
  filelockX(int fd);

  extern Boolean
  fileunlock(int fd);

  extern int
  objmapfileOpen(const char *dbfile, int flag);
    
  extern Status
  syserror(const char *fmt, ...);

  extern Status
  syscheck(const char *pre, long long c, const char *fmt, ...);

  extern Status
  syscheckn(const char *pre, long long c, int n, const char *fmt, ...);
  
  extern Status
  checkFileAccessFailed(Error err, const char *what, const char *file, unsigned int flags);

  extern Status
  checkFileAccess(Error err, const char *what, const char *file, unsigned int flags);

  extern Status
  dopen(char const * pre, char const * file, int mode, int * const fdp,
	Boolean * const suser);

  extern Status
  dbCleanup(const char *dbfile);

  extern Status
  fcouldnot(char const *pre, char const *what, char const *which);

  extern Status
  push_dir(const char *dbfile, char *pwd, unsigned int pwd_size);

  extern Status
  pop_dir(char *pwd);

  extern const char *
  get_dir(const char *dbfile);

  extern char *
  string_version(unsigned int version);

  extern Status
  protectionInit(DbHandle const *dbh);

  extern Status
  dbProtectionCheck(DbHandle const *dbh, int flag);

  extern Status
  dbProtectionRunTimeUpdate(DbHandle const *dbh);

  extern Status
  ESM_protectionsRunTimeUpdate(DbHandle const *dbh);

  extern Status
  ESM_getDatafile(DbHandle const *dbh, short &dspid, short &datid);

  extern Boolean
  ESM_getNextDatafile(DbHandle const *dbh, short dspid, short &datid);

  extern Status
  ESM_dspGet(DbHandle const *dbh, const char *dataspace, short *dspid);

  extern Status
  protectionRunTimeUpdate(DbHandle const *dbh);

  extern const Protection *
  protGet(DbHandle const *dbh, Oid const *oid, int uid);

  extern void
  dbg_setuid(int uid);

  extern int
  getUid(DbHandle const *dbh);

  extern int
  indUidGet(DbHandle const *dbh, int ind);

  extern int
  uidIndGet(DbHandle const *dbh, int uid);

  extern Status
  ESM_dbSetuid(DbHandle *dbh, int uid);

  extern Status
  ESM_suserUnset(DbHandle *dbh);

  extern void
  ESM_addToRegisterCreate(DbHandle const *dbh, const Oid *oid, size_t size);

  extern void
  ESM_addToRegisterRead(DbHandle const *dbh, const Oid *oid, size_t start, size_t length);

  extern void
  ESM_addToRegisterWrite(DbHandle const *dbh, const Oid *oid, size_t start, size_t length);

  extern void
  ESM_addToRegisterSizeMod(DbHandle const *dbh, const Oid *oid, size_t size);

  extern void
  ESM_addToRegisterSizeGet(DbHandle const *dbh, const Oid *oid);

  extern void
  ESM_addToRegisterLock(DbHandle const *dbh, const Oid *oid, OP lock);

  extern void
  ESM_addToRegisterDelete(DbHandle const *dbh, const Oid *oid);

  extern Boolean
  ESM_isExclusive(DbHandle const *dbh);

  extern OidLoc
  oidLocGet(DbHandle const *const dbh, const Oid *oid);

  extern OidLoc
  oidLocGet_(DbHandle const *const dbh, Oid::NX nx);

  extern int
  isNxValid(DbHandle const *const dbh, Oid::NX nx);

  extern Status
  nxAlloc(DbHandle const *const dbh, const OidLoc &oidloc, Oid::NX *pnx);

  extern void
  nxFree(DbHandle const *const dbh, Oid::NX nx);

  extern void
  nxSet(DbHandle const *const dbh, Oid::NX nx, NS ns, short datid);

  extern Oid::NX
  nxNextBusyGet(DbHandle const *const dbh, Oid::NX nx);

  extern const char *
  get_time();

  extern Status
  mapAlloc(DbHandle const *dbh, short datid, size_t size, NS *pns, NS *pneedslots, NS *pmax_free_slots);

  extern void
  mapFree(DbDescription *vd, NS ns, short datid, size_t size);

  extern void
  mapMark(DbDescription *vd, NS ns, short datid, size_t needslots, int value);

  extern ObjectHeader *
  oid2objh_(const Oid *oid, NS ns, short datid, const DbHandle *dbh, ObjectHeader **objh, MmapH *hdl, size_t *up, Boolean *oid2addr_failed);

  extern ObjectHeader *
  oid2objh(const Oid *oid, const DbHandle *dbh, ObjectHeader **objh,
	   MmapH *hdl, Boolean *oid2addr_failed);

  static const char* msg_2 = __FILE__;
#define TTT(S) (write( 1, S, strlen(S)))
 static int dummy_off_t_2 = (sizeof(off_t) != 8 ? (TTT(msg_2), *(char *)0 = 0) : 1);

  /*
    extern off_t
    oid2lastslot(const Oid *oid, const DbHandle *dbh);
  */

  extern int
  check_oid(const DbHandle *dbh, const Oid *oid);

  extern char *
  slot2addr(const DbHandle *dbh, off_t ns, short datid, size_t size, char **pt, MmapH *hdl, size_t *up);

  extern char *
  oidloc2addr(const DbHandle *dbh, const OidLoc &oidloc, size_t size, char **pt, MmapH *hdl, size_t *up);

  extern void
  hdl_release(MmapH *hdl);

  extern int
  oidloc_cmp(const OidLoc &, const OidLoc &);

  extern void
  display_invalid_oid(const Oid *oid, ObjectHeader *xobjh);

  extern int
  oid_cmp(Oid *a, Oid *b);

  extern unsigned int
  getDbVersion(void *dbh);

  extern Boolean
  isWholeMapped(void *dbh);

  extern void
  DbMutexesInit(DbDescription *, DbShmHeader *);

  extern void
  DbMutexesLightInit(DbDescription *, DbShmHeader *);

  extern Status
  DbMutexesRelease(DbDescription *, DbShmHeader *, unsigned int);

  extern Boolean
  isDatValid(DbHandle const *dbh, short datid);

  extern Boolean
  isDspValid(DbHandle const *dbh, short dspid);

  extern DatType
  getDatType(DbHeader const *dbh, short datid);

  extern DatType
  getDatType_inplace(DbHeader const *dbh, short datid);

  extern void
  setDatType(DbHeader *dbh, short datid, DatType dtype);

  extern void
  setDatType_inplace(DbHeader *dbh, short datid, DatType dtype);

  extern short
  getDataspace(const DbHeader *dbh, short datid);

  extern short
  getDataspace(const DbHeader *dbh, short datid);

  extern short
  getDataspace_inplace(const DbHeader *dbh, short datid);

  extern void
  setDataspace(DbHeader *dbh, short datid, short dspid);

  extern void
  setDataspace_inplace(DbHeader *dbh, short datid, short dspid);

  extern Status
  copyfile(const char *from, const char *to,
	   const char *fromdbdir, const char *todbdir,
	   int sparsify);

  extern Status
  renamefile(const char *from, const char *to,
	     const char *fromdbdir, const char *todbdir,
	     int sparsify);

  extern char *
  makefile(const char *dir, const char *file);

  extern Boolean
  is_number(const char *s);

  extern void
  errorInit(void);

  extern int
  power2(int);

  extern size_t
  fdSizeGet(int);

  extern size_t
  fileSizeGet(const char *);

  extern Status
  nxFileSizeExtends(DbHandle const *dbh, Oid::NX);

  extern Status
  nsFileSizeExtends(DbHandle const *dbh, short datid, NS);

  extern Boolean
  isPhy(DbHandle const *dbh, const Oid *oid);

  extern void
  setPhyInfo(Oid *oid, NS ns, short datid);

  extern void
  getPhyInfo(const Oid *oid, NS *pns, short *datid);

  extern Status
  oidCopySlot(DbHandle const *dbh, Oid::NX nx, Oid *oid, size_t *psize);

  extern Status
  oidCopySlot_(DbHandle const *dbh, Oid::NX nx, const OidLoc &, Oid *oid, size_t *psize);

  extern NS
  oidLastSlotGet(DbHandle const *dbh, const OidLoc &);
  /*}*/

  extern int pgsize, pgsize_pow2;
  extern unsigned long curref;
  extern const void *ObjectZero, *ObjectNone;
  extern const Protection p_all, p_none;
  extern Boolean backend_interrupt;
  extern Boolean backend;
  extern unsigned int import_xid;
  extern const int INVALID;

  extern const char ompext[];
  extern const char shmext[];
  extern const char dbsext[];
  extern const char datext[];
  extern const char dmpext[];
  extern int dbsext_len;
  extern int datext_len;
  extern Boolean cleanup;

#define ONE_K 1024
#define ONE_M (1024*1024)
#define BITS_PER_BYTE 8
#define IDBH "database handle is invalid"
  /*#define DBH2MP(dbh) (&(dbh)->vd->dbhead->mp)*/
#define WF_P "database is not in write access mode"
#define WF    WF_P ": '%s'"
#define NS_OFFSET 1

#define OIDDBIDGET(oid) ((oid)->getDbID())
#define OIDDBIDMAKE(oid, _dbid) (oid)->setDbID(_dbid)

#define check_dbh(dbh) (1)

#define MAX(x,y) ((int)(x) > (int)(y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#define DBSADDR(dbh) ((dbh)->vd->dbs_addr)

#define DAT2MP(dbh, datid) MapHeader(DbHeader_dat_ref(DBSADDR(dbh), datid) + DatafileDesc_mp_OFF)

#define DAT2MP_(vd, datid) MapHeader(DbHeader_dat_ref(vd->dbs_addr, datid) + DatafileDesc_mp_OFF)

#define LASTIDXBUSY(dbh) DbHeader___lastidxbusy(DBSADDR(dbh))

#define CURIDXBUSY(dbh) DbHeader___curidxbusy(DBSADDR(dbh))

#define LASTIDXBLKALLOC(dbh) DbHeader___lastidxblkalloc(DBSADDR(dbh))

#define LASTNSBLKALLOC(dbh, datid) DbHeader___lastnsblkalloc(DBSADDR(dbh), datid)

#define SZ2NS(sz, mp) ((((sz)-1)>>(mp)->pow2())+1)
#define SZ2NS_XDR(sz, mp) ((((sz)-1)>>x2h_u32((mp)->pow2()))+1)

#define NEXT_OIDLOC(omp_addr) (void *)((char *)omp_addr + OIDLOCSIZE)
#define OIDLOC(omp_addr, nx) (void *)((char *)omp_addr + ((unsigned long long)nx)*OIDLOCSIZE)

#define oid2addr_(ns, datid, dbh, size, pt, hdl, up) \
        slot2addr(dbh, ns, datid, size, (char **)pt, hdl, up)

#define oid2addr(oid, dbh, size, pt, hdl) \
        oidloc2addr(dbh, oidLocGet(dbh, oid), size, (char **)pt, hdl, 0)

#define oidloc2addr_(oidloc, dbh, size, pt, hdl) \
        oidloc2addr(dbh, oidloc, size, (char **)pt, hdl, 0)

#define InvalidMask_v2       0x80000000U
#define makeInvalid_v2(SZ)   ((SZ) | InvalidMask_v2)
#define makeValid_v2(SZ)     ((SZ) & ~InvalidMask_v2)
#define getSize_v2(SZ)       ((SZ) & ~InvalidMask_v2)
#define isValidObject_v2(SZ) (!((SZ) & InvalidMask_v2))

#define InvalidMask_v3       0x8000000000000000ULL
#define makeInvalid_v3(SZ)   ((SZ) | InvalidMask_v3)
#define makeValid_v3(SZ)     ((SZ) & ~InvalidMask_v3)
#define getSize_v3(SZ)       ((SZ) & ~InvalidMask_v3)
#define isValidObject_v3(SZ) (!((SZ) & InvalidMask_v3))

#define BMH    u.bmh
#define LMH    u.lmh
#define BMSTAT mstat.u.bmstat
#define LMSTAT mstat.u.lmstat

#define SEGMENT_UNMAP(MMD) \
{ \
  (MMD)->ismapped = False; \
  (MMD)->ref = 0; \
  (MMD)->locked  = False; \
  syscheck("", m_munmap((MMD)->m, (MMD)->mapaddr, (MMD)->a_end - (MMD)->a_start), ""); \
}

#define KB2SLOT(SZ, POW2SLOT) \
(((unsigned long long)(SZ) * ONE_K)>> (POW2SLOT))

#define LASTNS(START, SZ, POW2SLOT) \
     ((START) + KB2SLOT(SZ, POW2SLOT))

#define DELTANS(NEWSZ, OLDSZ, POW2SLOT) \
     (((((long long)(NEWSZ)) - (OLDSZ)) * ONE_K) >> (POW2SLOT))

#define SLOT2KB(NS, SZSLOT) \
     ((((NS) * (SZSLOT)) / ONE_K) + 1)

  /*
#define DMP_SIZE(MTYPE, NSLOTS) \
    ((MTYPE == BitmapType) ? \
     ((size_t)NSLOTS / BITS_PER_BYTE) : \
     (MAX_FREE_CELLS * sizeof(LinkmapCell)))
  */

#define DMP_SIZE(MTYPE, NSLOTS) \
    ((MTYPE == BitmapType) ? \
     ((size_t)NSLOTS / BITS_PER_BYTE) : 0)

#define CHECK_X(dbh, msg) \
 if (!ESM_isExclusive(dbh)) \
   return statusMake(ERROR, \
     "exclusive database access is needed when " msg);

#define PHYOID_VERSION 205015
#define V3_VERSION     300000

#define PHYDATID_SHIFT 13
#define PHYOID_BITMASK 0x200000

#define DATTYPE_SHIFT 15
#define DATTYPE_BITMASK (1 << DATTYPE_SHIFT)
#define DATTYPE_CLEAN(X) ((X) & ~DATTYPE_BITMASK)

#define maskSize(SIZE)    (SIZE)

#define objDataOffset (2 * sizeof(int))

#define objDataGetSize(SIZE)  \
(objDataOffset + SIZE + maskSize(SIZE))

#define objDataSize(DATA) (*(int *)((char *)DATA))
#define objDataAll(DATA)  (*(char *)((char *)DATA+sizeof(int)))
#define objDataData(DATA) (((char *)(DATA)+objDataOffset))
#define objDataMask(DATA) (objDataData(DATA) + objDataSize(DATA))
}

#define DEFAULT_PWD_SIZE 1024

#endif
