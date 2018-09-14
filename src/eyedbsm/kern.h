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


#ifndef _EYEDBSM_KERN_H
#define _EYEDBSM_KERN_H

#include <eyedbsm/eyedbsm.h>
#include <eyedbsm/xm_alloc.h>

namespace eyedbsm {

  struct DbLocalHandle {
    int logfd;
    char *dbfile;
    int xid;
  };

  extern Status
  ESM_dbOpen(const char *dbfile, int flags,
	     const OpenHints *hints, int *id, void **pmutp,
	     int create_mode, unsigned int xid,
	     unsigned int *pversion, DbHandle **dbh),
    ESM_dbClose(const DbHandle *dbh),
    ESM_dbOpenLocal(const char *dbfile, int flags,
		    int *id, unsigned int *xid,
		    DbLocalHandle **dbh),
    ESM_dbCloseLocal(const DbLocalHandle *dbh),

    ESM_dbSetuid(DbHandle *dbh, int uid),

    ESM_guestUidGet(DbHandle const *dbh, int *uid),
    ESM_guestUidSet(DbHandle *dbh, int uid),

    ESM_rootEntrySet(DbHandle const *dbh, char const *const key,
		     void const *const data, unsigned int size, Boolean create),
    ESM_rootEntryGet(DbHandle const *dbh, char const *const key,
		     void *data, int maxsize),
    ESM_rootEntryDelete(DbHandle const *dbh, char const *const key),

    ESM_objectCreate(DbHandle const *dbh, void const *const object,
		     size_t size, short dspid, Oid *oid, OPMode), // V3_API_size_t
  /*
    ESM_objectCreate_x(DbHandle const *dbh, void const *const object,
		       unsigned int size, short dspid, Oid *oid, OPMode,
		       unsigned int create_flags),
  */
    ESM_objectDelete(DbHandle const *dbh, Oid const *const oid,
		     OPMode),
    ESM_objectWrite(DbHandle const *dbh, size_t start, size_t length,
		    void const *const object, Oid const *const oid,
		    OPMode),
    ESM_objectWriteCache(DbHandle const *dbh, size_t start,
			 void const *const object, Oid const *const oid),
    ESM_objectRead(DbHandle const *dbh, size_t start, size_t length, void *object,
		   LockMode lockmode, short *pdatid, size_t *psize, // V3_API_size_t
		   Oid const *const oid, OPMode),
    ESM_objectReadNoCopy(DbHandle const *dbh, size_t start, size_t length,
			 void *object, LockMode lockmode, short *pdatid,
			 size_t *psize, Oid const *const oid, OPMode), // V3_API_size_t
    ESM_objectReadCache(DbHandle const *dbh, size_t start, void **object,
			LockMode lockmode, Oid const *const oid),
    ESM_objectValidate(DbHandle const *, Oid const *const),

#ifdef ESM_SERVER
    ESM_objectCreate_server(DbHandle const *dbh, void const *const object,
			    size_t size, Oid *oid, rpc_ServerData *data, // V3_API_size_t
			    OPmode),
    ESM_objectWrite_server(DbHandle const *dbh, size_t start, size_t length,
			   void const *const object, Oid const *const oid,
			   rpc_ServerData *data, OPMode),
    ESM_objectRead_server(DbHandle const *dbh, size_t start, size_t length,
			  void *object, Oid const *const oid, rpc_ServerData *data),

#endif

    ESM_bornAgainEpilogue(DbHandle const *dbh, Oid const *const o_oid,
			  Oid const *const n_oid, NS ns, short datid),

    ESM_objectSizeGet(DbHandle const *dbh, size_t *size, LockMode lockmode,
		      Oid const *const oid, OPMode), // V3_API_size_t
  
    ESM_objectSizeModify(DbHandle const *dbh, size_t size, Boolean, // V3_API_size_t
			 Oid const *const oid, OPMode),

    ESM_objectCheckAccess(DbHandle const *dbh, Boolean write,
			  Oid const *const oid, Boolean *access),

    ESM_objectLocationGet(DbHandle const *dbh, const Oid *oid,
			  ObjectLocation *objloc),

    ESM_objectsLocationGet(DbHandle const *dbh, const Oid *oid,
			   ObjectLocation *objloc, unsigned int oid_cnt),

    ESM_registerStart(DbHandle const *dbh, unsigned int reg_mask),
    ESM_registerClear(DbHandle const *dbh),
    ESM_registerEnd(DbHandle const *dbh),
    ESM_registerGet(DbHandle const *dbh, Register **),

    ESM_objectMoveDatDsp(DbHandle const *dbh, Oid const *const oid,
			 short datid, short dspid, Boolean keepDatid,
			 OPMode opmode),

    ESM_objectsMoveDatDsp(DbHandle const *dbh, Oid const *const oid,
			  unsigned int oid_cnt, short datid, short dspid,
			  Boolean keepDatid, OPMode opmode),

    ESM_firstOidDatGet(DbHandle const *dbh, short datid, Oid *oid,
		       Boolean *found),
    ESM_nextOidDatGet(DbHandle const *dbh, short datid,
		      Oid const *const baseoid, Oid *nextoid,
		      Boolean *found),

    ESM_firstOidGet_map(DbHandle const *dbh, short datid, Oid *oid,
			Boolean *found),
    ESM_nextOidGet_map(DbHandle const *dbh, short datid,
		       Oid const *const baseoid, Oid *nextoid,
		       Boolean *found),

    ESM_firstOidGet_omp(DbHandle const *dbh, Oid *oid,
			Boolean *found),
    ESM_nextOidGet_omp(DbHandle const *dbh,
		       Oid const *const baseoid, Oid *nextoid,
		       Boolean *found),

  //  ESM_mapInfoGet(DbHandle const *dbh, MapInfo *mpi),

    ESM_suserUnset(DbHandle *dbh),

    ESM_datCreate(DbHandle const *dbh, const char *file, const char *name,
		  unsigned long long maxsize, MapType mtype, unsigned int sizeslot,
		  DatType, mode_t file_mask, const char *file_group),

    ESM_datMove(DbHandle const *dbh, const char *datfile,
		const char *newdatfile, Boolean force),

    ESM_datDelete(DbHandle const *dbh, const char *datfile, Boolean force),

    ESM_datResize(DbHandle const *dbh, const char *datfile,
		  unsigned long long newmaxsize),

    ESM_datCheck(DbHandle const *dbh, const char *datfile,
		 short *datid, short *dspid),
		    
    ESM_datMoveObjects(DbHandle const *dbh, const char *dat_src,
		       const char *dat_dest),
		    
    ESM_datResetCurSlot(DbHandle const *dbh, const char *datfile),

    ESM_datDefragment(DbHandle const *dbh, const char *datfile, mode_t file_mask, const char *file_group),

    ESM_datsCompress(DbHandle const *dbh),

    ESM_datRename(DbHandle const *dbh, const char *datfile, const char *name),

    ESM_datGetInfo(DbHandle const *dbh, const char *datfile,
		   DatafileInfo *info),

    ESM_datGetDspid(DbHandle const *dbh, short datid, short *dspid),

    ESM_dspSetDefault(DbHandle const *dbh, const char *datafile,
		      Boolean fromDbCreate),

    ESM_dspGetDefault(DbHandle const *dbh, short *dspid),

    ESM_dspCreate(DbHandle const *dbh, const char *dataspace,
		  const char **datfiles, unsigned int datfile_cnt,
		  Boolean fromDbCreate),

    ESM_dspUpdate(DbHandle const *dbh, const char *dataspace,
		  const char **datfiles, unsigned int datfile_cnt,
		  short flags, short orphan_dspid),

    ESM_dspDelete(DbHandle const *dbh, const char *dataspace),
    ESM_dspRename(DbHandle const *dbh, const char *dataspace,
		  const char *dataspace_new),

    ESM_dspCheck(DbHandle const *dbh, const char *dataspace, short *dspid,
		 short datid[], unsigned int *ndat),

    ESM_dspSetCurDat(DbHandle const *dbh, const char *dataspace, const char *),
    ESM_dspGetCurDat(DbHandle const *dbh, const char *dataspace, short *cur),

    ESM_protectionCreate(DbHandle const *dbh,
			 ProtectionDescription const *desc,
			 Oid *oid),

    ESM_protectionDelete(DbHandle const *dbh, Oid const *const oid),

    ESM_protectionModify(DbHandle const *dbh,
			 ProtectionDescription const *desc,
			 Oid const *oid),

    ESM_protectionGetByName(DbHandle const *dbh,
			    char const *name,
			    ProtectionDescription **desc,
			    Oid *oid),

    ESM_protectionGetByOid(DbHandle const *dbh,
			   Oid const *oid,
			   ProtectionDescription **desc),

    ESM_protectionListGet(DbHandle const *dbh,
			  Oid **oid, ProtectionDescription ***desc,
			  unsigned int *nprot),

    ESM_dbProtectionAdd(DbHandle const *dbh,
			DbProtectionDescription const *desc, int nprot),

    ESM_dbProtectionGet(DbHandle const *dbh,
			DbProtectionDescription **desc, unsigned int *nprot),

    ESM_objectProtectionSet(DbHandle const *dbh, Oid const *const oid,
			    Oid const *const protoid, OPMode),
    ESM_objectProtectionGet(DbHandle const *dbh, Oid const *const oid,
			    Oid *protoid),

    ESM_protectionsVolatUpdate(DbHandle const *dbh),

    ESM_objectRestore(DbHandle const *dbh, Oid const *const oid,
		      NS ns, short datid),
    ESM_objectDeleteByOidLoc(DbHandle const *dbh, Oid const *const oid,
			     NS ns, short datid);

  extern int ESM_getOpenFlags(DbHandle const *dbh);
  extern unsigned int ESM_xidGet(DbHandle *dbh);
  extern void ESM_uidSet(DbHandle *dbh, int uid);
  extern int ESM_uidGet(DbHandle *dbh);

  enum ESM_oidsTraceAction {
    ESM_allOids = 1,
    ESM_invalidOids,
    ESM_oidCount
  };

  extern void
  ESM_oidsTrace(DbHandle const *const, ESM_oidsTraceAction, FILE *);

  extern int
  ESM_dataBaseIdGet(DbHandle const *dbh);

  extern const char *
  shmfileGet(const char *);

#define ESM_REGISTER(DBH, OP, X) do {				\
    if ((DBH)->vd->reg && ((DBH)->vd->reg_mask & (OP))) X;	\
  } while(0)

}

#endif
