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

#include <pthread.h>

#include <unistd.h>
#include <stdlib.h>

#include <eyedblib/iassert.h>
#include "transaction.h"
#include "kern.h"
#include "lock.h"
// added 4/05
#include "eyedbsm_p.h"
#include <eyedblib/m_mem.h>

// FD CHECK: include a lib/ private header
#include "lib/m_mem_p.h"

namespace eyedbsm {
  /*extern "C" */ Boolean
  isPhy(DbHandle const *dbh, const Oid *oid);

  //static StatusRec status_r;

#define STATUS_RETURN(S) \
return (((S).err == SUCCESS) ? Success : &(S))

  /*
    static void fe_statusMake(ClientArg *ua, int i)
    {
    static unsigned int status_alloc;
    StatusProtocol *s = &ua[i].a_status;

    status_r.err = (Error)s->err;
    if (strlen(s->err_msg) >= status_alloc) {
    status_alloc = strlen(s->err_msg)+10;
    status_r.err_msg = (char *)realloc(status_r.err_msg, status_alloc);
    }

    strcpy(status_r.err_msg, s->err_msg);
    }
  */

  /*
    Status
    connOpen(const char *hostname, const char *portname, ConnHandle **pch,
    int flags)
    {
    return Success;
    }

    Status
    connClose(ConnHandle *ch)
    {
    return Success;
    }
  */

  int
  getOpenFlags(DbHandle const *dbh)
  {
    return ESM_getOpenFlags((DbHandle *)dbh);
  }

  Status
  transactionBegin(DbHandle *dbh, const TransactionParams *params)
  {
    Status se;
    se = ESM_transactionBegin((DbHandle *)dbh, params);
    if (!se)
      dbh->tr_cnt++;
    return se;
  }

  Status
  transactionParamsSet(DbHandle const *dbh,
		       const TransactionParams *params)
  {
    /*  return ESM_transactionParamsSet(dbh, trmode, trwrmode, params);*/
    /* changed dbh to (DbHandle *)dbh 11/11/00 */
    return ESM_transactionParamsSet((DbHandle *)dbh, params);
  }

  Status
  transactionParamsGet(DbHandle const *dbh,
		       TransactionParams *params)
  {
    return ESM_transactionParamsGet(dbh, params);
  }

  Status
  transactionCommit(DbHandle *dbh)
  {
    Status se;
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "transactionCommit");

    se = ESM_transactionCommit((DbHandle *)dbh);
    if (!se)
      dbh->tr_cnt--;
    return se;
  }

  Status
  transactionAbort(DbHandle *dbh)
  {
    Status se;
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "transactionAbort");

    se = ESM_transactionAbort((DbHandle *)dbh);
    if (!se)
      dbh->tr_cnt--;
    return se;
  }

  /* remote procedure calls */
  Status
  dbOpen(const char *dbfile, int flags,
	 const OpenHints *hints, int uid, unsigned int *pversion,
	 DbHandle **dbh)
  {
    Status status;
      
    *dbh = (DbHandle *)m_calloc(sizeof(DbHandle), 1);
    memset(*dbh, 0, sizeof(**dbh));

    status = ESM_dbOpen(dbfile, flags & ~LOCAL, hints, 0, 0, 0, 0, pversion, dbh);
      
    if (!status) {
      //(*dbh)->ldbctx.rdbhid = 0;
      //(*dbh)->ldbctx.xid    = ESM_xidGet(tdbh);
      (*dbh)->xid    = ESM_xidGet(*dbh);
      ESM_uidSet(*dbh, uid);
      ESM_suserUnset(*dbh);
      //(*dbh) = tdbh;
      (*dbh)->flags = flags & ~LOCAL;
      //printf("dbOpen: dbh=%p\n", *dbh);
      //printf("dbOpen: dbh=%p\n", (*dbh));
    }
  
    return status;
  }

  Status
  dbClose(const DbHandle *dbh)
  {
    //printf("dbClose: dbh=%p\n", dbh);
    //printf("dbClose: dbh=%p\n", dbh);
    return ESM_dbClose((DbHandle *)dbh);
  }

  Status
  rootEntrySet(DbHandle const *dbh, char const *const key,
	       void const *const data, unsigned int size, Boolean create)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "rootEntrySet");
    return ESM_rootEntrySet((DbHandle *)dbh, key, data, size, create);
  }

  Status
  rootEntryGet(DbHandle const *dbh, char const *const key,
	       void *data, unsigned int maxsize)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "rootEntryGet");
    return ESM_rootEntryGet((DbHandle *)dbh, key, data, maxsize);
  }

  Status
  rootEntryDelete(DbHandle const *dbh, char const *const key)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "rootEntryDelete");
    return ESM_rootEntryDelete((DbHandle *)dbh, key);
  }

  Status
  objectCreate(DbHandle const *dbh, void const *const object,
	       size_t size, short dspid, Oid *oid) // V3_API_size_t
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectCreate");
    return ESM_objectCreate((DbHandle *)dbh, object, size, dspid, oid, OPDefault);
  }

  Boolean
  isPhysicalOid(DbHandle const *dbh, const Oid *oid)
  {
    return isPhy((DbHandle *)dbh, oid);
  }

  extern int
  getTransactionCount(DbHandle const *dbh)
  {
    return dbh->tr_cnt;
  }

  extern int
  getXID(DbHandle const *dbh)
  {
    return dbh->xid;
  }

  Status
  objectDelete(DbHandle const *dbh, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectDelete");

    return ESM_objectDelete((DbHandle *)dbh, oid, OPDefault);
  }

  Status
  objectWrite(DbHandle const *dbh, size_t start, size_t length,
	      void const *const object, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectWrite");

    return ESM_objectWrite((DbHandle *)dbh, start, length, object, oid, OPDefault);
  }

  Status
  objectWriteCache(DbHandle const *dbh, size_t start,
		   void const *const object, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectWriteCache");

    return ESM_objectWriteCache((DbHandle *)dbh, start, object, oid);
  }

  Status
  objectMoveDat(DbHandle const *dbh, Oid const *const oid,
		short datid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectMoveDat");
    return ESM_objectMoveDatDsp((DbHandle *)dbh, oid, datid, -1, False, OPDefault);
  }

  Status
  objectsMoveDat(DbHandle const *dbh, Oid const *const oid,
		 unsigned int oid_cnt, short datid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectsMoveDat");
    return ESM_objectsMoveDatDsp((DbHandle *)dbh, oid, oid_cnt, datid, -1, False, OPDefault);
  }

  Status
  objectMoveDsp(DbHandle const *dbh, Oid const *const oid,
		short dspid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectMoveDsp");
    return ESM_objectMoveDatDsp((DbHandle *)dbh, oid, -1, dspid, False, OPDefault);
  }

  Status
  objectsMoveDsp(DbHandle const *dbh, Oid const *const oid,
		 unsigned int oid_cnt, short dspid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectsMoveDsp");
    return ESM_objectsMoveDatDsp((DbHandle *)dbh, oid, oid_cnt, -1, dspid, False, OPDefault);
  }

  Status
  objectLock(DbHandle const *dbh, Oid const *const oid, 
	     LockMode mode, LockMode *rmode)
  {
    int lockmode;
    Status se;

    if (!oid->getNX() && !isPhysicalOid(dbh, oid))
      return statusMake(ERROR, "object lock: invalid null oid");
    
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectLock");

    if (mode == LockX)
      lockmode = LOCKX;
    else if (mode == LockS)
      lockmode = LOCKS;
    else if (mode == LockSX)
      lockmode = LOCKSX;
    else if (mode == LockN)
      lockmode = LOCKN;
    else
      return statusMake(ERROR, "invalid lock mode %d", mode);

    se = ESM_objectLock((DbHandle *)dbh, oid, (TransactionOP)(OREAD|lockmode), NULL, NULL);
    if (se) return se;

    if (rmode)
      ESM_objectGetLock((DbHandle *)dbh, oid, rmode);

    return Success;
  }

  Status
  objectGetLock(DbHandle const *dbh, Oid const *const oid,
		LockMode *rmode)
  {
    if (!oid->getNX() && !isPhysicalOid(dbh, oid))
      return statusMake(ERROR, "object lock: invalid null oid");
    
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectLock");

    if (rmode)
      return ESM_objectGetLock((DbHandle *)dbh, oid, rmode);
    return Success;
  }

  Status
  objectDownLock(DbHandle const *dbh, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectDownLock");
    return ESM_objectDownLock((DbHandle *)dbh, oid);
  }

  Status
  transactionLockSet(DbHandle const *dbh, ObjectLockMode lockmode,
		     ObjectLockMode *omode)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "transactionLockSet");
    return ESM_transactionLockSet((DbHandle *)dbh, lockmode, omode);
  }

  Status
  objectRead(DbHandle const *dbh, size_t start, size_t length, void *object,
	     LockMode lockmode, short *pdatid, size_t *psize, // V3_API_size_t
	     Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectRead");
    return ESM_objectRead((DbHandle *)dbh, start, length, object,
			  lockmode, pdatid, psize, oid, OPDefault);
  }

  Status
  objectReadNoCopy(DbHandle const *dbh, size_t start, size_t length,
		   void *object, LockMode lockmode, short *pdatid,
		   size_t *psize, Oid const *const oid) // V3_API_size_t
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectReadNoCopy");
    return ESM_objectReadNoCopy((DbHandle *)dbh, start, length, object,
				lockmode, pdatid, psize, oid, OPDefault);
  }

  Status
  objectReadCache(DbHandle const *dbh, size_t start, void **object,
		  LockMode lockmode, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectReadCache");
    return ESM_objectReadCache((DbHandle *)dbh, start, object, lockmode, oid);
  }

  Status
  objectSizeGet(DbHandle const *dbh, size_t *size, LockMode lockmode, // V3_API_size_t
		Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectSizeGet");
    return ESM_objectSizeGet((DbHandle *)dbh, size, lockmode, oid, OPDefault);
  }

  Status
  objectSizeModify(DbHandle const *dbh, size_t size, Boolean copy, // V3_API_size_t
		   Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectSizeModify");
    return ESM_objectSizeModify((DbHandle *)dbh, size, copy, oid, OPDefault);
  }

  Status
  objectCheckAccess(DbHandle const *dbh, Boolean write,
		    Oid const *const oid, Boolean *access)
  {
    return ESM_objectCheckAccess((DbHandle *)dbh, write, oid, access);
  }

  Status
  objectLocationGet(DbHandle const *dbh, const Oid *oid,
		    ObjectLocation *objloc)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectLocationGet");
    return ESM_objectLocationGet((DbHandle *)dbh, oid, objloc);
  }
  
  Status
  objectsLocationGet(DbHandle const *dbh, const Oid *oid,
		     ObjectLocation *objloc, unsigned int oid_cnt)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectsLocationGet");
    return ESM_objectsLocationGet((DbHandle *)dbh, oid, objloc, oid_cnt);
  }
  
  /*
    Status
    firstOidGet(DbHandle const *dbh, Oid *oid, Boolean *found)
    {
    if (!dbh->tr_cnt)
    return statusMake(TRANSACTION_NEEDED, "firstOidGet");
    return ESM_firstOidGet((DbHandle *)dbh, oid, found);
    }

    Status
    nextOidGet(DbHandle const *dbh, Oid const *const baseoid,
    Oid *nextoid, Boolean *found)
    {
    if (!dbh->tr_cnt)
    return statusMake(TRANSACTION_NEEDED, "nextOidGet");
    return ESM_nextOidGet((DbHandle *)dbh, baseoid, nextoid, found);
    }
  */

  Status
  firstOidDatGet(DbHandle const *dbh, short datid, Oid *oid,
		 Boolean *found)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "firstOidGet");
    return ESM_firstOidDatGet((DbHandle *)dbh, datid, oid, found);
  }

  Status
  nextOidDatGet(DbHandle const *dbh, short datid,
		Oid const *const baseoid,
		Oid *nextoid, Boolean *found)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "nextOidGet");
    return ESM_nextOidDatGet((DbHandle *)dbh, datid, baseoid, nextoid, found);
  }

  Status
  suserUnset(DbHandle *dbh)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "suserUnset");
    return ESM_suserUnset((DbHandle *)dbh);
  }

  Status
  protectionCreate(DbHandle const *dbh,
		   ProtectionDescription const *desc,
		   Oid *oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionCreate");

    return ESM_protectionCreate((DbHandle *)dbh, desc, oid);
  }

  Status
  protectionDelete(DbHandle const *dbh, Oid const *const oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionDelete");
    return ESM_protectionDelete((DbHandle *)dbh, oid);
  }

  Status
  protectionModify(DbHandle const *dbh,
		   ProtectionDescription const *desc,
		   Oid const *oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionModify");
    return ESM_protectionModify((DbHandle *)dbh, desc, oid);
  }

  Status
  protectionGetByName(DbHandle const *dbh,
		      char const *name,
		      ProtectionDescription **desc,
		      Oid *oid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionGetByName");
    return ESM_protectionGetByName((DbHandle *)dbh, name, desc, oid);
  }

  Status
  protectionGetByOid(DbHandle const *dbh,
		     Oid const *oid,
		     ProtectionDescription **desc)
  { 
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionGetByOid");
    return ESM_protectionGetByOid((DbHandle *)dbh, oid, desc);
  }

  Status
  protectionListGet(DbHandle const *dbh,
		    Oid **oid, ProtectionDescription ***desc,
		    unsigned int *nprot)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "protectionListGet");
    return ESM_protectionListGet((DbHandle *)dbh, oid, desc, nprot);
  }

  Status
  dbProtectionAdd(DbHandle const *dbh,
		  DbProtectionDescription const *desc, int nprot)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dbProtectionAdd");
    return ESM_dbProtectionAdd((DbHandle *)dbh, desc, nprot);
  }

  Status
  dbProtectionGet(DbHandle const *dbh,
		  DbProtectionDescription **desc, unsigned int *nprot)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dbProtectionGet");
    return ESM_dbProtectionGet((DbHandle *)dbh, desc, nprot);
  }

  Status
  objectProtectionSet(DbHandle const *dbh, Oid const *const oid,
		      Oid const *const protoid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectProtectionSet");
    return ESM_objectProtectionSet((DbHandle *)dbh, oid, protoid, OPDefault);
  }

  Status
  objectProtectionGet(DbHandle const *dbh, Oid const *const oid,
		      Oid *protoid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "objectProtectionGet");
    return ESM_objectProtectionGet((DbHandle *)dbh, oid, protoid);
  }

  Status
  datCreate(DbHandle const *dbh, const char *file, const char *name,
	    unsigned long long maxsize, MapType mtype, unsigned int sizeslot,
	    DatType dtype, mode_t file_mask, const char *file_group)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datCreate");
    return ESM_datCreate((DbHandle *)dbh, file, name, maxsize, mtype, sizeslot, dtype, file_mask, file_group);
  }


  Status
  datMove(DbHandle const *dbh, const char *datfile, const char *newdatfile)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datMove");
    return ESM_datMove((DbHandle *)dbh, datfile, newdatfile, False);
  }

  Status
  datResize(DbHandle const *dbh, const char *datfile,
	    unsigned long long newmaxsize)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datResize");
    return ESM_datResize((DbHandle *)dbh, datfile, newmaxsize);
  }

  Status
  datDelete(DbHandle const *dbh, const char *datfile, Boolean force)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datDelete");
    //    return ESM_datDelete((DbHandle *)dbh, datfile, False);
    return ESM_datDelete((DbHandle *)dbh, datfile, force);
  }

  Status
  datDefragment(DbHandle const *dbh, const char *datfile, mode_t file_mask, const char *file_group)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datDefragment");
    return ESM_datDefragment((DbHandle *)dbh, datfile, file_mask, file_group);
  }

  Status
  datCheck(DbHandle const *dbh, const char *datfile, short *datid,
	   short *dspid)
  {
    return ESM_datCheck((DbHandle *)dbh, datfile, datid, dspid);
  }

  Status
  datResetCurSlot(DbHandle const *dbh, const char *datfile)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datResetCurSlot");
    return ESM_datResetCurSlot((DbHandle *)dbh, datfile);
  }

  Status
  dspCheck(DbHandle const *dbh, const char *dataspace, short *dspid,
	   short datid[], unsigned int *ndat)
  {
    return ESM_dspCheck((DbHandle *)dbh, dataspace, dspid, datid, ndat);
  }

  Status
  dspSetCurDat(DbHandle const *dbh, const char *dataspace, const char *datfile)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspSetCurDat");
    return ESM_dspSetCurDat((DbHandle *)dbh, dataspace, datfile);
  }

  Status
  dspGetCurDat(DbHandle const *dbh, const char *dataspace, short *datid)
  {
    return ESM_dspGetCurDat((DbHandle *)dbh, dataspace, datid);
  }

  Status
  dspSetDefault(DbHandle const *dbh, const char *dataspace)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspSetDefault");
    return ESM_dspSetDefault((DbHandle *)dbh, dataspace, False);
  }

  Status
  dspGetDefault(DbHandle const *dbh, short *dspid)
  {
    return ESM_dspGetDefault((DbHandle *)dbh, dspid);
  }

  Status
  datRename(DbHandle const *dbh, const char *datfile, const char *name)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspRename");
    return ESM_datRename((DbHandle *)dbh, datfile, name);
  }

  Status
  datGetInfo(DbHandle const *dbh, const char *datfile, DatafileInfo *info)
  {
    return ESM_datGetInfo((DbHandle *)dbh, datfile, info);
  }

  Status
  datGetDspid(DbHandle const *dbh, short datid, short *dspid)
  {
    return ESM_datGetDspid((DbHandle *)dbh, datid, dspid);
  }

  Status
  datMoveObjects(DbHandle const *dbh, const char *dat_src,
		 const char *dat_dest)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "datMoveObjects");
    return ESM_datMoveObjects((DbHandle *)dbh, dat_src, dat_dest);
  }

  Status
  dspCreate(DbHandle const *dbh, const char *dataspace,
	    const char **datfiles, unsigned int datfile_cnt)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspCreate");
    return ESM_dspCreate((DbHandle *)dbh, dataspace, datfiles, datfile_cnt, False);
  }

  Status
  dspUpdate(DbHandle const *dbh, const char *dataspace,
	    const char **datfiles, unsigned int datfile_cnt,
	    short flags, short orphan_dspid)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspUpdate");
    return ESM_dspUpdate((DbHandle *)dbh, dataspace, datfiles, datfile_cnt,
			 flags, orphan_dspid);
  }

  Status
  dspDelete(DbHandle const *dbh, const char *dataspace)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspDelete");
    return ESM_dspDelete((DbHandle *)dbh, dataspace);
  }

  Status
  dspRename(DbHandle const *dbh, const char *dataspace,
	    const char *dataspace_new)
  {
    if (!dbh->tr_cnt)
      return statusMake(TRANSACTION_NEEDED, "dspRename");
    return ESM_dspRename((DbHandle *)dbh, dataspace, dataspace_new);
  }

  Status
  registerStart(DbHandle const *dbh, unsigned reg_mask)
  {
    return ESM_registerStart((DbHandle *)dbh, reg_mask);
  }

  Status
  registerClear(DbHandle const *dbh)
  {
    return ESM_registerClear((DbHandle *)dbh);
  }

  Status
  registerEnd(DbHandle const *dbh)
  {
    return ESM_registerEnd((DbHandle *)dbh);
  }

  Status
  registerGet(DbHandle const *dbh, Register **preg)
  {
    return ESM_registerGet((DbHandle *)dbh, preg);
  }

  // FD: added
  size_t dbDescriptionSize()
  {
    return sizeof(eyedbsm::DbDescription);
  }

  // FD: added
  int *dbDescriptionSemkeys(DbDescription *vd)
  {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    return vd->semkeys;
#else
    return 0;
#endif
  }
  
}
