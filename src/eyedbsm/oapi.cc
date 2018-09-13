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

#include <eyedbsm/eyedbsm.h>

namespace eyedbsm {

  Status Database::dbCreate(const char *dbfile, unsigned int version,
			    const DbCreateDescription &dbc,
			    mode_t file_mask, const char *file_group)
  {
    return eyedbsm::dbCreate(dbfile, version, &dbc, file_mask, file_group);
  }

  Status Database::dbDelete(const char *dbfile)
  {
    return eyedbsm::dbDelete(dbfile);
  }

  Status Database::dbMove(const char *dbfile, const DbMoveDescription &dmv)
  {
    return eyedbsm::dbMove(dbfile, &dmv);
  }

  Status Database::dbCopy(const char *dbfile, const DbCopyDescription &dcp)
  {
    return eyedbsm::dbCopy(dbfile, &dcp);
  }

  Status Database::dbInfo(const char *dbfile, DbInfoDescription &info)
  {
    return eyedbsm::dbInfo(dbfile, &info);
  }

  Status Database::dbRelocate(const char *dbfile,
			      const DbRelocateDescription &rel)
  {
    return eyedbsm::dbRelocate(dbfile, &rel);
  }


  Database::Database()
  {
    dbh = 0;
  }


  Status Database::open(const char *_dbfile, int flags,
			const OpenHints &_hints, int uid)
  {
    dbfile = strdup(_dbfile);
    hints = _hints;
    return eyedbsm::dbOpen(dbfile, flags, &hints, uid, &version, &dbh);
  }


  unsigned int Database::getVersion() const
  {
    return version;
  }

  int Database::getOpenFlags() const
  {
    return eyedbsm::getOpenFlags(dbh);
  }

  const char *Database::getDBFile() const {
    return dbfile;
  }

  const OpenHints &Database::getOpenHints() const {
    return hints;
  }

  Status Database::close()
  {
    return eyedbsm::dbClose(dbh);
  }

  Status Database::transactionBegin(const TransactionParams &params)
  {
    return eyedbsm::transactionBegin(dbh, &params);
  }

  Status Database::transactionCommit()
  {
    return eyedbsm::transactionCommit(dbh);
  }

  Status Database::transactionAbort()
  {
    return eyedbsm::transactionAbort(dbh);
  }


  Status Database::transactionParamsSet(const TransactionParams &params)
  {
    return eyedbsm::transactionParamsSet(dbh, &params);
  }


  Status Database::transactionParamsGet(TransactionParams &params)
  {
    return eyedbsm::transactionParamsGet(dbh, &params);
  }


  Status Database::transactionLockSet(ObjectLockMode lockmode,
				      ObjectLockMode &olockmode)
  {
    return eyedbsm::transactionLockSet(dbh, lockmode, &olockmode);
  }


  Status Database::objectCreate(const void *object,
				size_t size, short dspid, Oid &oid) // V3_API_size_t
  {
    return eyedbsm::objectCreate(dbh, object, size, dspid, &oid);
  }


  Status Database::objectDelete(const Oid & oid)
  {
    return eyedbsm::objectDelete(dbh, &oid);
  }


  Status Database::objectWrite(size_t start, size_t length,
			       const void *object, const Oid & oid)
  {
    return eyedbsm::objectWrite(dbh, start, length, object, &oid);
  }


  Status Database::objectWriteCache(size_t start,
				    const void *object, const Oid & oid)
  {
    return eyedbsm::objectWriteCache(dbh, start, object, &oid);
  }


  Status Database::objectRead(size_t start, size_t length, void *object,
			      LockMode lockmode, short &pdatid,
			      size_t &psize, // V3_API_size_t
			      const Oid & oid)
  {
    return eyedbsm::objectRead(dbh, start, length, object, lockmode,
			       &pdatid, &psize, &oid);
  }


  Status Database::objectReadNoCopy(size_t start, size_t length,
				    void *object, LockMode lockmode,
				    short &pdatid, size_t &psize, // V3_API_size_t
				    const Oid & oid)
  {
    return eyedbsm::objectReadNoCopy(dbh, start, length, object, lockmode,
				     &pdatid, &psize, &oid);
  }


  Status Database::objectReadCache(size_t start, void **object,
				   LockMode lockmode, const Oid & oid)
  {
    return eyedbsm::objectReadCache(dbh, start, object, lockmode, &oid);
  }


  Status Database::objectSizeGet(size_t &size, LockMode lockmode, const Oid & oid) // V3_API_size_t
  {
    return eyedbsm::objectSizeGet(dbh, &size, lockmode, &oid);
  }


  Status Database::objectCheckAccess(Boolean write,
				     const Oid & oid, Boolean &access)
  {
    return eyedbsm::objectCheckAccess(dbh, write, &oid, &access);
  }


  Status Database::objectLocationGet(const Oid &oid, ObjectLocation &objloc)
  {
    return eyedbsm::objectLocationGet(dbh, &oid, &objloc);
  }


  Status Database::objectsLocationGet(const Oid *oid, ObjectLocation *objloc,
				      unsigned int oid_cnt)
  {
    return eyedbsm::objectsLocationGet(dbh, oid, objloc, oid_cnt);
  }


  Status Database::objectMoveDat(const Oid & oid, short datid)
  {
    return eyedbsm::objectMoveDat(dbh, &oid, datid);
  }


  Status Database::objectsMoveDat(const Oid * oid,
				  unsigned int oid_cnt, short datid)
  {
    return eyedbsm::objectsMoveDat(dbh, oid, oid_cnt, datid);
  }


  Status Database::objectMoveDsp(const Oid & oid, short dspid)
  {
    return eyedbsm::objectMoveDsp(dbh, &oid, dspid);
  }


  Status Database::objectsMoveDsp(const Oid * oid,
				  unsigned int oid_cnt, short dspid)
  {
    return eyedbsm::objectsMoveDsp(dbh, oid, oid_cnt, dspid);
  }


  Status Database::objectSizeModify(size_t size, Boolean copy, // V3_API_size_t
				    const Oid & oid)
  {
    return eyedbsm::objectSizeModify(dbh, size, copy, &oid);
  }


  Status Database::objectLock(const Oid & oid, LockMode mode,
			      LockMode &rmode)
  {
    return eyedbsm::objectLock(dbh, &oid, mode, &rmode);
  }


  Status Database::objectGetLock(const Oid & oid, LockMode &rmode)
  {
    return eyedbsm::objectGetLock(dbh, &oid, &rmode);
  }


  Status Database::objectDownLock(const Oid & oid)
  {
    return eyedbsm::objectDownLock(dbh, &oid);
  }


  Status Database::firstOidDatGet(short datid, Oid &oid, Boolean &found)
  {
    return eyedbsm::firstOidDatGet(dbh, datid, &oid, &found);
  }

  Status Database::nextOidDatGet(short datid, const Oid & baseoid,
				 Oid &nextoid, Boolean &found)
  {
    return eyedbsm::nextOidDatGet(dbh, datid, &baseoid, &nextoid, &found);
  }



  Status Database::rootEntrySet(const char *key,
				const void *data, unsigned int size, Boolean create)
  {
    return eyedbsm::rootEntrySet(dbh, key, data, size, create);
  }


  Status Database::rootEntryGet(const char *key,
				void *data, unsigned int maxsize)
  {
    return eyedbsm::rootEntryGet(dbh, key, data, maxsize);
  }

  Status Database::rootEntryDelete(const char *key)
  {
    return eyedbsm::rootEntryDelete(dbh, key);
  }


  Status Database::suserUnset()
  {
    return eyedbsm::suserUnset(dbh);
  }


  Status Database::datCreate(const char *file, const char *name,
			     unsigned long long maxsize, MapType mtype,
			     unsigned int sizeslot, DatType type,
			     mode_t file_mask, const char *file_group)
  {
    return eyedbsm::datCreate(dbh, file, name, maxsize, mtype,
			      sizeslot, type, file_mask, file_group);
  }


  Status Database::datMove(const char *datfile, const char *newdatfile)
  {
    return eyedbsm::datMove(dbh, datfile, newdatfile);
  }


  Status Database::datDelete(const char *datfile, Boolean force)
  {
    return eyedbsm::datDelete(dbh, datfile, force);
  }


  Status Database::datResize(const char *datfile,
			     unsigned long long newmaxsize)
  {
    return eyedbsm::datResize(dbh, datfile, newmaxsize);
  }


  Status Database::datMoveObjects(const char *dat_src, const char *dat_dest)
  {
    return eyedbsm::datMoveObjects(dbh, dat_src, dat_dest);
  }

		    
  Status Database::datCheck(const char *datfile, short &datid, short &dspid)
  {
    return eyedbsm::datCheck(dbh, datfile, &datid, &dspid);
  }

		    
  Status Database::datDefragment(const char *datfile,
				 mode_t file_mask, const char *file_group)
  {
    return eyedbsm::datDefragment(dbh, datfile, file_mask, file_group);
  }


  Status Database::datRename(const char *datfile, const char *name)
  {
    return eyedbsm::datRename(dbh, datfile, name);
  }


  Status Database::datGetInfo(const char *datfile, DatafileInfo &info)
  {
    return eyedbsm::datGetInfo(dbh, datfile, &info);
  }


  Status Database::datGetDspid(short datid, short &dspid)
  {
    return eyedbsm::datGetDspid(dbh, datid, &dspid);
  }


  Status Database::dspSetDefault(const char *dataspace)
  {
    return eyedbsm::dspSetDefault(dbh, dataspace);
  }


  Status Database::dspGetDefault(short &dspid)
  {
    return eyedbsm::dspGetDefault(dbh, &dspid);
  }


  Status Database::dspCreate(const char *dataspace,
			     const char **datfiles, unsigned int datfile_cnt)
  {
    return eyedbsm::dspCreate(dbh, dataspace, datfiles, datfile_cnt);
  }


  Status Database::dspUpdate(const char *dataspace,
			     const char **datfiles, unsigned int datfile_cnt)
  {
    return eyedbsm::dspUpdate(dbh, dataspace, datfiles, datfile_cnt, 0, DefaultDspid);
  }


  Status Database::dspDelete(const char *dataspace)
  {
    return eyedbsm::dspDelete(dbh, dataspace);
  }

  Status Database::dspRename(const char *dataspace,
			     const char *dataspace_new)
  {
    return eyedbsm::dspRename(dbh, dataspace, dataspace_new);
  }


  Status Database::dspCheck(const char *dataspace, short &dspid,
			    short datid[], unsigned int &ndat)
  {
    return eyedbsm::dspCheck(dbh, dataspace, &dspid, datid, &ndat);
  }

		    
  Status Database::dspSetCurDat(const char *dataspace,
				const char *datfile)
  {
    return eyedbsm::dspSetCurDat(dbh, dataspace, datfile);
  }

  Status Database::dspGetCurDat(const char *dataspace, short &datid)
  {
    return eyedbsm::dspGetCurDat(dbh, dataspace, &datid);
  }


  Status Database::objectNumberSet(unsigned int maxobjs)
  {
    return eyedbsm::objectNumberSet(dbh, maxobjs);
  }


  Status Database::protectionCreate(const ProtectionDescription &desc,
				    Oid &oid)
  {
    return eyedbsm::protectionCreate(dbh, &desc, &oid);
  }


  Status Database::protectionDelete(const Oid & oid)
  {
    return eyedbsm::protectionDelete(dbh, &oid);
  }


  Status Database::protectionModify(const ProtectionDescription &desc,
				    const Oid &oid)
  {
    return eyedbsm::protectionModify(dbh, &desc, &oid);
  }


  Status Database::protectionGetByName(const char *name,
				       ProtectionDescription **desc,
				       Oid &oid)
  {
    return eyedbsm::protectionGetByName(dbh, name, desc, &oid);
  }


  Status Database::protectionGetByOid(const Oid &oid,
				      ProtectionDescription **desc)
  {
    return eyedbsm::protectionGetByOid(dbh, &oid, desc);
  }


  Status Database::protectionListGet(Oid **oid, ProtectionDescription ***desc,
				     unsigned int &nprot)
  {
    return eyedbsm::protectionListGet(dbh, oid, desc, &nprot);
  }


  Status Database::dbProtectionAdd(const DbProtectionDescription &desc,
				   unsigned int nprot)
  {
    return eyedbsm::dbProtectionAdd(dbh, &desc, nprot);
  }


  Status Database::dbProtectionGet(DbProtectionDescription **desc,
				   unsigned int &nprot)
  {
    return eyedbsm::dbProtectionGet(dbh, desc, &nprot);
  }


  Status Database::objectProtectionSet(const Oid & oid,
				       const Oid & protoid)
  {
    return eyedbsm::objectProtectionSet(dbh, &oid, &protoid);
  }

  Status Database::objectProtectionGet(const Oid & oid,
				       Oid *protoid)
  {
    return eyedbsm::objectProtectionGet(dbh, &oid, protoid);
  }


  Boolean Database::isPhysicalOid(const Oid &oid)
  {
    return eyedbsm::isPhysicalOid(dbh, &oid);
  }


  Status Database::registerStart(unsigned reg_mask)
  {
    return eyedbsm::registerStart(dbh, reg_mask);
  }


  Status Database::registerClear()
  {
    return eyedbsm::registerClear(dbh);
  }

  Status Database::registerEnd()
  {
    return eyedbsm::registerEnd(dbh);
  }

  Status Database::registerGet(Register **preg)
  {
    return eyedbsm::registerGet(dbh, preg);
  }

  Database::~Database()
  {
    free(dbfile);
  }
}
