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


#ifndef _EYEDBSM_IDXP_H
#define _EYEDBSM_IDXP_H

#include "transaction.h"
#include <assert.h>

namespace eyedbsm {
class IdxLock {

  ObjectLockMode olockmode;
  DbHandle *dbh;
  const Oid &treeOid;
  Boolean lockedPerformed;
  Boolean locked;

 public:
  IdxLock(DbHandle *_dbh, const Oid &_treeOid) :
    dbh(_dbh), treeOid(_treeOid), lockedPerformed(False), locked(False)
    { }

  Status lock() {
    lockedPerformed = True;
    /* warning; was OWRITE|LOCKX */
    Status s = objectLock(dbh, &treeOid, LockX, 0);
    if (s) return s;

    transactionLockSet(dbh, ReadSWriteX, &olockmode);
    locked = True;
    return Success;
  }

  ~IdxLock() {
    assert(lockedPerformed);

    if (locked)
      transactionLockSet(dbh, olockmode, 0);
  }
};

}

#endif
