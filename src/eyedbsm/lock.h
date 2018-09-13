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


#include <eyedbsm_p.h>
#include <transaction.h>
#include <mutex.h>

namespace eyedbsm {
  extern void lockInit(DbDescription *, DbLock *, const char *name);
  extern void lockLightInit(DbDescription *, DbLock *);

  extern Status lockS(DbDescription *, DbLock *, unsigned int, unsigned int);

  extern Status lockX(DbDescription *, DbLock *, unsigned int, unsigned int);

  extern Status unlockS(DbDescription *, DbLock *, unsigned int);

  extern Status unlockX(DbDescription *, DbLock *, unsigned int);

  extern Status checkLock(DbDescription *, DbLock *);

  extern Status pobjLock(DbHandle const *dbh, XMHandle *,
			 const TransactionContext *,
			 Transaction *, XMOffset, 
			 LockMode lockMode, PObject *,
			 Mutex *, unsigned int, unsigned int);

  extern Status pobjUnlock(DbDescription *vd, XMHandle *, PObject *,
			   LockMode lockMode, Mutex *, unsigned int);

  extern bool findDbLockXID(DbDescription *vd, DbLock *, unsigned int, bool *,
			    Boolean);
}
