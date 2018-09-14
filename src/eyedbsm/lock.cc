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

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <lock.h>

#include <eyedbsm_p.h>
#include <eyedblib/iassert.h>
#include <eyedblib/rpc_be.h>
#include <eyedblib/log.h>

// FD CHECK: include a lib/ private header
#include <lib/m_mem_p.h>

#define TRACE(X) /*(X, fflush(stdout))*/

#define DBLOCK_LOCK(VD, XID)           MUTEX_LOCK_VOID(DBLOCK_MTX(VD), XID)
#define DBLOCK_UNLOCK(VD, XID)         MUTEX_UNLOCK(DBLOCK_MTX(VD), XID)
#define DBLOCK_COND_WAIT_R(VD, XID, TM)  COND_WAIT_R(DBLOCK_COND(VD), DBLOCK_MTX(VD), XID, TM)
#define DBLOCK_COND_SIGNAL(VD)         COND_SIGNAL(DBLOCK_COND(VD))

#define MKXID(X, XID) XID

#define SX_MODE

#define CHECK_CONN(X) \
if (rpc_checkConn() < 0) \
{ \
 X; \
 return statusMake(CONN_RESET_BY_PEER, ""); \
}

#define TIMEOUT 10

#define WAIT_CHECK(MAXTIME, NS, X, FMT, MSG) \
do { \
  IDB_LOG(IDB_LOG_MTX, ("object locked. Waiting for maxtime=%d\n", MAXTIME)); \
  if (backend_interrupt) { \
    backend_interrupt = False; \
    X; \
    fprintf(stderr, "backend interrupt!\n"); \
    return statusMake(BACKEND_INTERRUPTED, FMT, MSG); \
  } \
  else if (NS < 0) { \
    MAXTIME += NS; \
    if ((int)(MAXTIME) <= 0) { \
      X; \
      return statusMake(LOCK_TIMEOUT, FMT, MSG); \
    } \
  } \
  else if (NS > 0) { \
    X; \
    if (errno != 0) \
      perror("lock"); \
    return statusMake(INTERNAL_ERROR, FMT ": cannot acquire lock", MSG); \
  } \
} \
while(0)

namespace eyedbsm {

  static Status addXid(DbLock *dblock, Mutex *mp, unsigned int xid)
  {
    int i;
    unsigned int *pxid = dblock->xidS;

    for (i = 0; i < MAXCLIENTS_PERDB; i++, pxid++)
      if (!*pxid) {
	*pxid = xid;
	return Success;
      }

    ESM_ASSERT(0, mp, xid);
  }

  static Status
  rmXid(DbLock *dblock, Mutex *mp, unsigned int xid)
  {
    int i;
    unsigned int *pxid = dblock->xidS;

    for (i = 0; i < MAXCLIENTS_PERDB; i++, pxid++)
      if (*pxid == xid)	{
	*pxid = 0;
	return Success;
      }

    ESM_ASSERT(0, mp, xid);
  }

  void lockInit(DbDescription *vd, DbLock *dblock, const char *name)
  {
    mutexInit(vd, DBLOCK_MTX(vd), &dblock->mp, name);
    condInit(vd, DBLOCK_COND(vd), &dblock->cond_wait);
    dblock->X = 0;
    dblock->S = 0;
    dblock->wt_cnt = 0;
    dblock->xidX = 0;
    memset(dblock->xidS, 0, MAXCLIENTS_PERDB * sizeof(unsigned int));
  }

  void lockLightInit(DbDescription *vd, DbLock *dblock)
  {
    mutexLightInit(vd, DBLOCK_MTX(vd), &dblock->mp);
    condLightInit(vd, DBLOCK_COND(vd), &dblock->cond_wait);
  }

  bool findDbLockXID(DbDescription *vd, DbLock *dblock, unsigned int xid,
		     bool *lockX, Boolean mustLock)
  {
    int i;
    unsigned int *pxid;

    if (mustLock)
      DBLOCK_LOCK(vd, xid);
    if (xid == dblock->xidX) {
      if (mustLock)
	DBLOCK_UNLOCK(vd, xid);
      if (lockX)
	*lockX = true;
      return true;
    }

    pxid = dblock->xidS;

    for (i = 0; i < MAXCLIENTS_PERDB; i++, pxid++)
      if (*pxid == xid) {
	if (mustLock)
	  DBLOCK_UNLOCK(vd, xid);
	if (lockX)
	  *lockX = false;
	return true;
      }

    if (mustLock)
      DBLOCK_UNLOCK(vd, xid);
    return false;
  }

  Status
  lockS(DbDescription *vd, DbLock *dblock, unsigned int xid,
	unsigned int timeout)
  {
    int x;
    unsigned int maxtime = timeout;
    Status se;

    TRACE(printf("\n------LOCK_S------ thread = %d, timeout = %d\n\n",
		 thr_self(), timeout));

    for (x = 0; ; x++) {
      if (!x)
	DBLOCK_LOCK(vd, xid);

      if (!dblock->X) {
	dblock->S++;
	se = addXid(dblock, &vd->mp[MTX_CNT], xid);
	DBLOCK_UNLOCK(vd, MKXID(x, xid));
	TRACE(printf("\n------LOCK_S DONE------ thread = %d\n\n", thr_self()));
	if (se)
	  return se;
	break;
      }
      else if (!timeout) {
	WAIT_CHECK(maxtime, -1, DBLOCK_UNLOCK(vd, MKXID(x, xid)),
		   "beginning transaction", "");
      }
      else {
	NS ns;

	CHECK_CONN(DBLOCK_UNLOCK(vd, MKXID(x, xid)));

	dblock->wt_cnt++;
	ns = DBLOCK_COND_WAIT_R(vd, xid, (timeout < TIMEOUT ? timeout : TIMEOUT));
	dblock->wt_cnt--;

	WAIT_CHECK(maxtime, ns, DBLOCK_UNLOCK(vd, MKXID(x, xid)),
		   "beginning transaction", "");
      }
    }
    return Success;
  }

  Status
  unlockS(DbDescription *vd, DbLock *dblock, unsigned int xid)
  {
    Status se;
    DBLOCK_LOCK(vd, xid);

    if (dblock->S <= 0) {
      fprintf(stderr, "error dblockS == %d\n", dblock->S);
      DBLOCK_UNLOCK(vd, xid);
      return Success;
    }

    dblock->S--;
    se = rmXid(dblock, DBLOCK_MTX(vd), xid);

    if (dblock->wt_cnt) {
      TRACE(printf("cond_signal!!\n"));
      DBLOCK_COND_SIGNAL(vd);
    }
    DBLOCK_UNLOCK(vd, xid);
    TRACE(printf("\n------UNLOCK_S DONE------ thread = %d\n\n", thr_self()));
    return se;
  }

  Status
  lockX(DbDescription *vd, DbLock *dblock, unsigned int xid,
	unsigned int timeout)
  {
    int x;
    unsigned int maxtime = timeout;
    TRACE(printf("\n------LOCK_X------ thread = %d, timeout = %d\n\n",
		 thr_self(), timeout));

    for (x = 0; ; x++) {
      if (!x)
	DBLOCK_LOCK(vd, xid);

      if (!dblock->X && !dblock->S) {
	dblock->X = 1;
	dblock->xidX = xid;
	DBLOCK_UNLOCK(vd, MKXID(x, xid));
	TRACE(printf("\n------LOCK_X DONE------ thread = %d\n\n", thr_self()));
	TRACE(printf("LOCX done after %d times\n", x));
	break;
      }
      else if (!timeout) {
	WAIT_CHECK(maxtime, -1, DBLOCK_UNLOCK(vd, MKXID(x, xid)),
		   "beginning transaction", "");
      }
      else {
	NS ns;

	CHECK_CONN(DBLOCK_UNLOCK(vd, MKXID(x, xid)));

	dblock->wt_cnt++;
	ns = DBLOCK_COND_WAIT_R(vd, xid, (timeout < TIMEOUT ? timeout : TIMEOUT));
	dblock->wt_cnt--;
	TRACE(printf("awaken!!!\n"));
	WAIT_CHECK(maxtime, ns, DBLOCK_UNLOCK(vd, MKXID(x, xid)),
		   "beginning transaction", "");
      }
    }
    return Success;
  }

  Status
  unlockX(DbDescription *vd, DbLock *dblock, unsigned int xid)
  {
    DBLOCK_LOCK(vd, xid);

    ESM_ASSERT(dblock->X == 1, &dblock->mp, xid);
    dblock->X = 0;

    ESM_ASSERT(dblock->xidX == xid, &dblock->mp, xid);

    dblock->xidX = 0;
    if (dblock->wt_cnt) {
      TRACE(printf("cond_signal!!\n"));
      DBLOCK_COND_SIGNAL(vd);
    }
    DBLOCK_UNLOCK(vd, xid);
    TRACE(printf("\n------UNLOCK_X DONE------ thread = %d\n\n", thr_self()));
    return Success;
  }

  Status
  checkLock(DbDescription *vd, DbLock *dblock)
  {
    assert(dblock);
    TRACE(printf("checkLOCK = 0x%x\n", *(unsigned long *)((char *)dblock + sizeof(DbLock))));
    return Success;
  }

  /* pobject part */
  /* these functions assumes that mp is already locked! */

  /*
    #undef TRACE
    #define TRACE(X) X
  */

  Status
  pobjLock(DbHandle const *dbh, XMHandle *xmh,
	   const TransactionContext *trctx,
	   Transaction *trs, XMOffset tro_off, 
	   LockMode lockMode, PObject *po,
	   Mutex *mp, unsigned int xid, unsigned int timeout)
  {
    unsigned int maxtime = timeout;
    TRACE(printf("\n------POBJLOCK_S------ thread = %d\n\n", thr_self()));

    for (;;) {
      if (lockMode == LockX) {
	if (!po->lockX && !po->lockS && !po->lockSX) {
	  po->lockX = 1;
	  break;
	}
      }
      else if (lockMode == LockS) {
	if (!po->lockX)
	  {
	    po->lockS++;
	    break;
	  }
      }
      else if (lockMode == LockSX) {
	if (!po->lockX && !po->lockSX)
	  {
	    po->lockSX = 1;
	    break;
	  }
      }

      if (!timeout)
	WAIT_CHECK(maxtime, 1, 0, "locking object %s", getOidString(&po->oid));
      else {
	CondWait cond;
	Status se;
	NS ns;

	CHECK_CONN(0);

	se = deadLockCheck(xmh, trs, po, LockS);

	if (se)
	  return se;

	if (po->cond)
	  condMake(dbh->vd, xmh, po->cond, &cond);
	else
	  po->cond = condNew(dbh->vd, xmh, &cond);

	trs->trobj_wait = tro_off;
	trs->lock_wait = LockS;

	se = ESM_transactionsGarbage(dbh, False);

	if (se)
	  return se;

	po->wait_cnt++;
	ns = COND_WAIT_R(&cond, mp, xid, (timeout < TIMEOUT ? timeout : TIMEOUT));
	trs->trobj_wait = XM_NULLOFFSET;
	trs->lock_wait = (LockMode)0;
	po->wait_cnt--;

	WAIT_CHECK(maxtime, ns, 0, "locking object %s", getOidString(&po->oid));
      }
    }
    return Success;
  }

  Status
  pobjUnlock(DbDescription *vd, XMHandle *xmh, PObject *po,
	     LockMode lockMode, Mutex *mp, unsigned int xid)
  {
    if (lockMode == LockX) {
      ESM_ASSERT(po->lockX == 1, mp, xid);
      po->lockX = 0;
    }
    else if (lockMode == LockSX) {
      ESM_ASSERT(po->lockSX == 1, mp, xid);
      po->lockSX = 0;
    }
    else if (lockMode == LockS) {
      ESM_ASSERT(po->lockS > 0, mp, xid);
      po->lockS--;
    }

    if (po->wait_cnt) {
      CondWait cond;
      COND_SIGNAL(condMake(vd, xmh, po->cond, &cond));
    }

    return Success;
  }
}
