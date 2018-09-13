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

/*#define TRS_DBG*/


#define CRASH(X) if (getenv(#X)) {printf(#X ## "\n"); exit(1);}

#ifdef TRS_DBG
#define TT(X) X
#else
#define TT(X)
#endif

/*#define NEW_TR_CNT*/

static const char trTooLarge[] = 
"no shmspace left in transaction file: transaction too large";

#ifdef NEW_TR_CNT
#define TR_CNT(DBH) ((DBH)->vd->shm_addr->trs_hdr.tr_cnt)
#else
#define TR_CNT(DBH) ((DBH)->vd->tr_cnt)
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <eyedblib/machtypes.h>
#include <eyedblib/rpc_lib.h>
#include <eyedbsm_p.h>
#include <transaction.h>
#include <hashtable.h>
#include <lock.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include <eyedblib/iassert.h>
#include <eyedblib/log.h>
#include <eyedblib/butils.h>

#define _ESM_C_
#include <eyedblib/rpc_be.h>
#include <kern.h>
#include <kern_p.h>
#include <eyedblib/semlib.h>

//#define NO_INTERNAL_LOCK

#ifdef TRS_INTER_MUT
#define MUTEX_LOCKER eyedbsm::MutexLocker
#else
#define MUTEX_LOCKER eyedblib::MutexLocker
#endif

/* 24/08/01 */
#define LAZY_LOCK_X

namespace eyedbsm {

  Boolean trace_garb_trs = False;

  static TransactionParams defparams = DEFAULT_TRANSACTION_PARAMS;

  static void
  ESM_transactionRegister(Transaction *trs, Mutex *mp, unsigned int xid);
  static void

  ESM_transactionUnregister(Transaction *trs, Mutex *mp, unsigned int xid);

  static TransactionOP crossOps[OP_CNT][OP_CNT] = {
    /*             OCREATE  OREAD    OWRITE   ODELETE  OCREADEL  OCHSIZE OERROR */

    /* OCREATE  */ OCREATE, OCREATE, OCREATE, OCREADEL, OERROR, OCREATE, OERROR,

    /* OREAD    */ OERROR,  OREAD,   OWRITE,  ODELETE, OERROR, OCHSIZE, OERROR,

    /* OWRITE   */ OERROR,  OWRITE,  OWRITE,  ODELETE, OERROR, OCHSIZE, OERROR,

    /* ODELETE  */ OERROR,  OERROR,  OERROR,  OERROR,  OERROR, OERROR,  OERROR,
    /* OCREADEL */ OERROR,  OERROR,  OERROR,  OERROR,  OERROR, OERROR,  OERROR,

    // changed the 30/01/02
    // /* OCHSIZE  */ OERROR,  OCHSIZE, OCHSIZE, ODELETE, OCHSIZE, OERROR,
    /* OCHSIZE  */ OERROR,  OCHSIZE, OWRITE, ODELETE, OCHSIZE, OERROR,

    /* OERROR   */ OERROR,  OERROR,  OERROR,  OERROR,  OERROR,  OERROR
  };

  static int opSync[OP_CNT] = {
    /* OCREATE  */ 1,
    /* OREAD    */ 1,
    /* OWRITE   */ 0,
    /* ODELETE  */ 0,
    /* OCHSIZE  */ 0,
    /* OERROR   */ 0
  };

  static Boolean trs_initialized = False;
  static LockMode opLockMode[OP_CNT][LockModeIndex_CNT];
  static OP lock2op[LockE+1];

#define DEF_MAGORDER        10240
#define MAX_MAGORDER      2000000

  /*extern "C" */ int trs_init(void)
  {
    if (trs_initialized)
      return 0;

    lock2op[LockN]  = LockNOP;
    lock2op[LockS]  = LockSOP;
    lock2op[LockX]  = LockXOP;
    lock2op[LockSX] = LockSXOP;
    lock2op[LockP]  = LockPOP;

    opLockMode[OCREATE] [R_S_W_S] = LockP;
    opLockMode[OREAD]   [R_S_W_S] = LockS;
    opLockMode[OWRITE]  [R_S_W_S] = LockS;
    opLockMode[ODELETE] [R_S_W_S] = LockS;
    opLockMode[OCHSIZE] [R_S_W_S] = LockS;
    opLockMode[OERROR]  [R_S_W_S] = LockE;

    opLockMode[OCREATE] [R_S_W_SX] = LockP;
    opLockMode[OREAD]   [R_S_W_SX] = LockS;
    opLockMode[OWRITE]  [R_S_W_SX] = LockSX;
    opLockMode[ODELETE] [R_S_W_SX] = LockSX;
    opLockMode[OCHSIZE] [R_S_W_SX] = LockSX;
    opLockMode[OERROR]  [R_S_W_SX] = LockE;

    opLockMode[OCREATE] [R_S_W_X] = LockP;
    opLockMode[OREAD]   [R_S_W_X] = LockS;
    opLockMode[OWRITE]  [R_S_W_X] = LockX;
    opLockMode[ODELETE] [R_S_W_X] = LockX;
    opLockMode[OCHSIZE] [R_S_W_X] = LockX;
    opLockMode[OERROR]  [R_S_W_X] = LockE;

    opLockMode[OCREATE] [R_SX_W_SX] = LockP;
    opLockMode[OREAD]   [R_SX_W_SX] = LockSX;
    opLockMode[OWRITE]  [R_SX_W_SX] = LockSX;
    opLockMode[ODELETE] [R_SX_W_SX] = LockSX;
    opLockMode[OCHSIZE] [R_SX_W_SX] = LockSX;
    opLockMode[OERROR]  [R_SX_W_SX] = LockE;

    opLockMode[OCREATE] [R_SX_W_X] = LockP;
    opLockMode[OREAD]   [R_SX_W_X] = LockSX;
    opLockMode[OWRITE]  [R_SX_W_X] = LockX;
    opLockMode[ODELETE] [R_SX_W_X] = LockX;
    opLockMode[OCHSIZE] [R_SX_W_X] = LockX;
    opLockMode[OERROR]  [R_SX_W_X] = LockE;

    opLockMode[OCREATE] [R_X_W_X] = LockP;
    opLockMode[OREAD]   [R_X_W_X] = LockX;
    opLockMode[OWRITE]  [R_X_W_X] = LockX;
    opLockMode[ODELETE] [R_X_W_X] = LockX;
    opLockMode[OCHSIZE] [R_X_W_X] = LockX;
    opLockMode[OERROR]  [R_X_W_X] = LockE;

    opLockMode[OCREATE] [R_N_W_S] = LockP;
    opLockMode[OREAD]   [R_N_W_S] = LockN;
    opLockMode[OWRITE]  [R_N_W_S] = LockS;
    opLockMode[ODELETE] [R_N_W_S] = LockS;
    opLockMode[OCHSIZE] [R_N_W_S] = LockS;
    opLockMode[OERROR]  [R_N_W_S] = LockE;

    opLockMode[OCREATE] [R_N_W_SX] = LockP;
    opLockMode[OREAD]   [R_N_W_SX] = LockN;
    opLockMode[OWRITE]  [R_N_W_SX] = LockSX;
    opLockMode[ODELETE] [R_N_W_SX] = LockSX;
    opLockMode[OCHSIZE] [R_N_W_SX] = LockSX;
    opLockMode[OERROR]  [R_N_W_SX] = LockE;

    opLockMode[OCREATE] [R_N_W_X] = LockP;
    opLockMode[OREAD]   [R_N_W_X] = LockN;
    opLockMode[OWRITE]  [R_N_W_X] = LockX;
    opLockMode[ODELETE] [R_N_W_X] = LockX;
    opLockMode[OCHSIZE] [R_N_W_X] = LockX;
    opLockMode[OERROR]  [R_N_W_X] = LockE;

    opLockMode[OCREATE] [R_N_W_N] = LockP;
    opLockMode[OREAD]   [R_N_W_N] = LockN;
    opLockMode[OWRITE]  [R_N_W_N] = LockN;
    opLockMode[ODELETE] [R_N_W_N] = LockN;
    opLockMode[OCHSIZE] [R_N_W_N] = LockN;
    opLockMode[OERROR]  [R_N_W_N] = LockE;

    trs_initialized = True;

    return 0;
  }

  static bool must_lock_db(DbHandle const *dbh)
  {
#ifdef LAZY_LOCK_X
    return dbh->vd->flags == VOLRW;
#else
    return true;
#endif
  }

  static int
  magorderHtCount(int magorder)
  {
    int n = magorder/20;
    int p = 1;

    for (;;) {
      if (p >= n)
	break;
      p <<= 1;
    }

    return p;
  }

  static Boolean
  ESM_transactionParamsCompare(const TransactionParams *params1,
			       const TransactionParams *params2,
			       Boolean compare_all)
  {
    int r;
    if (params1 == 0 && params2 != 0)
      return False;

    if (params1 != 0 && params2 == 0)
      return False;

    if (params1 == 0 && params2 == 0)
      return True;

    r = (params1->trsmode == params2->trsmode &&
	 params1->recovmode == params2->recovmode &&
	 params1->magorder == params2->magorder);

    if (!compare_all || !r)
      return r ? True : False;

    return (r &&
	    params1->lockmode == params2->lockmode &&
	    params1->ratioalrt == params2->ratioalrt &&
	    params1->wait_timeout == params2->wait_timeout) ? True : False;
  }

  static Status
  ESM_transactionLockModeIdx_realize(DbHandle const *dbh,
				     TransactionContext *trctx,
				     ObjectLockMode lockmode)
  {
    if (lockmode == ReadSWriteS)
      trctx->lockmodeIndex = R_S_W_S;
    else if (lockmode == ReadSWriteSX)
      trctx->lockmodeIndex = R_S_W_SX;
    else if (lockmode == ReadSWriteX)
      trctx->lockmodeIndex = R_S_W_X;

    else if (lockmode == ReadSXWriteSX)
      trctx->lockmodeIndex = R_SX_W_SX;
    else if (lockmode == ReadSXWriteX)
      trctx->lockmodeIndex = R_SX_W_X;

    else if (lockmode == ReadXWriteX)
      trctx->lockmodeIndex = R_X_W_X;

    else if (lockmode == ReadNWriteS)
      trctx->lockmodeIndex = R_N_W_S;
    else if (lockmode == ReadNWriteSX)
      trctx->lockmodeIndex = R_N_W_SX;
    else if (lockmode == ReadNWriteX)
      trctx->lockmodeIndex = R_N_W_X;
    else if (lockmode == ReadNWriteN)
      trctx->lockmodeIndex = R_N_W_N;

    else if (lockmode == DatabaseW)
      trctx->lockmodeIndex = DB_W;
    else if (lockmode == DatabaseRW)
      trctx->lockmodeIndex = DB_RW;
    else if (lockmode == DatabaseWtrans)
      trctx->lockmodeIndex = DB_Wtrans;

    else
      return statusMake(INVALID_TRANSACTION_MODE,
			"transaction lock mode %d", lockmode);

    return Success;
  }

  static Status
  ESM_transactionParamsSet_realize(DbHandle const *dbh,
				   TransactionContext *trctx,
				   const TransactionParams *params,
				   const TransactionParams *oparams)
				
  {
    Status se;

    /* checking individualy trsmode */
    if (params->trsmode != TransactionOff &&
	params->trsmode != TransactionOn)
      return statusMake(INVALID_TRANSACTION_MODE,
			"transaction mode %d", params->trsmode);

    /* checking individualy recovmode */
    if (params->recovmode != RecoveryOff &&
	params->recovmode != RecoveryPartial &&
	params->recovmode != RecoveryFull)
      return statusMake(INVALID_TRANSACTION_MODE,
			"transaction recovery mode %d", params->recovmode);

    /* checking individualy lockmode */
    se = ESM_transactionLockModeIdx_realize(dbh, trctx, params->lockmode);
    if (se) return se;

    /* checking incompatibily modes */
    if ((params->recovmode == RecoveryPartial ||
	 params->recovmode == RecoveryFull) &&
	params->trsmode == TransactionOff)
      return statusMake(INVALID_TRANSACTION_MODE,
			"cannot have recovery on with transaction off mode");

    /* checking old params vs. new params: only lockmode, timeout and
       ratioalrt may be changed */
    if (oparams &&
	!ESM_transactionParamsCompare(params, oparams, False))
      return statusMake(INVALID_TRANSACTION_MODE,
			"only lockmode, timeout and ratioalrt can be changed"
			"dynamically");

    if (params->lockmode == DatabaseW && oparams &&
	oparams->lockmode != params->lockmode)
      return statusMake(INVALID_TRANSACTION_MODE,
			"cannot change dynamically to database W lockmode");

    if (params->lockmode == DatabaseRW && oparams &&
	oparams->lockmode != params->lockmode)
      return statusMake(INVALID_TRANSACTION_MODE,
			"cannot change dynamically to database RW lockmode");

    if (params->lockmode == DatabaseWtrans && oparams &&
	oparams->lockmode != params->lockmode)
      return statusMake(INVALID_TRANSACTION_MODE,
			"cannot change dynamically to database Wtrans lockmode");

    trctx->params = *params;

    if (params->magorder < DEF_MAGORDER)
      trctx->params.magorder = DEF_MAGORDER;
    else if (params->magorder > MAX_MAGORDER)
      trctx->params.magorder = MAX_MAGORDER;
    else
      trctx->params.magorder = params->magorder;

    if (params->trsmode == TransactionOff &&
	(params->lockmode == ReadNWriteN ||
	 params->lockmode == DatabaseW ||
	 params->lockmode == DatabaseRW))
      trctx->skip = True;
    else
      trctx->skip = False;

    return Success;
  }

  Status
  ESM_transactionParamsSet(DbHandle const *dbh,
			   const TransactionParams *params)
  {
    TransactionContext *trctx;

    if (!TR_CNT(dbh))
      return statusMake(TRANSACTION_NEEDED, "transaction needed in transactionParamsSet");

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    if (ESM_transactionParamsCompare(params, &trctx->params, True))
      return Success;

    if (!params)
      params = &defparams;

    return ESM_transactionParamsSet_realize(dbh, trctx, params, &trctx->params);
  }

  Status
  ESM_transactionParamsGet(DbHandle const *dbh,
			   TransactionParams *params)
  {
    TransactionContext *trctx;

    if (!TR_CNT(dbh))
      return statusMake(TRANSACTION_NEEDED, "transaction needed in transactionParamsGet");

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    *params   = trctx->params;

    return Success;
  }

  Boolean
  ESM_isExclusive(DbHandle const *dbh)
  {
    if (!TR_CNT(dbh))
      return False;

    return dbh->vd->trctx[TR_CNT(dbh)-1].params.lockmode == DatabaseW ||
      dbh->vd->trctx[TR_CNT(dbh)-1].params.lockmode == DatabaseRW ?
      True : False;
  }

  Status
  ESM_transactionBegin(DbHandle const *dbh,
		       const TransactionParams *params)
  {
    if (dbh->vd->flags & NO_SHM_ACCESS) {
      return Success;
    }

    TransactionContext *trctx;
    unsigned int xid = dbh->vd->xid;
    DbLock *dblock_W = &dbh->vd->shm_addr->dblock_W;
    Status se;

    if (TR_CNT(dbh) >= MAXTRS)
      return statusMake(TOO_MANY_TRANSACTIONS, "maximum transaction excedeed [max=%d]", MAXTRS);
  
    if (!params)
      params = &defparams;

    IDB_LOG(IDB_LOG_TRANSACTION, ("transaction xid=%d begin "
				  "trsmode=%p, lockmode=%d, recovmode=%d, "
				  "magorder=%u , ratioalrt=%u, timeout=%u",
				  xid,
				  params->trsmode,
				  params->lockmode,
				  params->recovmode,
				  params->magorder,
				  params->ratioalrt,
				  params->wait_timeout));

    trctx = &dbh->vd->trctx[TR_CNT(dbh)++];

    if (se = ESM_transactionParamsSet_realize(dbh, trctx, params, 0)) {
      TR_CNT(dbh)--;
      return se;
    }

    IDB_LOG(IDB_LOG_TRANSACTION, ("lockmode index=%p\n", trctx->lockmodeIndex));

    if (params->lockmode == DatabaseW) {
      se = lockX(dbh->vd, dblock_W, xid, trctx->params.wait_timeout);
      if (se) {
	TR_CNT(dbh)--;
	return se;
      }
    }
    else if (must_lock_db(dbh)) {
      se = lockS(dbh->vd, dblock_W, xid, trctx->params.wait_timeout);
      if (se) {
	TR_CNT(dbh)--;
	return se;
      }
    }

    if (trctx->skip)
      trctx->trs_off = 0;
    else {
      se = ESM_transactionCreate(dbh, &trctx->params, &trctx->trs_off);
      if (se)
	return se;

      if (!trctx->trs_off) {
	TR_CNT(dbh)--;
	return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
      }
    }

    dbh->vd->shm_addr->stat.tr_begin_cnt = h2x_u32(x2h_u32(dbh->vd->shm_addr->stat.tr_begin_cnt)+1);

    return Success;
  }

  static  void
  ESM_transactionProtectionsAdvise(DbHandle const *dbh)
  {
    TransHeader *trshd;
    Transaction *trs;
    DbShmHeader *shmh = dbh->vd->shm_addr;
    /*  Mutex *mp = &shmh->mtx.mp[TRS];*/
    Mutex *mp = TRS_MTX(dbh);
    XMHandle *xmh = dbh->vd->trs_mh;
    Status se;

    trshd = &shmh->trs_hdr;

    se = MUTEX_LOCK_VOID(mp, 0);
    if (se) {
      IDB_LOG(IDB_LOG_TRANSACTION, (statusGet(se)));
      return;
    }

    trs = (Transaction *)XM_ADDR(xmh, trshd->first_trs);

    while (trs) {
      trs->prot_update = True;
      trs = (Transaction *)XM_ADDR(xmh, trs->next);
    }

    MUTEX_UNLOCK(mp, 0);
  }

  Boolean
  ESM_protectionsMustUpdate(DbHandle const *dbh)
  {
    TransactionContext *trctx;
    Transaction *trs;
    Boolean prot_update;

    if (TR_CNT(dbh) == 0)
      return False;

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];
    trs = (Transaction *)XM_ADDR(dbh->vd->trs_mh, trctx->trs_off);
#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif

    prot_update = trs->prot_update;
    trs->prot_update = False;
    return prot_update;
  }

  Status
  ESM_transactionLockSet(DbHandle const *dbh, ObjectLockMode lockmode,
			 ObjectLockMode *olockmode)
  {
    TransactionContext *trctx;

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    if (olockmode)
      *olockmode = trctx->params.lockmode;
    trctx->params.lockmode = lockmode;

    return ESM_transactionLockModeIdx_realize(dbh, trctx, lockmode);
  }

  static void
  ESM_PObjectChangeTransOwnerLock(XMHandle *xmh, PObject *po,
				  XMOffset trs_off, LockMode lock,
				  Mutex *mp, unsigned int xid);

#define ESM_REGISTER_LOCK(dbh, lock) \
do { \
 if ((dbh)->vd->reg && (dbh)->vd->reg_mask) { \
    OP op = lock2op[lock]; \
    ESM_REGISTER(dbh, op, ESM_addToRegisterLock(dbh, oid, op)); \
 } \
} while(0)

  Status
  ESM_objectDownLock(DbHandle const *dbh, Oid const *const oid)
  {
    TransactionContext *trctx;
    XMHandle *xmh;
    Transaction *trs;
    HashTable *trs_ht;
    HashTable *obj_ht;
    XMOffset tro_off;
    XMOffset po_off;
    TRObject *tro;
    PObject *po;
    Mutex *mp = TRS_MTX(dbh);
    unsigned int xid = dbh->vd->xid;
    Status se = Success;

    /*printf("MUST DOWN LOCK %s\n", getOidString(oid));*/

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    if (trctx->skip || !NEED_OBJLOCK(trctx))
      return Success;

    xmh = dbh->vd->trs_mh;

    trs = (Transaction *)XM_ADDR(xmh, trctx->trs_off);

    ESM_ASSERT(trs->magic == TRS_MAGIC, 0, xid);

    obj_ht = (HashTable *)XM_ADDR(xmh, dbh->vd->shm_addr->trs_hdr.obj_ht);
    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    tro_off = HashTableTRObjectLookup(xmh, trs_ht, oid);

    tro = (TRObject *)XM_ADDR(xmh, tro_off);
    MUTEX_LOCKER trolock(tro->mut);

#ifndef NO_INTERNAL_LOCK
    mtlock.unlock();
#endif
      
    if (!tro->lockSX && !tro->lockX && !tro->lockP)
      return statusMake(ERROR, "object '%s' is neither lock X, nor lock SX, nor lock P",
			getOidString(oid));

#ifdef TRS_SECURE
    ESM_ASSERT(tro->magic == TROBJ_MAGIC, 0, 0);
#endif

    po = (PObject *)XM_ADDR(xmh, tro->po_off);

#ifdef TRS_SECURE
    ESM_ASSERT(po->magic == POBJ_MAGIC, 0, 0);
#endif

    //ESM_REGISTER(dbh, LockSOP, ESM_addToRegisterLock(dbh, oid, False));

    MUTEX_LOCK(mp, xid);

    se = pobjUnlock(dbh->vd, xmh, po, LockX, mp, xid);

    tro->lockX = 0;

    if (!se) {
      se = pobjLock(dbh, xmh, trctx, trs, tro_off, LockS, po, mp, xid,
		    trctx->params.wait_timeout);
      if (!se) {
	tro->lockS++;
	ESM_PObjectChangeTransOwnerLock(xmh, po, trctx->trs_off,
					LockS, mp, xid);
	ESM_REGISTER_LOCK(dbh, LockS);
      }
    }

    MUTEX_UNLOCK(mp, xid);

    return se;
  }

  Status
  ESM_transactionRealize(DbHandle const *dbh, TransState state)
  {
    if (dbh->vd->flags & NO_SHM_ACCESS) {
      return Success;
    }

    TransactionContext *trctx;
    DbLock *dblock_W = &dbh->vd->shm_addr->dblock_W;
    unsigned int xid = dbh->vd->xid;

    if (!TR_CNT(dbh))
      return statusMake(TRANSACTION_NEEDED,
			"transaction needed in %s",
			(state == TransCOMMITING ? "transactionBegin" :
			 "transactionAbort"));

    trctx = &dbh->vd->trctx[--TR_CNT(dbh)];

    Status se = Success;

    // 15/09/06:
    // why the unlock is before the ESM_transactionDelete !?
    // I think, it should be after...
    // => #define NEW_DBLOCK

#define NEW_DBLOCK

#ifdef NEW_DBLOCK
    if (!trctx->skip)
      se = ESM_transactionDelete(dbh, trctx->trs_off, state);
#endif

    if (findDbLockXID(dbh->vd, dblock_W, xid, 0, False)) {
      if (trctx->params.lockmode == DatabaseW)
	unlockX(dbh->vd, dblock_W, xid);
      else if (must_lock_db(dbh))
	unlockS(dbh->vd, dblock_W, xid);
    }

#ifndef NEW_DBLOCK
    if (!trctx->skip)
      se = ESM_transactionDelete(dbh, trctx->trs_off, state);
#endif

    trctx->trs_off = 0;

    if (state == TransABORTING)
      ESM_protectionsRunTimeUpdate(dbh);
    else
      ESM_transactionProtectionsAdvise(dbh);

    return se;
  }

  Status
  ESM_transactionCommit(DbHandle const *dbh)
  {
    return ESM_transactionRealize(dbh, TransCOMMITING);
  }

  Status
  ESM_transactionAbort(DbHandle const *dbh)
  {
    return ESM_transactionRealize(dbh, TransABORTING);
  }

  static TRObject *
  makeTRObject(DbHandle const *dbh, const Oid *oid,
	       TransactionOP op, LockMode lock, HashTable *trs_ht,
	       TransactionContext *trctx, XMOffset *tro_off,
	       Mutex *mp, unsigned int xid)
  {
    TRObject *tro;
    XMHandle *xmh = dbh->vd->trs_mh;

    tro = (TRObject *)XMAlloc(xmh, sizeof(TRObject));

    if (!tro)
      return 0;

    tro->op = op;

#ifdef TRS_SECURE
    tro->magic = TROBJ_MAGIC;
#endif
    tro->lockX = 0;
    tro->lockS = 0;
    tro->lockSX = 0;
    tro->lockP = 0;
    tro->data = XM_NULLOFFSET;
    tro->prot_oid_set = False;
    memset(&tro->prot_oid, 0, sizeof(tro->prot_oid));

    tro->oid = *oid;
    tro->oidloc.ns = 0;
    tro->oidloc.datid = -1;
    tro->po_off = 0;
    tro->state = Active;
#ifdef TRS_INTER_MUT
    mutexInit(dbh->vd, &tro->mut, &tro->mp, "TRANSACTION");
#else
    // EV 15/02/08: really PROCESS_PRIVATE ?
    tro->mut.init(eyedblib::Mutex::PROCESS_PRIVATE);
#endif

    HashTableTRObjectInsert(xmh, trs_ht, tro);
    *tro_off = XM_OFFSET(xmh, tro);
    return tro;
  }

  static PObject *
  makePObject(XMHandle *xmh, const Oid *oid, HashTable *obj_ht,
	      XMOffset trs_off, XMOffset *po_off,
	      LockMode lock)
  {
    PObject *po;

    po = (PObject *)XMAlloc(xmh, sizeof(PObject));

    if (!po)
      return 0;

#ifdef TRS_SECURE
    po->magic = POBJ_MAGIC;
#endif
    po->oid      = *oid;
    po->lockS    = 0;
    po->lockX    = 0;
    po->lockSX   = 0;
    po->lockPxid = 0;
    po->tridx    = ~0;
    po->wait_cnt = 0;
    po->refcnt   = 1;
    po->state    = Active;
    po->cond = XM_NULLOFFSET;

    po->trs_cnt = 0;
    po->trs_own.trs_off = 0;
    po->trs_own.trs_lock = DefaultLock;
    po->trs_own.next = XM_NULLOFFSET;
    po->trs_own.prev = XM_NULLOFFSET;

    HashTablePObjectInsert(xmh, obj_ht, po);

    *po_off = XM_OFFSET(xmh, po);

    return po;
  }

  static void
  print_item_trs(TransOwner *trs_own)
  {
    printf("\t%d [lock =%d]\n", trs_own->trs_off, trs_own->trs_lock);
  }

  static void
  print_trs(const char *msg, XMHandle *xmh, PObject *po)
  {
    TransOwner *trs_own;
    printf("%s {\n", msg);
    print_item_trs(&po->trs_own);

    trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

    while (trs_own) {
      print_item_trs(trs_own);
      trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
    }

    printf("}\n");
  }

  static void
  ESM_PObjectSuppressTransOwner(XMHandle *, PObject *, XMOffset,
				Mutex *, unsigned int);

  static void
  ESM_PObjectChangeTransOwnerLock(XMHandle *xmh, PObject *po,
				  XMOffset trs_off, LockMode lock,
				  Mutex *mp, unsigned int xid)
  {
    TransOwner *trs_own;

    if (po->trs_own.trs_off == trs_off) {
      if (po->trs_own.trs_lock == lock)
	IDB_LOG(IDB_LOG_TRANSACTION, ("ESM_PObjectChangeTransOwnerLock: %d vs. %d\n",
				      po->trs_own.trs_lock, lock));
      ESM_ASSERT_ABORT(po->trs_own.trs_lock != lock, mp, xid);
      po->trs_own.trs_lock = lock;
      return;
    }

    trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

    while (trs_own) {
      if (trs_own->trs_off == trs_off) {
	ESM_ASSERT_ABORT(trs_own->trs_lock != lock, mp, xid);
	trs_own->trs_lock = lock;
	return;
      }
      trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
    }

    ESM_ASSERT_ABORT(0, mp, xid);
  }

  static int
  addTransOwner(XMHandle *xmh, PObject *po, XMOffset trs_off,
		LockMode lock)
  {
    TransOwner *trs_own;
    XMOffset trs_own_off;

    TT(printf(" addTransOwner(trs_off = %d, oid = %d.%d)\n",
	      trs_off, po->oid.nx, po->oid.unique));

    po->trs_cnt++;

    if (!po->trs_own.trs_off) {
      po->trs_own.trs_off = trs_off;
      po->trs_own.trs_lock = lock;

      ESM_ASSERT_ABORT(!po->trs_own.next, 0, 0);
      ESM_ASSERT_ABORT(!po->trs_own.prev, 0, 0);

      return 1;
    }

    trs_own = (TransOwner *)XMAlloc(xmh, sizeof(TransOwner));

    if (!trs_own)
      return 0;

    trs_own->trs_off = trs_off;
    trs_own->trs_lock = lock;
    trs_own_off = XM_OFFSET(xmh, trs_own);

    trs_own->next = po->trs_own.next;
    if (po->trs_own.next)
      ((TransOwner *)XM_ADDR(xmh, po->trs_own.next))->prev = trs_own_off;
    trs_own->prev = XM_NULLOFFSET;
    po->trs_own.next = trs_own_off;

    return 1;
  }

  const Oid *
  ESM_getProtection(DbHandle const *dbh, const Oid *oid,
		    const Oid *prot_oid)
  {
    TransactionContext *trctx;
    XMHandle *xmh;
    Transaction *trs;
    HashTable *trs_ht;
    XMOffset tro_off;
    TRObject *tro;

    if (!TR_CNT(dbh))
      return prot_oid;

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    if (trctx->skip)
      return prot_oid;

    xmh =  dbh->vd->trs_mh;

    trs = (Transaction *)XM_ADDR(xmh, trctx->trs_off);

    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    tro_off = HashTableTRObjectLookup(xmh, trs_ht, oid);

    if (!tro_off)
      return prot_oid;

    tro = (TRObject *)XM_ADDR(xmh, tro_off);

    if (tro->prot_oid_set) {
      printf("OUPS SPECIAL PROT_OID!!!!\n");
      return &tro->prot_oid;
    }

    return prot_oid;
  }

  /*#define QUICK_READ_LOCK*/

  Status
  ESM_objectGetLock(DbHandle const *dbh, const Oid *oid, LockMode *rlock)
  {
    XMHandle *xmh;
    int tridx;
    HashTable *trs_ht;
    XMOffset tro_off;
    TRObject *tro;
    TransactionContext *trctx;
    Transaction *trs;

    tridx = TR_CNT(dbh)-1;
    trctx = &dbh->vd->trctx[tridx];

    xmh = dbh->vd->trs_mh;
    trs = (Transaction *)XM_ADDR(xmh, trctx->trs_off);

    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    tro_off = HashTableTRObjectLookup(xmh, trs_ht, oid);
    tro = (TRObject *)XM_ADDR(xmh, tro_off);

    if (tro) {
      if (tro->lockX)
	*rlock = LockX;
      else if (tro->lockSX)
	*rlock = LockSX;
      else if (tro->lockP)
	*rlock = LockP;
      else if (tro->lockS)
	*rlock = LockS;
      else
	*rlock = LockN;
    }
    else
      *rlock = LockN;

    return Success;
  }

  static eyedblib::int64 current_time()
  {
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (eyedblib::int64)tv.tv_sec * 1000000 + tv.tv_usec;
  }

  Status
  ESM_objectLock(DbHandle const *dbh, const Oid *oid, TransactionOP op,
		 Boolean *popsync, TRObject **ptro)
  {
    return ESM_objectLockCheck(dbh, oid, op, popsync, 0, ptro);
  }

  Status
  ESM_objectLockCheck(DbHandle const *dbh, const Oid *oid,
		      TransactionOP op, Boolean *popsync,
		      Boolean *exists, TRObject **ptro)
  {
    TransactionContext *trctx;
    XMHandle *xmh;
    Transaction *trs;
    HashTable *trs_ht;
    HashTable *obj_ht;
    XMOffset tro_off;
    XMOffset po_off;
    TRObject *tro;
    PObject *po;
    LockMode lock;
    Mutex *mp = TRS_MTX(dbh);
    unsigned int xid = dbh->vd->xid;
    Status se = Success;
    int tridx;
    LockMode wlock = DefaultLock;

    if (!TR_CNT(dbh)) {
      if (popsync)
	*popsync = True;
      if (exists)
	*exists = False;
      return Success;
    }

    tridx = TR_CNT(dbh)-1;
    trctx = &dbh->vd->trctx[tridx];

    if (trctx->skip) {
      if (popsync)
	*popsync = True;
      if (exists)
	*exists = False;
      return Success;
    }

    if (op == PWRITE)
      op = OWRITE;
    else if (op == PREAD)
      op = OREAD;

    if (op & LOCKX) {
      //      op &= ~LOCKX;
      op = (TransactionOP)(op & ~LOCKX);
      wlock = LockX;
    }
    else if (op & LOCKSX) {
      //op &= ~LOCKSX;
      op = (TransactionOP)(op & ~LOCKSX);
      wlock = LockSX;
    }
    else if (op & LOCKS) {
      //op &= ~LOCKS;
      op = (TransactionOP)(op & ~LOCKS);
      wlock = LockS;
    }
    else if (op & LOCKN) {
      //ESM_REGISTER_LOCK(dbh, lock);
      if (popsync)
	*popsync = True;
      if (exists)
	*exists = False;
      return Success;
    }

    xmh = dbh->vd->trs_mh;
    trs = (Transaction *)XM_ADDR(xmh, trctx->trs_off);

    trs->access_time = current_time();

    ESM_ASSERT(trs->magic == TRS_MAGIC, 0, xid);

    /* obj_ht could be directly in dbh->vd */
    obj_ht = (HashTable *)XM_ADDR(xmh, dbh->vd->shm_addr->trs_hdr.obj_ht);
    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    if (op == OCREATE)
      tro_off = 0;
    else
      tro_off = HashTableTRObjectLookup(xmh, trs_ht, oid);
  
    if (!tro_off) {
      if (exists && *exists) {
	*exists = False;
	return Success;
      }

      if (wlock != DefaultLock)
	lock = wlock;
      else {
	ESM_ASSERT_ABORT(op < OP_CNT && op >= 0 && trctx->lockmodeIndex < LockModeIndex_CNT && trctx->lockmodeIndex >= 0, 0, 0);
	lock = opLockMode[op][trctx->lockmodeIndex];
      }

      ESM_REGISTER_LOCK(dbh, lock);

      if (lock == LockN) {
	// EV: 14/05/05
	// added this test to isolate the private oids in other transactions
	if (op != OCREATE) {
	  if (NEED_LOCK(trctx))
	    MUTEX_LOCK(mp, xid);
	  XMOffset tpo_off = HashTablePObjectLookup(xmh, obj_ht, oid);
	  if (tpo_off) {
	    PObject *tpo = (PObject *)XM_ADDR(xmh, tpo_off);
	    if (tpo->lockPxid && (tpo->lockPxid != xid || tpo->tridx != tridx)) {
	      if (NEED_LOCK(trctx))
		MUTEX_UNLOCK(mp, xid);
	      return statusMake(INVALID_OID, "invalid oid '%s'",
				getOidString(oid));
	    }
	  }

	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mp, xid);
	}
      
	if (popsync)
	  *popsync = True;
	return Success;
      }

#ifdef QUICK_READ_LOCK
      /* ERROR: in case of lock is equal to R_S_W_S and
	 op is equal to O_DELETE, O_WRITE or O_CHSIZE, lock will be equal
	 to lockS (cf opLockMode)! As *popsync will be set to True,
	 the operation will be done immediately and so no rollback will
	 be possible: I add the condition op == OREAD (30/11/00) */
      if (op == OREAD && lock == LockS) {
	if (popsync)
	  *popsync = True;
	return Success;
      }
#endif
      if (NEED_LOCK(trctx))
	MUTEX_LOCK(mp, xid);

      tro = makeTRObject(dbh, oid, op, lock, trs_ht, trctx, &tro_off, mp,
			 xid);

      if (!tro)	{
	if (NEED_LOCK(trctx))
	  MUTEX_UNLOCK(mp, xid);
	return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
      }

      MUTEX_LOCKER trolock(tro->mut);
#ifndef NO_INTERNAL_LOCK
      mtlock.unlock();
#endif

      if (trctx->params.ratioalrt != 0 &&
	  trctx->params.magorder != MAX_MAGORDER &&
	  trctx->params.magorder * trctx->params.ratioalrt < trs->obj_cnt) {
	if (NEED_LOCK(trctx))
	  MUTEX_UNLOCK(mp, xid);
	return statusMake(ERROR, "transaction ratio alert: "
			  "%d objects in transaction, magorder is %u, "
			  "ratioalrt is %u", trs->obj_cnt,
			  trctx->params.magorder,
			  trctx->params.ratioalrt);
      }
      
      if (op == OCREATE)
	po_off = 0;
      else
	po_off = HashTablePObjectLookup(xmh, obj_ht, oid);

      if (!po_off) {
	po = makePObject(xmh, oid, obj_ht, trctx->trs_off, &po_off,
			 lock);
	if (!po) {
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mp, xid);
	  return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
	}
	  
	TT(printf("ESM_objectLock (new PObject = %d)\n", po_off));
      }
      else {
	po = (PObject *)XM_ADDR(xmh, po_off);

	po->refcnt++;
#ifdef TRS_SECURE
	ESM_ASSERT(po->magic == POBJ_MAGIC, mp, xid);
#endif
	TT(printf("ESM_objectLock (old PObject = %d)\n", po_off));
      }

      tro->po_off = po_off;

      if (po->lockPxid && (po->lockPxid != xid || po->tridx != tridx)) {
	if (NEED_LOCK(trctx))
	  MUTEX_UNLOCK(mp, xid);
	return statusMake(INVALID_OID, "invalid oid '%s'",
			  getOidString(oid));
      }

      if (NEED_OBJLOCK(trctx)) {
	if (lock == LockX || lock == LockS || lock == LockSX) {
	  se = pobjLock(dbh, xmh, trctx, trs, tro_off, lock,
			po, mp, xid, trctx->params.wait_timeout);

	  if (!se) {
	    if (lock == LockX)
	      tro->lockX = 1;
	    else if (lock == LockS)
	      tro->lockS = 1;
	    else if (lock == LockSX)
	      tro->lockSX = 1;
	  }
	}
	else if (lock == LockP && trctx->params.trsmode != TransactionOff) {
	  po->lockPxid = xid;
	  po->tridx = tridx;
	  tro->lockP = 1;
	}
	  
	if (!se) {
	  if (!addTransOwner(xmh, po, trctx->trs_off, lock)) {
	    if (NEED_LOCK(trctx))
	      MUTEX_UNLOCK(mp, xid);
	    return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
	  }
	}
      }

      trs->obj_cnt++;

      if (NEED_LOCK(trctx))
	MUTEX_UNLOCK(mp, xid);
    }
    else {
      TransactionOP oop;

      tro = (TRObject *)XM_ADDR(xmh, tro_off);
      
      MUTEX_LOCKER trolock(tro->mut);
#ifndef NO_INTERNAL_LOCK
      mtlock.unlock();
#endif

#ifdef TRS_SECURE
      ESM_ASSERT(!memcmp(&tro->oid, oid, sizeof(Oid)), 0, 0);
#endif
      if (tro->op == ODELETE)
	return statusMake(ERROR, "object %s is deleted",
			  getOidString(oid));

      oop = tro->op;

      ESM_ASSERT_ABORT(tro->op < OP_CNT && tro->op >= 0 && op < OP_CNT && op >= 0, 0, 0);
      tro->op = crossOps[tro->op][op];

      if (tro->op == OERROR)
	return statusMake(ERROR,
			  "operation %d followed by %d is invalid",
			  oop, op);

      if (wlock != DefaultLock)
	lock = wlock;
      else
	lock = opLockMode[tro->op][trctx->lockmodeIndex];

      ESM_REGISTER_LOCK(dbh, lock);

      if (lock == LockN) {
	if (popsync)
	  *popsync = True;
	return Success;
      }

#define OCREADEL_SYNC
#ifdef OCREADEL_SYNC
      if (tro->op == OCREADEL) {
	//printf("deleting object %s\n", getOidString(oid));
	se = ESM_objectDelete(dbh, oid, OPShrinkingPhase);
	return se;
      }
#endif

#ifdef TRS_SECURE
      ESM_ASSERT(tro->magic == TROBJ_MAGIC, 0, 0);
#endif
      po = (PObject *)XM_ADDR(xmh, tro->po_off);

      if (!tro->po_off)	{
	IDB_LOG(IDB_LOG_TRANSACTION,
		("internal transaction error: transaction object offset "
		 "should not be null\n"));
	return statusMake(ERROR,
			  "internal transaction error: "
			  "transaction object offset "
			  "should not be null");
      }

      if (!po)
	return statusMake(NO_SHMSPACE_LEFT, trTooLarge);

#ifdef TRS_SECURE
      ESM_ASSERT(po->magic == POBJ_MAGIC, 0, 0);
#endif

      if (po->lockPxid && (po->lockPxid != xid || po->tridx != tridx))
	return statusMake(INVALID_OID, "invalid oid '%s'",
			  getOidString(oid));

      if (NEED_OBJLOCK(trctx)) {
	if (lock == LockX || lock == LockSX) {
	  if ((lock == LockX && !tro->lockX) ||
	      (lock == LockSX && !tro->lockSX && !tro->lockX)) {
	    LockMode olock;
	    int r = 0;
	    if (tro->lockS)       olock = LockS;
	    else if (tro->lockX)  olock = LockX;
	    else if (tro->lockSX) olock = LockSX;
	    else                  olock = DefaultLock;

	    if (NEED_LOCK(trctx))
	      MUTEX_LOCK(mp, xid);

	    if (olock) {
	      /* changed the 30/08/01 */
	      if (tro->lockS) { 
		pobjUnlock(dbh->vd, xmh, po, LockS, mp, xid);
		tro->lockS = 0;
	      }

	      if (tro->lockSX) {
		pobjUnlock(dbh->vd, xmh, po, LockSX, mp, xid);
		tro->lockSX = 0;
	      }
	    }

	    se = pobjLock(dbh, xmh, trctx, trs, tro_off, lock,
			  po, mp, xid, trctx->params.wait_timeout);

	    if (!se) {
	      if (olock) /* added the 29/05/99 */
		ESM_PObjectChangeTransOwnerLock(xmh, po, trctx->trs_off,
						lock, mp, xid);
	      /* added the 29/05/99 */
	      else if (!addTransOwner(xmh, po, trctx->trs_off,
				      lock))	{
		if (NEED_LOCK(trctx))
		  MUTEX_UNLOCK(mp, xid);
		return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
	      }

	      if (lock == LockX)
		tro->lockX++;
	      else if (lock == LockSX)
		tro->lockSX++;
	    }
	    else if (olock) {
	      if (tro->lockP)
		printf("OUH LA LA ERROR POTENTIELLE GRAVE!\n");
	      tro->lockP = 0;
	      ESM_PObjectSuppressTransOwner(xmh, po, trctx->trs_off,
					    mp, xid);
	    }

	    if (NEED_LOCK(trctx))
	      MUTEX_UNLOCK(mp, xid);
	  }
	  else if (lock == LockX)
	    tro->lockX++;
	  else if (lock == LockSX)
	    tro->lockSX++;
	}
	else if (lock == LockS) {
	  if (!tro->lockS && !tro->lockX && !tro->lockSX) {
	    /* added: && !tro->lockSX the 03/09/01 */
	    if (NEED_LOCK(trctx))
	      MUTEX_LOCK(mp, xid);

	    se = pobjLock(dbh, xmh, trctx, trs, tro_off, LockS,
			  po, mp, xid, trctx->params.wait_timeout);

	    if (!se) {
	      /* added the 3/09/01 */
	      if (!addTransOwner(xmh, po, trctx->trs_off, lock)) {
		if (NEED_LOCK(trctx))
		  MUTEX_UNLOCK(mp, xid);
		return statusMake(NO_SHMSPACE_LEFT, trTooLarge);
	      }
	      /* end of added */
	      tro->lockS = 1;
	    }

	    if (NEED_LOCK(trctx))
	      MUTEX_UNLOCK(mp, xid);
	  }
	  else if (tro->lockS) /* added this test the 04/09/01 */
	    tro->lockS++;
	}
	else if (lock == LockP && trctx->params.trsmode != TransactionOff) {
	  po->lockPxid = xid;
	  po->tridx = tridx;
	  tro->lockP++;
	}
      }
    }

    if (!se) {
      if (popsync) {
	if (trctx->params.trsmode == TransactionOff) {
	  if (op == OCHSIZE)
	    return statusMake(ERROR,
			      "size modify operation cannot be "
			      "performed in transaction off mode");
	  *popsync = True;
	}
	else if (op == OCHSIZE && tro->op == OCREATE)
	  *popsync = False;
	else
	  *popsync = opSync[tro->op] ? True : False;
      }

      if (ptro)
	*ptro = tro;
    }

    if (se) {
      /*
	fprintf(stderr,
	"ESM_objectLock(lock = %d, tro->lock %d, %d. po->refcnt %d, "
	"xid: %d)",
	lock, tro->lockS, tro->lockX, po->refcnt, xid);
	statusPrint(se, "ESM_objectLock");
      */

      IDB_LOG(IDB_LOG_TRANSACTION, ("ESM_objectLock(lock = %d, tro->lock %d, %d. po->refcnt %d, "
				    "xid: %d: %s", lock, tro->lockS, tro->lockX, po->refcnt, xid,
				    statusGet(se)));
    }
    return se;
  }

#ifdef EYEDBSM_USE_DATA_VMEM
  static void *
#else
  static XMOffset
#endif
  trobjDataMake(XMHandle *xmh, size_t size)
  {
#ifdef EYEDBSM_USE_DATA_VMEM
    char *data = (char *)m_malloc(objDataGetSize(size));
#else
    char *data = (char *)XMAlloc(xmh, objDataGetSize(size));
#endif

    if (!data)
      return XM_NULLOFFSET;

    objDataSize(data) = size;
    objDataAll(data)  = 0;

    memset(objDataMask(data), 0, maskSize(size));

#ifdef EYEDBSM_USE_DATA_VMEM
    /*  return (XMOffset)data;*/
    return data;
#else
    return XM_OFFSET(xmh, data);
#endif
  }

  static void
  pobjMakeMask(char *data, size_t start, size_t length)
  {
    if (start == 0 && length == objDataSize(data))
      objDataAll(data) = 1;
    else {
      char *m = objDataMask(data) + start;

      while (length--)
	*m++ = 1;
    }
  }

  char *
  ESM_trobjDataGetIfExist(DbHandle const *dbh, TRObject *tro)
  {
    XMHandle *xmh = dbh->vd->trs_mh;  

    if (!tro->data || !objDataAll(tro->data)) {
      return 0;
    }

#ifdef EYEDBSM_USE_DATA_VMEM
    return objDataData(tro->data);
#else
    return XM_ADDR(xmh, tro->data) + objDataOffset;
#endif
  }

  char *
  ESM_trobjDataGet(DbHandle const *dbh, TRObject *tro, size_t size)
  {
    XMHandle *xmh = dbh->vd->trs_mh;  

    if (!tro->data)
      tro->data = trobjDataMake(xmh, size);

#ifdef EYEDBSM_USE_DATA_VMEM
    return (char *)tro->data;
#else
    return XM_ADDR(xmh, tro->data);
#endif
  }

  void
  ESM_trobjDataWrite(char *dest, const char *src,
		     size_t start, size_t length,
		     OPMode opmode, Boolean opsync)
  {
    TT(printf("ESM_trobjDataWrite(opsync = %d, start = %d, length = %d, opmode = %d)\n", opsync, start, length, opmode));
    if (opmode == OPGrowingPhase) {
      if (opsync)
	memcpy(dest + start, src, length);
      else {
	memcpy(objDataData(dest) + start, src, length);
	pobjMakeMask(dest, start, length);
      }
    }
    else if (opmode == OPShrinkingPhase) {
      /*      ESM_ASSERT(start == 0, 0, 0);*/
      if (length != objDataSize(src)) {
	IDB_LOG(IDB_LOG_TRANSACTION, ("trobjDataWRITE %d vs. %d\n", length, objDataSize(src)));
	abort();
      }

      if (objDataAll(src))
	memcpy(dest, objDataData(src), length);
      else {
	char *m = objDataMask(src);
	int i, size = objDataSize(src);

	src = objDataData(src);

	for (i = 0; i < size; i++, dest++, src++, m++)
	  if (*m)
	    *dest = *src;
      }
    }
  }

  Status
  ESM_trobjDataRead(char *dest, const char *src, const char *dbsrc,
		    size_t start, size_t length,
		    Boolean opsync, Boolean nocopy)
  {
    TT(printf("ESM_trobjDataRead(opsync = %d, start = %d, length = %d)\n", opsync, start, length));

    if (opsync) {
      if (nocopy)
	*(const char **)dest = src + start;
      else
	memcpy(dest, src + start, length);

      return Success;
    }

    if (objDataAll(src)) {
      if (nocopy)
	*(const char **)dest = objDataData(src) + start;
      else
	memcpy(dest, objDataData(src) + start, length);

      return Success;
    }

    if (nocopy)
      return statusMake(ERROR, "internal error in trobjDataRead : "
			"cannot read without copy");

    char *m = objDataMask(src) + start;
    int i, size = objDataSize(src);
  
    src = objDataData(src) + start;
    dbsrc += start;
  
    for (i = 0; i < length; i++, dest++, src++, dbsrc++, m++)
      *dest = (*m ? *src : *dbsrc);

    return Success;
  }

  Status
  ESM_bornAgainEpilogue(DbHandle const *dbh, Oid const *const o_oid,
			Oid const *const n_oid, NS ns, short datid)
  {
    TransactionContext *trctx;
    XMHandle *xmh;
    Transaction *trs;
    HashTable *obj_ht;
    HashTable *trs_ht;
    XMOffset off;
    Mutex *mp = TRS_MTX(dbh);
    Status se = Success;
    TRObject *o_tro, *n_tro;
    PObject *o_po, *n_po;
    unsigned int xid = dbh->vd->xid;

    xmh = dbh->vd->trs_mh;

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    trs = (Transaction *)XM_ADDR(xmh, trctx->trs_off);
    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off),
      obj_ht = (HashTable *)XM_ADDR(xmh, dbh->vd->shm_addr->trs_hdr.obj_ht);

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    off = HashTableTRObjectLookup(xmh, trs_ht, o_oid);
    o_tro = (TRObject *)XM_ADDR(xmh, off);
    off = o_tro->po_off;
    o_po = (PObject *)XM_ADDR(xmh, off);

    off = HashTableTRObjectLookup(xmh, trs_ht, n_oid);
    n_tro = (TRObject *)XM_ADDR(xmh, off);
    off = n_tro->po_off;
    n_po = (PObject *)XM_ADDR(xmh, off);

    if (NEED_LOCK(trctx))
      MUTEX_LOCK(mp, xid);
    HashTablePObjectSuppress(xmh, obj_ht, n_po);
    HashTableTRObjectSuppress(xmh, trs_ht, n_tro);

    n_tro->oid = *o_oid;
    n_po->oid  = *o_oid;

    HashTablePObjectInsert(xmh, obj_ht, n_po);
    HashTableTRObjectInsert(xmh, trs_ht, n_tro);

    o_tro->oidloc.ns = ns+1;
    o_tro->oidloc.datid = datid;
    /* to invalid entry in hash table */

    o_tro->oid.setUnique(o_tro->oid.getUnique() + 1);
    o_po->oid.setUnique(o_po->oid.getUnique() + 1);

    if (NEED_LOCK(trctx))
      MUTEX_UNLOCK(mp, xid);
    return se;
  }

#define TRHT_COUNT 4096

  void
  ESM_transInit(DbDescription *vd, char *addr, unsigned int shmsize)
  {
    DbShmHeader *shmh = (DbShmHeader *)addr;
    XMHandle *xmh;
    HashTable *ht;

    IDB_LOG(IDB_LOG_TRANSACTION, ("ESM_transInit(0x%x, shmsize=%x)\n", addr, shmsize));

    xmh = XMCreate((char *)(addr + SHM_HEADSIZE), shmsize - SHM_HEADSIZE, vd);

    ht = HashTableCreate(xmh, TRHT_COUNT);

    TT(printf("ESM_transInit(%p)\n", addr));

    shmh->trs_hdr.obj_ht = XM_OFFSET(xmh, ht);
    shmh->trs_hdr.first_trs = 0;
    shmh->trs_hdr.tr_cnt = 0;

    XMClose(xmh);
  }


  Status
  ESM_transactionCreate(DbHandle const *dbh,
			const TransactionParams *params, XMOffset *off)
  {
    if (dbh->vd->flags & NO_SHM_ACCESS) {
      return Success;
    }

    XMHandle *xmh;
    XMOffset trs_off;
    TransHeader *trshd;
    Transaction *trs;
    HashTable *ht;
    Mutex *mp = TRS_MTX(dbh);
    unsigned int xid = dbh->vd->xid;
    Status se;

    /* NEWRECOV */
    /* should also allocate a structure transinfo in the .sta */

    xmh = dbh->vd->trs_mh;
    TT(printf("ESM_transactionCreate(%x)\n", xmh));
    trs = (Transaction *)XMAlloc(xmh, sizeof(Transaction));

    if (!trs) {
      *off = XM_NULLOFFSET;
      return Success;
    }

#ifdef TRS_SECURE
    trs->magic = TRS_MAGIC;
#endif
    trs->trs_state   = TransACTIVE;
    trs->proc_state  = NilProcState;
    trs->trobj_wait  = 0;
    trs->lock_wait   = (LockMode)0;
    trs->obj_cnt     = 0;
    trs->del_obj_cnt = 0;
    trs->xid = dbh->vd->xid;
    trs->wrimmediate = (params->trsmode == TransactionOff ? True : False);
    trs->prot_update = False;
    trs->dl          = 0;
    trs->timestamp   = 0;
    trs->create_time = current_time();
    trs->access_time = current_time();
#ifdef TRS_INTER_MUT
    mutexInit(dbh->vd, &trs->mut, &trs->mp, "TRANSACTION");
#else
    trs->mut.init(eyedblib::Mutex::PROCESS_PRIVATE);
#endif

    ESM_transactionRegister(trs, mp, xid);

    trs_off = XM_OFFSET(xmh, trs);

    trshd = &dbh->vd->shm_addr->trs_hdr;

#ifdef TRS_DBG
    /*  XMCheckMemory(xmh); */
#endif

    se = MUTEX_LOCK_VOID(mp, xid);
    if (se) return se;

    if (trshd->first_trs)
      ((Transaction *)XM_ADDR(xmh, trshd->first_trs))->prev = trs_off;
      
    trs->next = trshd->first_trs;
    trs->prev = 0;

    trshd->first_trs = trs_off;
#ifndef NEW_TR_CNT
    trshd->tr_cnt++;
#endif

    MUTEX_UNLOCK(mp, xid);

    TT(printf("creating transaction #%d\n", trshd->tr_cnt - 1));

    ht = HashTableCreate(xmh, magorderHtCount(params->magorder));

    trs->ht_off = XM_OFFSET(xmh, ht);

    *off = trs_off;
    return Success;
  }

  static void
  ESM_PObjectRemove(DbDescription *vd, XMHandle *xmh, HashTable *obj_ht,
		    PObject *po)
  {
    TT(printf("PObjectRemove\n"));

    if (po->cond) {
      condDelete(vd, xmh, po->cond);
      /*
	pthread_cond_destroy((pthread_cond_t *)XM_ADDR(xmh, po->cond));
	XMFree(xmh, XM_ADDR(xmh, po->cond));
      */
    }

    po->state = Deleted;

    HashTablePObjectSuppress(xmh, obj_ht, po);

#ifdef TRS_SECURE
    po->magic = POBJ_MAGIC_DELETED;
#endif

    po->state = Zombie;

    XMFree(xmh, po);
  }

  static void
  check_trans_owner(XMHandle *xmh, PObject *po)
  {
    TransOwner *trs_own = &po->trs_own;
    while (trs_own) {
      Transaction *trs = (Transaction *)XM_ADDR(xmh, trs_own->trs_off);
      if (trs->magic != TRS_MAGIC)
	printf("%d: check_trans_owner: trs magic trsoff=%p failed\n", rpc_getpid(), XM_OFFSET(xmh, trs));
      trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
    }
  }

  static void
  ESM_PObjectSuppressTransOwner(XMHandle *xmh, PObject *po, XMOffset trs_off,
				Mutex *mp, unsigned int xid)
  {
    TT(printf("PObjectSuppressTransOwner trs_off = %d, oid = %d.%d\n",
	      trs_off, po->oid.nx, po->oid.unique));

    ESM_ASSERT_ABORT(po->trs_own.trs_off, mp, xid);

    if (po->trs_own.trs_off == trs_off) {
      TT(printf("PObjectSuppressTransOwner : first link found #1\n"));

      if (po->trs_own.next) {
	TransOwner *next_trs_own =
	  ((TransOwner *)XM_ADDR(xmh, po->trs_own.next));

	po->trs_own.trs_off  = next_trs_own->trs_off;
	po->trs_own.trs_lock = next_trs_own->trs_lock;
	po->trs_own.next     = next_trs_own->next;
	if (next_trs_own->next)
	  ((TransOwner *)XM_ADDR(xmh, next_trs_own->next))->prev =
	    XM_NULLOFFSET;
	XMFree(xmh, next_trs_own);
      }
      else {
	po->trs_own.trs_off = XM_NULLOFFSET;
	po->trs_own.trs_lock = DefaultLock;
      }
      po->trs_cnt--;
    }
    else {
      TransOwner *trs_own;
      int cnt = 0;
      trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

      TT(printf("PObjectSuppressTransOwner : other link found #1 %p\n",
		po->trs_own.next));

      while (trs_own) {
	if (trs_own->trs_off == trs_off) {
	  TransOwner *next_trs_own, *prev_trs_own;

	  next_trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
	  prev_trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->prev);

	  if (next_trs_own)
	    next_trs_own->prev = trs_own->prev;

	  if (prev_trs_own)
	    prev_trs_own->next = trs_own->next;
	  else
	    po->trs_own.next = trs_own->next;

	  XMFree(xmh, trs_own);
	  TT(printf("PObjectSuppressTransOwner : %d link found\n", cnt));
	  po->trs_cnt--;
	  return;
	}

	trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
	cnt++;
      }

      ESM_ASSERT_ABORT(0, mp, xid);
    }
  }

  static Status
  TRObjectUnlock(DbHandle const *dbh, XMHandle *xmh, Mutex *mp,
		 unsigned int xid, HashTable *obj_ht,
		 TRObject *tro, XMOffset trs_off)
  {
    PObject *po;
    Status s;
    DbDescription *vd = dbh->vd;
    TransactionContext *trctx;

    po = (PObject *)XM_ADDR(xmh, tro->po_off);

    if (!po || po->state != Active)
      return Success;

#ifdef TRS_SECURE
    if (po->magic != POBJ_MAGIC)
      IDB_LOG(IDB_LOG_TRANSACTION, ("magic = %x, oid = %s\n", po->magic, getOidString(&po->oid)));
    ESM_ASSERT(po->magic == POBJ_MAGIC, 0, 0);
#endif
    TT(printf("TRObjectUnlock(nx = %d)\n", tro->oid.nx));

    trctx = &dbh->vd->trctx[TR_CNT(dbh)-1];

    if (NEED_LOCK(trctx))
      MUTEX_LOCK(mp, xid);

    if (NEED_OBJLOCK(trctx)) {
      if (tro->lockX) {
	s = pobjUnlock(vd, xmh, po, LockX, mp, xid);
	if (s) {
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mp, xid);
	  return s;
	}
      }
      else if (tro->lockS) {
	s = pobjUnlock(vd, xmh, po, LockS, mp, xid);
	if (s) {
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mp, xid);
	  return s;
	}
      }
      else if (tro->lockSX) {
	s = pobjUnlock(vd, xmh, po, LockSX, mp, xid);
	if (s) {
	  if (NEED_LOCK(trctx))
	    MUTEX_UNLOCK(mp, xid);
	  return s;
	}
      }
      /* WARNING: suppressed the else on the 11/1/99 because sometimes
	 objects are locked both in X and P */
      /*else*/if (tro->lockP) {
	po->lockPxid = 0;
	po->tridx = ~0;
      }

      /* WARNING: changed the 7/7/99 because of a XM memory leak detected.
	 This changed must be tested seriously */
      if (tro->lockX || tro->lockS || tro->lockP)
	ESM_PObjectSuppressTransOwner(xmh, po, trs_off, mp, xid);
    }

    if (!--po->refcnt)
      ESM_PObjectRemove(vd, xmh, obj_ht, po);

    if (NEED_LOCK(trctx))
      MUTEX_UNLOCK(mp, xid);

    tro->po_off = XM_NULLOFFSET;

    if (tro->data) {
#ifdef EYEDBSM_USE_DATA_VMEM
#ifdef TRS_SECURE
      *(char *)tro->data = 0;
#endif
      free((char *)tro->data);
#else
#ifdef TRS_SECURE
      *objDataData(XM_ADDR(xmh, tro->data)) = 0;
#endif
      XMFree(xmh, XM_ADDR(xmh, tro->data));
#endif
    }

    return Success;
  }

  static Status
  ESM_pobjectRealize(DbHandle const *dbh, XMHandle *xmh,
		     TRObject *tro, TransState state,
		     RecoveryMode recovmode)
  {
    /* status management added the 7/11/2000 */
    Status se = Success;
    PObject *po = (PObject *)XM_ADDR(xmh, tro->po_off);

    if (!po)
      return se;

    if (state == TransCOMMITING) {
      //printf("commit tro->op %d %s\n", tro->op, getOidString(&po->oid));
      if (tro->op == OCREATE) {
	/*
	  if (recovmode == RecoveryPartial || recovmode == RecoveryFull)
	  printf("should actually create %s instead of validate\n",
	  getOidString(&po->oid));
	*/
	ESM_objectValidate(dbh, &po->oid);
	/*
	  if (se)
	  statusPrint(se, "ESM_ObjectValidate");
	*/
      }
#ifdef OCREADEL_SYNC
      else if (tro->op == ODELETE)
#else
      else if (tro->op == ODELETE || tro->op == OCREADEL)
#endif
	{
	if (tro->oidloc.ns) {
	  po->oid.setUnique(po->oid.getUnique() - 1);
	  se = ESM_objectDeleteByOidLoc(dbh, &po->oid, tro->oidloc.ns-1,
					tro->oidloc.datid);
	}
	else
	  se = ESM_objectDelete(dbh, &po->oid, OPShrinkingPhase);

	/*
	  if (se)
	  statusPrint(se, "ESM_ObjectDelete");
	*/
      }
      else if (tro->op == OWRITE) {
	if (tro->data) {
#ifdef EYEDBSM_USE_DATA_VMEM
	  se = ESM_objectWrite(dbh, 0, 0, (void *)tro->data, &po->oid,
			       OPShrinkingPhase);
#else
	  se = ESM_objectWrite(dbh, 0, 0, XM_ADDR(xmh, tro->data), &po->oid,
			       OPShrinkingPhase);
#endif
	  /*
	    if (se)
	    statusPrint(se, "ESM_ObjectWrite");
	  */
	}

	if (tro->prot_oid_set) {
	  se = ESM_objectProtectionSet(dbh, &po->oid, &tro->prot_oid,
				       OPShrinkingPhase);
	  /*
	    if (se)
	    statusPrint(se, "ESM_ObjectProtectionSet");
	  */
	}
      }
      else if (tro->op == OCHSIZE) {
	/* nothing */
	/*
	printf("NOTHING FOR OCHSIZE %s tro->data %p\n",
	       getOidString(&po->oid), tro->data);
	*/
      }
    }
    else if (state == TransABORTING) {
#ifdef OCREADEL_SYNC
      if (tro->op == OCREATE)
#else
      if (tro->op == OCREATE || tro->op == OCREADEL)
#endif
	{
	se = ESM_objectDelete(dbh, &po->oid, OPShrinkingPhase);
	/*
	if (se)
	  statusPrint(se, "ESM_ObjectDelete");
	*/
      }

      if (tro->op == ODELETE && tro->oidloc.ns) {
	po->oid.setUnique(po->oid.getUnique() - 1);
	/*se =*/ ESM_objectRestore(dbh, &po->oid, tro->oidloc.ns-1,
			       tro->oidloc.datid);
	/*
	if (se)
	  statusPrint(se, "ESM_ObjectRestore");
	*/
      }
    }

    return se;
  }

  void
  ESM_transactionObjectProtSet(TRObject *tro, const Oid *prot_oid)
  {
    tro->prot_oid_set = True;
    tro->prot_oid = *prot_oid;
  }

  static void
  wait_a_little()
  {
    int i;
    static float f;

    f = 0.0;

    for (i = 0; i < 10000; i++)
      f += 0.1;
  }

  static Boolean
  ESM_isTrsActive(Transaction *trs)
  {
    int del_obj_cnt = trs->del_obj_cnt;

#if 1
    wait_a_little(); /* should better do a sleep(1), but problems
			with multithread alarms */
#else
    sleep(1);
#endif

    if (del_obj_cnt == trs->del_obj_cnt) {
      IDB_LOG(IDB_LOG_TRANSACTION, ("transaction is *not* active\n"));
      return False;
    }

    IDB_LOG(IDB_LOG_TRANSACTION, ("transaction is active\n"));
    return True;
  }

  static Boolean
  ESM_checkTrsState(Mutex *mp, unsigned int xid,
		    Transaction *trs, TransState *state,
		    Boolean *trs_active)
  {
    /*  printf("Transaction [%p] %d to state %d\n", trs, xid, state); */

    if (trs_active)
      *trs_active = False;

    if (MUTEX_LOCK_VOID(mp, xid))
      return False;

    if (trs->trs_state == TransCOMMITED ||
	trs->trs_state == TransABORTED) {
      MUTEX_UNLOCK(mp, xid);
      IDB_LOG(IDB_LOG_TRANSACTION,
	      ("WARNING: transaction %d [%p] already deleted\n",
	       xid, trs));
      return False;
    }

    if (trs->trs_state == TransCOMMITING) {
      MUTEX_UNLOCK(mp, xid);
      if (!ESM_isTrsActive(trs)) {
	IDB_LOG(IDB_LOG_TRANSACTION, ("WARNING try to recover commiting\n"));
	*state = trs->trs_state;
	return True;
      }

      IDB_LOG(IDB_LOG_TRANSACTION, ("WARNING commiting is running\n"));
      if (trs_active)
	*trs_active = True;
      return False;
    }

    if (trs->trs_state == TransABORTING) {
      MUTEX_UNLOCK(mp, xid);

      if (!ESM_isTrsActive(trs)) {
	IDB_LOG(IDB_LOG_TRANSACTION, ("WARNING try to recover aborting\n"));
	*state = trs->trs_state;
	return True;
      }

      IDB_LOG(IDB_LOG_TRANSACTION, ("WARNING aborting is running\n"));
      if (trs_active)
	*trs_active = True;
      return False;
    }

    if (!*state && trs->trs_state == TransACTIVE)
      *state = TransABORTING;

    trs->trs_state = *state;

    MUTEX_UNLOCK(mp, xid);
      
    return True;
  }

#define SECURE_FREE

#ifdef SECURE_FREE
  struct SecureFree {
    SecureFree(XMHandle *xmh, void *trs) : xmh(xmh), trs(trs) {}
    ~SecureFree() { XMFree(xmh, trs); }
    XMHandle *xmh;
    void *trs;
  };
#endif

  static Status
  ESM_transactionDeleteRealize(DbHandle const *dbh,
			       XMOffset trs_off, unsigned int xid,
			       XMHandle *xmh, TransState state,
			       Boolean *trs_active)
  {
    if (dbh->vd->flags & NO_SHM_ACCESS) {
      return Success;
    }

    DbShmHeader *shmh = dbh->vd->shm_addr;
    Transaction *trs, *trs_next, *trs_prev;
    TransHeader *trshd;
    HashTable *trs_ht;
    int i, count;
    XMOffset *tro_poff;
    HashTable *obj_ht;
    Mutex *mp = TRS_MTX(dbh);
    int cnt = 0;
    int del_cnt = 0;
    time_t t;
    Status s, s_err;
    TRObject *tro;
    TransactionContext *trctx = &dbh->vd->trctx[TR_CNT(dbh)];

    /*
      printf("TRS DELETE trsmode %d lockmode %d recovmode %d tr_cnt %d\n",
      trctx->params.trsmode, trctx->params.lockmode,
      trctx->params.recovmode, TR_CNT(dbh));
    */
    s_err = Success;

    trshd = &shmh->trs_hdr;
    trs = (Transaction *)XM_ADDR(xmh, trs_off);
#ifdef SECURE_FREE
    // trs must be deleted after MUTEX_LOCKED destructor is called, because
    // MUTEX_LOCKER destructor uses trs->mut !
    SecureFree _(xmh, trs);
#endif

#ifndef NO_INTERNAL_LOCK
    MUTEX_LOCKER mtlock(trs->mut);
#endif
    /*
      std::cout << rpc_getpid() << ":" << pthread_self() <<
      " transaction delete mut " << XM_OFFSET(xmh, &trs->mut) << std::endl;
    */
    time(&t);

    IDB_LOG(IDB_LOG_TRANSACTION, ("transaction delete xid=%d\n", xid));

    /*  printf("%d: transaction delete %d [%p] [magic=%d] [%s] %s",
	rpc_getpid(), xid, trs, trs->magic, dbh->dbfile, ctime(&t)); */

#ifdef TRS_SECURE
    ESM_ASSERT(trs->magic == TRS_MAGIC, 0, 0);
#endif

    if (!ESM_checkTrsState(mp, xid, trs, &state, trs_active))
      return Success;

    obj_ht = (HashTable *)XM_ADDR(xmh, trshd->obj_ht);

    trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

    count = trs_ht->mask + 1;

    IDB_LOG(IDB_LOG_TRANSACTION,
	    ("transaction xid=%d %s [object count=%d, state=%d]\n",
	     xid, state == TransCOMMITING ? "commiting" : "aborting",
	     trs->obj_cnt, state));

#ifdef KEEP_ORDER
    tro = (TRObject *)XM_ADDR(xmh, trs_ht->xlast);
    while (tro) {
      XMOffset xprev = tro->xprev;
#else
      /*
	for (i = 0, tro_poff = &trs_ht->offs[0]; i < count; i++, tro_poff++) {
	tro = (TRObject *)XM_ADDR(xmh, *tro_poff);
	while (tro) {
	XMOffset next = tro->next;
      */
#endif
      if (tro->state == Active) {
	if (!trs->wrimmediate) {
	  s = ESM_pobjectRealize(dbh, xmh, tro, state,
				 trctx->params.recovmode);
	  if (s) return s; /* added the 7/11/2000 */
	}
#ifdef TRS_SECURE
	ESM_ASSERT(tro->magic == TROBJ_MAGIC ||
		   tro->magic == TROBJ_MAGIC_DELETED, 0, 0);
#endif
	s = TRObjectUnlock(dbh, xmh, mp, xid, obj_ht, tro, trs_off);
	if (s) s_err = s;
	tro->state = Deleted;
#ifdef TRS_SECURE
	tro->magic = TROBJ_MAGIC_DELETED;
#endif
	trs->del_obj_cnt++;
      }
      else
	del_cnt++;

      /* XMFree(xmh, tro);*/
	  
#ifdef KEEP_ORDER
      tro = (TRObject *)XM_ADDR(xmh, xprev);
#else
      tro = (TRObject *)XM_ADDR(xmh, next);
#endif
      cnt++;
#ifndef KEEP_ORDER
      //}
#endif
    }

    /*printf("COUNT %d\n", cnt);*/
    trs->trs_state = (trs->trs_state == TransABORTING ? TransABORTED :
		      TransCOMMITED);

    IDB_LOG(IDB_LOG_TRANSACTION, ("transaction xid=%d done\n", xid));

    /* now desallocate */
    for (i = 0, tro_poff = &trs_ht->offs[0]; i < count; i++, tro_poff++) {
      TRObject *tro = (TRObject *)XM_ADDR(xmh, *tro_poff);
      while (tro) {
	XMOffset next = tro->next;
	tro->state = Zombie;
	XMFree(xmh, tro);
	tro = (TRObject *)XM_ADDR(xmh, next);
      }
    }

    if (state == TransCOMMITING)
      shmh->stat.tr_commit_cnt = h2x_u32(x2h_u32(shmh->stat.tr_commit_cnt)+1);
    else if (state == TransABORTING)
      shmh->stat.tr_abort_cnt = h2x_u32(x2h_u32(shmh->stat.tr_abort_cnt)+1);

    /*  printf("Transaction %d %s\n", xid, (state == TransCOMMITING ?
	"committed" : "aborted")); */
    ESM_transactionUnregister(trs, mp, xid);

    s = MUTEX_LOCK_VOID(mp, xid);
    if (s)
      return s;

    trs_next = (Transaction *)XM_ADDR(xmh, trs->next);
    trs_prev = (Transaction *)XM_ADDR(xmh, trs->prev);

    if (trs_next)
      trs_next->prev = trs->prev;

    if (trs_prev)
      trs_prev->next = trs->next;
    else
      trshd->first_trs = trs->next;

#ifndef NEW_TR_CNT
    trshd->tr_cnt--;
    assert(trshd->tr_cnt >= 0);
#endif
    MUTEX_UNLOCK(mp, xid);

    XMFree(xmh, trs_ht);

#ifdef TRS_SECURE
    trs->magic = 0;
    trs->xid = 0;
#endif
#ifndef SECURE_FREE
    XMFree(xmh, trs);
#endif

#ifdef TRS_DBG
    /*  XMCheckMemory(xmh); */
#endif
    TT(printf("%d objects found in transaction %d\n", cnt, trshd->tr_cnt));

    TT(printf("deleting transaction %p: done!\n", trs_off));
    return s_err;
  }

  Status
  ESM_transactionDelete(DbHandle const *dbh, XMOffset trs_off,
			TransState state)
  {
    return ESM_transactionDeleteRealize(dbh, trs_off, dbh->vd->xid,
					dbh->vd->trs_mh, state, 0);
  }

#define REINIT(MP, XID)

  Status
  ESM_transactionsRelease(DbDescription *vd, DbShmHeader *shmh,
			  const char *dbfile, int xid,
			  XMHandle *xmh, Boolean *trs_active)
  {
    TransHeader *trshd;
    Transaction *trs;
    int i;
    int cnt = 0, pcnt = 0;
    Mutex *mp = &vd->mp[TRS];
    XMOffset trs_off;
    XMOffset trs_x[MAXTRS];
    DbHandle *dbh;
    Status se;
    time_t t;

    time(&t);
    IDB_LOG(IDB_LOG_TRANSACTION, ("transactions release xid=%d\n", xid));

    REINIT(&shmh->lock.mp, xid);
    REINIT(&shmh->mtx.mp[MAP], xid);
    REINIT(&shmh->mtx.mp[TRS], xid);
    REINIT(&shmh->mtx.mp[NX], xid);
    REINIT(&shmh->mtx.mp[SLT], xid);
    REINIT(&shmh->mtx.mp[LSL], xid);

    trshd = &shmh->trs_hdr;

    MUTEX_LOCK(mp, xid);

    trs_off = trshd->first_trs;
    trs = (Transaction *)XM_ADDR(xmh, trs_off);

    cnt = 0;
    pcnt = 0;

    while (trs) {
      cnt++;
#ifdef TRS_SECURE
      if (trs->magic != TRS_MAGIC)
	IDB_LOG(IDB_LOG_TRANSACTION, ("TRS magic 0x%x, expected 0x%x\n",
				      trs->magic, TRS_MAGIC));
      ESM_ASSERT(trs->magic == TRS_MAGIC, 0, 0);
#endif
      if (!xid || trs->xid == xid)
	trs_x[pcnt++] = trs_off;
      trs_off = trs->next;
      trs = (Transaction *)XM_ADDR(xmh, trs_off);
    }

    MUTEX_UNLOCK(mp, xid);

    IDB_LOG(IDB_LOG_TRANSACTION, ("%d transactions running\n", cnt));
    IDB_LOG(IDB_LOG_TRANSACTION, ("%d transactions for the current closing process\n", pcnt));

    if (pcnt) {
      Status se = ESM_dbOpen(dbfile, VOLRW, 0, 0, 0, 0, xid, 0, &dbh);

      /* warning: ESM_dbOpen can call transactionGarbage which can
	 call transactionDeleteRealize;
	 so we must not call ESM_transactionDeleteRealize again
	 if trs->magic == 0
      */

      if (se)
	return se;

      for (i = 0; i < pcnt; i++) {
	if (((Transaction *)XM_ADDR(xmh, trs_x[i]))->magic) /* very important! */
	  se = ESM_transactionDeleteRealize(dbh, trs_x[i], xid, xmh, NilTransState, trs_active);
	else
	  IDB_LOG(IDB_LOG_TRANSACTION, ("WARNING transaction deletion reentrance\n"));

	if (se)
	  break;
      }

      ESM_dbClose(dbh);
      return se;
    }

    TT(printf("TRANSACTIONS RELEASE #3\n"));
    return Success;
  }

  void
  DbMutexesInit(DbDescription *vd, DbShmHeader *shmh)
  {
    lockInit(vd, &shmh->dblock_W, "database W");
    lockInit(vd, &shmh->dblock_RW, "database RW");
    lockInit(vd, &shmh->dblock_Wtrans, "database Wtrans");

    mutexInit(vd, VD2MTX(vd, MAP), &shmh->mtx.mp[MAP], "map");
    mutexInit(vd, VD2MTX(vd, TRS), &shmh->mtx.mp[TRS], "trs");
    mutexInit(vd, VD2MTX(vd, NX), &shmh->mtx.mp[NX],  "nx");
    mutexInit(vd, VD2MTX(vd, SLT), &shmh->mtx.mp[SLT], "slot");
    mutexInit(vd, VD2MTX(vd, LSL), &shmh->mtx.mp[LSL], "lsl");
  }

  void
  DbMutexesLightInit(DbDescription *vd, DbShmHeader *shmh)
  {
    lockLightInit(vd, &shmh->dblock_W);
    lockLightInit(vd, &shmh->dblock_RW);
    lockLightInit(vd, &shmh->dblock_Wtrans);

    mutexLightInit(vd, &vd->mp[MAP], &shmh->mtx.mp[MAP]);
    mutexLightInit(vd, &vd->mp[TRS], &shmh->mtx.mp[TRS]);
    mutexLightInit(vd, &vd->mp[NX], &shmh->mtx.mp[NX]);
    mutexLightInit(vd, &vd->mp[SLT], &shmh->mtx.mp[SLT]);
    mutexLightInit(vd, &vd->mp[LSL], &shmh->mtx.mp[LSL]);
  }

  /*extern "C" */ Status
  DbMutexesRelease(DbDescription *vd, DbShmHeader *shmh, unsigned int xid)
  {
    if (vd->flags & NO_SHM_ACCESS) {
      return Success;
    }

    Mutex *mp;
    bool lockX;

    IDB_LOG(IDB_LOG_TRANSACTION, ("eyedbsm: DbMutexesRelease\n"));

    DbLock *dblocks[] = {&shmh->dblock_W, &shmh->dblock_RW, &shmh->dblock_Wtrans};

    for (unsigned int i = 0; i < sizeof(dblocks)/sizeof(dblocks[0]); i++) {
      while (findDbLockXID(vd, dblocks[i], xid, &lockX, True)) {
	IDB_LOG(IDB_LOG_TRANSACTION, ("eyedbsm: main db mutex is kept by CURRENT xid = %d lockX = %d\n", xid, lockX));

	// MIND: if XID has several lockS on dblock, one must do S -= n
      
	if (lockX)
	  unlockX(vd, dblocks[i], xid);
	else 
	  unlockS(vd, dblocks[i], xid);
      }
    }
    
    mp = vd->mp;

    for (int i = 0; i < MTX_CNT; i++, mp++)
      mutexCheckNotLock(mp, xid);

    fflush(stderr);
    return Success;
  }

  static Transaction **
  transOwnerMake(XMHandle *xmh, XMOffset trs_off, PObject *po,
		 LockMode lockmode, int *pn)
  {
    Transaction **trs_set;
    Transaction *trs;
    TransOwner *trs_own;
    int n;

    if (!po->trs_own.trs_off) {
      *pn = 0;
      return (Transaction **)0;
    }

    n = 0;

    trs_set = (Transaction **)m_calloc(sizeof(Transaction *), po->trs_cnt);

    if (lockmode == LockX) {
      trs = (Transaction *)XM_ADDR(xmh, po->trs_own.trs_off);

      if (trs->magic != TRS_MAGIC)
	printf("%d: trs magic trsoff=%p failed\n", rpc_getpid(), XM_OFFSET(xmh, trs));
      if (trs->trobj_wait || po->trs_own.trs_off == trs_off)
	trs_set[n++] = trs;

      trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

      while (trs_own) {
	trs = (Transaction *)XM_ADDR(xmh, trs_own->trs_off);
	if (trs->magic != TRS_MAGIC)
	  printf("%d: trs magic trsoff=%p failed\n", rpc_getpid(), XM_OFFSET(xmh, trs));
	if (trs->trobj_wait || trs_own->trs_off == trs_off)
	  trs_set[n++] = trs;
	trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
      }

      /*ESM_ASSERT(n <= po->trs_cnt, 0, 0);*/
    }
    else {
      if (po->trs_own.trs_lock == LockX) {
	trs = (Transaction *)XM_ADDR(xmh, po->trs_own.trs_off);
	if (trs->magic != TRS_MAGIC)
	  printf("%d: trs magic trsoff=%p failed\n", rpc_getpid(), XM_OFFSET(xmh, trs));
	  
	if (po->trs_own.trs_off == trs_off || trs->trobj_wait)
	  trs_set[n++] = trs;
      }

      trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

      while (trs_own) {
	if (trs_own->trs_lock == LockX) {
	  trs = (Transaction *)XM_ADDR(xmh, trs_own->trs_off);
	  if (trs->magic != TRS_MAGIC)
	    printf("%d: trs magic trsoff=%p failed\n", rpc_getpid(), XM_OFFSET(xmh, trs));
	  if (trs_own->trs_off == trs_off || trs->trobj_wait)
	    trs_set[n++] = trs;
	}

	trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
      }

      /*ESM_ASSERT(n <= 2, 0, 0);*/
    }

    *pn = n;
    return trs_set;
  }

  static Status
  deadLockCheckRealize(XMHandle *xmh, XMOffset trs_off,
		       const Oid *oid_base,
		       const Oid *oid_w,
		       Transaction **trs_set, int n)
  {
    int i;
    for (i = 0; i < n; i++) {
      Transaction *trs = trs_set[i];

#ifdef TRS_SECURE
      if (trs->magic != TRS_MAGIC)
	printf("!!ouh lala!! %p vs. %p\n", trs->magic, XM_OFFSET(xmh, trs));

      ESM_ASSERT(trs->magic == TRS_MAGIC, 0, 0);
#endif
      if (oid_w && XM_OFFSET(xmh, trs) == trs_off)
	return statusMake(DEADLOCK_DETECTED, "trying lock %s, dead lock through %s",
			  getOidString(oid_base),
			  getOidString(oid_w));
      else if (trs->dl)
	continue;
      else if (trs->trobj_wait) {
	TRObject *trow = (TRObject *)XM_ADDR(xmh, trs->trobj_wait);
	PObject *pow;
	Transaction **xtrs_set;
	int xn;
	Status se;

	pow = (PObject *)XM_ADDR(xmh, trow->po_off);
	ESM_ASSERT(pow, 0, 0);

	trs->dl = 1;

	xtrs_set = transOwnerMake(xmh, trs_off, pow, trs->lock_wait, &xn);
	if (xn) {
	  se = deadLockCheckRealize(xmh, trs_off, oid_base,
				    &pow->oid, xtrs_set, xn);
	  free(xtrs_set);
	}
	else
	  se = Success;

	trs->dl = 0;

	if (se)
	  return se;
      }

    }

    return Success;
  }

  Status
  deadLockCheck(XMHandle *xmh, Transaction *trs, PObject *po,
		LockMode lockmode)
  {
    Transaction **trs_set;
    XMOffset trs_off = XM_OFFSET(xmh, trs);
    int n;

    trs_set = transOwnerMake(xmh, trs_off, po, lockmode, &n);

    if (n) {
      Status se = deadLockCheckRealize(xmh, trs_off, &po->oid,
				       0, trs_set, n);
      free(trs_set);
      return se;
    }

    return Success;
  }

  const char *
  getOidString(const Oid *oid)
  {
#define N 8
    static char str[N][128];
    static int n;
    char *p;

    if (!oid)
      return "NULL";

    if (n >= N)
      n = 0;

    p = str[n++];

    sprintf(p, "%u.%u.%u:oid", oid->getNX(), dbidGet(oid), oid->getUnique());
    return p;
  }

  /*
   * Recovery System
   */

  static pthread_t recovid;
  static pthread_mutex_t recov_mp = PTHREAD_MUTEX_INITIALIZER;

#define MAXTRS 64

  typedef struct {
    /*  Mutex *mp;*/
    unsigned int xid;
  } RecovArg;

#define INTERVAL 5

  static int recovtrs_cnt;

  static struct {
    Mutex *mp;
    Transaction *trs;
  } recovtrs[MAXTRS];

  /* NEWRECOV */
  /* should also mark timestamp in the .sta transinfo entry of the .sta
   * and msync .sta */

  static void
  markActive(Transaction *trs, Mutex *mp, unsigned int xid)
  {
    /*
      if (!MUTEX_LOCK_VOID(mp, xid))
      {
      time(&trs->timestamp);
      MUTEX_UNLOCK(mp, xid);
      }
    */

    // EV: 21/12/04
    // we suppress MUTEX_LOCK because of a concurrency problem with the
    // main thread using the mode UT_SEM_FAST: in this mode, MUTEX_LOCK
    // (mutexLock_realize) is inter processus safe but not intra processus safe !
    time(&trs->timestamp);
  }

  static void
  markInactive(Transaction *trs, Mutex *mp, unsigned int xid)
  {
    if (!MUTEX_LOCK_VOID(mp, xid)) {
      trs->timestamp = 0;
      MUTEX_UNLOCK(mp, xid);
    }
  }

  /*extern "C" { */
  static void *
  recovfun(void *arg)
  {
    unsigned int xid = ((RecovArg *)arg)->xid;

    free(arg);

    for (;;) {
      int i;
      sleep(INTERVAL);

      pthread_mutex_lock(&recov_mp);

      for (i = 0; i < recovtrs_cnt; i++)
	if (recovtrs[i].trs)
	  markActive(recovtrs[i].trs, recovtrs[i].mp, xid);

      pthread_mutex_unlock(&recov_mp);
    }
    return (void *)0;
  }
  //}

  static void
  ESM_transactionRegister(Transaction *trs, Mutex *mp, unsigned int xid)
  {
    int i;

    if (!recovid && !getenv("EYEDBSM_NO_MARK_ACTIVE")) {
      RecovArg *arg = (RecovArg *)m_malloc(sizeof(RecovArg));
      arg->xid = xid;
      pthread_create(&recovid, NULL, recovfun, arg);
    }

    markActive(trs, mp, xid);

    pthread_mutex_lock(&recov_mp);

    for (i = 0; i < MAXTRS; i++)
      if (!recovtrs[i].mp) {
	recovtrs[i].trs = trs;
	recovtrs[i].mp = mp;
	if (i >= recovtrs_cnt)
	  recovtrs_cnt = i+1;
	break;
      }

    pthread_mutex_unlock(&recov_mp);
  }

  static void
  ESM_transactionUnregister(Transaction *trs, Mutex *mp, unsigned int xid)
  {
    int i;

    markInactive(trs, mp, xid);

    pthread_mutex_lock(&recov_mp);

    for (i = 0; i < recovtrs_cnt; i++)
      if (recovtrs[i].trs == trs) {
	recovtrs[i].mp = 0;
	recovtrs[i].trs = 0;
	if (i == recovtrs_cnt - 1)
	  recovtrs_cnt--;
	break;
      }

    pthread_mutex_unlock(&recov_mp);
  }

  Status
  ESM_transactionsGarbage(DbHandle const *dbh, Boolean mustLock)
  {
    DbShmHeader *shmh = dbh->vd->shm_addr;
    unsigned int xid = dbh->vd->xid;
    Mutex *mp = TRS_MTX(dbh);
    XMHandle *xmh = dbh->vd->trs_mh;
    TransHeader *trshd;
    Transaction *trs;
    int inactrs_cnt = 0;
    int i;
    Transaction *inactrs[MAXTRS];
    Status se;

    /* NEWRECOV */
    /* should look at .sta file instead ?? */

    trshd = &shmh->trs_hdr;

    if (mustLock && (se = MUTEX_LOCK_VOID(mp, xid)))
      return se;

    trs = (Transaction *)XM_ADDR(xmh, trshd->first_trs);

    while(trs) {
      if (!ESM_isTransactionActive(trs) &&
	  trs->trs_state != TransABORTING &&
	  trs->trs_state != TransCOMMITING) {
	time_t ts;
	inactrs[inactrs_cnt++] = trs;
	time(&ts);
	trs->timestamp = ts;
      }

      trs = (Transaction *)XM_ADDR(xmh, trs->next);
    }

    if (mustLock)
      MUTEX_UNLOCK(mp, xid);

    for (i = 0; i < inactrs_cnt; i++) {
      /*
	time_t t;
	time(&t);
      */
      IDB_LOG(IDB_LOG_TRANSACTION,
	      ("RECOVERY SYSTEM : aborting the transaction xid = %d\n",
	       inactrs[i]->xid));
      if (trace_garb_trs) {
	printf("Deleting inactive transaction\n");
	printf(" Server Pid %d\n", inactrs[i]->xid);
	printf(" Object Count %u\n",  inactrs[i]->obj_cnt);
	printf(" Deleted Object Count %u\n",  inactrs[i]->del_obj_cnt);
	printf(" Last Access on %s\n", eyedblib::setbuftime(inactrs[i]->access_time));
      }
      se = ESM_transactionDelete(dbh, XM_OFFSET(xmh, inactrs[i]), TransABORTING);
      if (se) return se;
#ifdef USE_SHM_REFCNT
      if (mustLock && (se = MUTEX_LOCK_VOID(mp, xid)))
	return se;
      --shmh->refcnt;
      if (mustLock)
	MUTEX_UNLOCK(mp, xid);
#endif
    }

    return Success;
  }

  extern Boolean
  ESM_isTransactionActive(Transaction *trs)
  {
    time_t ts;

    time(&ts);

    if (ts - trs->timestamp > 6 * INTERVAL)
      return False;

    return True;
  }
}
