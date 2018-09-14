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


#ifndef _EYEDBSM_TRANSACTION_H
#define _EYEDBSM_TRANSACTION_H

#include <time.h>
#include <eyedbsm/xm_alloc.h>
#include <eyedblib/thread.h>
#include <eyedbsm/eyedbsm.h>
#include "eyedbsm/mutex.h"

#define TRY_DATA
#define KEEP_ORDER

//#define TRS_INTER_MUT

namespace eyedbsm {
  enum TransactionOP {
    /* object operations */
    OCREATE = 0,
    OREAD,
    OWRITE,
    ODELETE,
    OCREADEL,
    OCHSIZE,
    OERROR,
    OP_CNT, /* OP_CNT should be after PDELETE when all operations
	       will be implemented */
    /* protection operations */
    PCREATE,
    PREAD,
    PWRITE,
    PDELETE,
    LOCKS  = 0x200,
    LOCKX  = 0x400,
    LOCKSX = 0x800,
    LOCKN  = 0x1000
  };

  enum LockModeIndex {
    R_S_W_S = 0, /* read shared; write shared */
    R_S_W_SX,    /* read shared; write shared/exclusive */
    R_S_W_X,     /* read shared; write exclusive */
    R_SX_W_SX,   /* read shared/exclusive; write shared/exclusive */
    R_SX_W_X,    /* read shared/exclusive; write shared/exclusive */
    R_X_W_X,     /* read exclusive; write exclusive */
    R_N_W_S,     /* read no lock; write shared */
    R_N_W_SX,    /* read no lock; write shared/exclusive */
    R_N_W_X,     /* read no lock; write exclusive */
    R_N_W_N,     /* read no lock; write no lock */
    DB_W,        /* database exclusive for writing */
    DB_RW,       /* database exclusive for reading and writing */
    DB_Wtrans,   /* database exclusive for writing trans */
    LockModeIndex_CNT
  };

  enum TransState {
    NilTransState,
    TransACTIVE,
    TransCOMMITING,
    TransABORTING,
    TransCOMMITED,
    TransABORTED
  };

  enum ProcState {
    NilProcState,
    ProcRunning,
    ProcWaiting
  };

  enum OPMode {
    OPImmediate = 1,
    OPGrowingPhase,
    OPShrinkingPhase,
    OPDefault = OPGrowingPhase
  };

#define TRS_SECURE

  struct Transaction {
#ifdef TRS_SECURE
    eyedblib::uint32 magic;
#endif
    TransState trs_state;
    ProcState proc_state;

    eyedblib::int64 create_time;
    eyedblib::int64 access_time;
    time_t timestamp;
    unsigned int xid;
    unsigned int obj_cnt;
    unsigned int del_obj_cnt;
    XMOffset trobj_wait;    /* sleeping on object ... */
    LockMode lock_wait;  /* in lockX or lockS */
    XMOffset ht_off;        /* hash table offset */

    Boolean wrimmediate; /* true if write immediate transaction */
    char dl;                /* deadlock avoid recursion */
    Boolean prot_update; /* to update protections runtime list */
    XMOffset prev, next;    /* double links */
#ifdef TRS_INTER_MUT
    eyedbsm::Mutex mut;
    eyedbsm::MutexP mp;
#else
    eyedblib::Mutex mut; // warning: non process shared data
#endif
  };
  /*@@@@ eyedblib::Mutex is a class*/
  //#endif

  enum State {
    Active = 1,
    Deleted,
    Zombie
  };

  static const NS INVALID_NS = ~0U;
  //static const NS INVALID_NS = ~0ULL;

  struct OidLoc {
    NS ns;
    short datid;
  };

  /*#define EYEDBSM_USE_DATA_VMEM*/

  struct TRObject {
#ifdef TRS_SECURE
    eyedblib::uint32 magic;
#endif
    TransactionOP op;    /* main transaction operation */
    unsigned int lockS;     /* cardinal of S locking: [0, N] */ 
    unsigned int lockX;     /* cardinal of X locking: [0, 1] */
    unsigned int lockSX;    /* cardinal of SX locking: [0, 1] */
    unsigned int lockP;     /* cardinal of P locking: [0, 1] */
    XMOffset po_off;        /* offset of the PObject */
    Oid oid;             /* part of object oid */
    OidLoc oidloc;
    State state;
#ifdef EYEDBSM_USE_DATA_VMEM
    void *data; // warning: volatile data
#else
    XMOffset data;
#endif
    XMOffset prev, next;          /* simple link */
#ifdef KEEP_ORDER
    XMOffset xprev, xnext;
#endif
    Boolean prot_oid_set;
    Oid prot_oid;
#ifdef TRS_INTER_MUT
    eyedbsm::Mutex mut;
    eyedbsm::MutexP mp;
#else
    eyedblib::Mutex mut; // warning: non process shared data
#endif
  };

  struct TransOwner {
    XMOffset trs_off;       /* transaction owner */
    LockMode trs_lock;   /* lock mode for transaction */
    XMOffset prev, next;    /* double links */
  };

  struct PObject {
#ifdef TRS_SECURE
    eyedblib::uint32 magic;
#endif
    Oid oid;             /* object oid */
    unsigned int lockS;     /* cardinal of S locking: [0, N] */
    unsigned int lockX;     /* cardinal of X locking: [0, 1] */
    unsigned int lockSX;    /* cardinal of SX locking: [0, 1] */
    unsigned int lockPxid;  /* xid of P locking */
    unsigned int tridx;     /* idx of transaction */
    XMOffset cond;          /* offset of condition */

    int refcnt;
    int trs_cnt;            /* count of transaction owner */
    TransOwner trs_own;  /* head list for transowner */

    int wait_cnt;           /* waiting threads count */

    State state;
    XMOffset prev, next;    /* double links */
  };

  struct TransactionContext {
    XMOffset trs_off;
    TransactionParams params;
    LockModeIndex lockmodeIndex;
    Boolean skip;
  };

  struct TransHeader {
    MutexP mut_access;
    XMOffset obj_ht;
    XMOffset first_trs;
    int tr_cnt;
  };

#ifdef TRS_SECURE
  static const unsigned int TRS_MAGIC =  0x23ffed12;
  static const unsigned int POBJ_MAGIC = 0x6e199930;
  static const unsigned int TROBJ_MAGIC = 0x5110293e;
  static const unsigned int MT_MAGIC_BASE = (eyedblib::uint32)0x62efd812;

  /* this magic number must be changed each time mutex mapping changed */
  static const unsigned int MT_MAGIC = (MT_MAGIC_BASE + 1);

  static const unsigned int POBJ_MAGIC_DELETED  = 0xffe35601;
  static const unsigned int TROBJ_MAGIC_DELETED = 0x77ef1234;

  enum {
    MAXTRS = 16
  };

  extern TRObject *
  TRObjectAlloc(XMHandle *);

  extern void
  TRObjectFree(XMHandle *, TRObject *);

  extern PObject *
  PObjectAlloc(XMHandle *);

  extern void
  PObjectFree(XMHandle *, PObject *);

  extern void
  ESM_transactionObjectProtSet(TRObject *, const Oid *prot_oid);

  extern Status
  ESM_objectLock(DbHandle const *dbh, const Oid *oid, TransactionOP,
		 Boolean *, TRObject **),
    ESM_objectLockCheck(DbHandle const *dbh, const Oid *oid,
			TransactionOP op, Boolean *popsync,
			Boolean *mustExists, TRObject **ptro),
    ESM_objectGetLock(DbHandle const *dbh, const Oid *oid,
		      LockMode *rmode),
    ESM_objectDownLock(DbHandle const *dbh, Oid const *const oid),
    ESM_transactionBegin(DbHandle const *, const TransactionParams *),

    ESM_transactionCommit(DbHandle const *),
    ESM_transactionAbort(DbHandle const *),

    ESM_transactionParamsSet(DbHandle const *dbh,
			     const TransactionParams *params),

    ESM_transactionParamsGet(DbHandle const *dbh,
			     TransactionParams *params);
  extern char *
  ESM_trobjDataGet(DbHandle const *dbh, TRObject *tro, size_t size);

  extern char *
  ESM_trobjDataGetIfExist(DbHandle const *dbh, TRObject *tro);

  extern void
  ESM_trobjDataWrite(char *addr, const char *object, size_t start, size_t length, OPMode, Boolean);

  extern Status
  ESM_trobjDataRead(char *object, const char *addr, const char *dbaddr,
		    size_t start, size_t length, Boolean, Boolean);

  extern void
  ESM_transInit(DbDescription *, char *, unsigned int);

  extern Status
  ESM_transactionCreate(DbHandle const *, const TransactionParams *params,
			XMOffset *);

  extern Status
  ESM_transactionDelete(DbHandle const *, XMOffset, TransState);

  extern Status
  deadLockCheck(XMHandle *, Transaction *, PObject *, LockMode);

  extern Status
  ESM_transactionLockSet(DbHandle const *dbh, ObjectLockMode mode,
			 ObjectLockMode *omode);

  extern Boolean
  ESM_protectionsMustUpdate(DbHandle const *);

  extern const Oid *
  ESM_getProtection(DbHandle const *, const Oid *oid,
		    const Oid *prot_oid);

  extern Status
  ESM_transactionsGarbage(DbHandle const *dbh, Boolean mustLock);

  extern Boolean ESM_isTransactionActive(Transaction *trs);

#define SHM_HEADSIZE  sizeof(DbShmHeader)
  /*#define SHM_ALLOCSIZE (SHM_DEFSIZE - SHM_HEADSIZE)*/

#endif

  extern int trs_init(void);

  extern Boolean trace_garb_trs;

}
#endif
