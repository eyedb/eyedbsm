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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <unistd.h>
#include <stdlib.h>
#include "eyedbsm_p.h"
#include <eyedbsm/mutex.h>

#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
#include <sys/sem.h>
/* SEM_FAST could not work because in this case we need as many semaphores
   as mutex! */
#define UT_SEM_FAST
#endif

#include <eyedblib/performer.h>

#define NMT 10

namespace eyedbsm {
  Boolean cleanup = False;

  static int g_mutex_idx;

  struct GMutex {
    unsigned int xid;
    Mutex *mp;
  } g_mutex[NMT];

  static Mutex *sleeping_mp;

  //#undef IDB_LOG
  //#define IDB_LOG(X, MSG) printf MSG

  void
  mutexes_init()
  {
  }

  void
  mutexes_release()
  {
    int idx = g_mutex_idx;

#ifdef HAVE_SEMAPHORE_POLICY_POSIX
    if (sleeping_mp) {
      pthread_mutex_unlock(&sleeping_mp->pmp->u.mp);
      IDB_LOG(IDB_LOG_MTX, ("found a sleeping mutex"));
    }
#endif

    IDB_LOG(IDB_LOG_MTX, ("mutexes_release start => %d\n", idx));

    for (int i = 0; i < g_mutex_idx; i++) {
      GMutex *gm = &g_mutex[i];
      if (gm->mp) {
	// added the 16/01/99
#ifdef HAVE_SEMAPHORE_POLICY_POSIX
	pthread_mutex_unlock((pthread_mutex_t *)&gm->mp->pmp);
#endif
	mutexUnlock(gm->mp, gm->xid);
	gm->mp = 0;
      }
    }

    IDB_LOG(IDB_LOG_MTX, ("mutexes_release done => %d\n", idx));
  }

  static pthread_mutex_t local_mp = PTHREAD_MUTEX_INITIALIZER;

  static void
  appendGMutex(Mutex *mp, unsigned int xid)
  {
    int i;

    pthread_mutex_lock(&local_mp);
    for (i = 0; i < NMT; i++) {
      GMutex *gm = &g_mutex[i];
      if (!gm->mp) {
	gm->mp = mp;
	gm->xid = xid;
	if (i >= g_mutex_idx)
	  g_mutex_idx = i+1;
	break;
      }
    }

    pthread_mutex_unlock(&local_mp);
  }

  static Status
  releaseGMutex(Mutex *mp, unsigned int xid)
  {
    int i;

    pthread_mutex_lock(&local_mp);
    for (i = g_mutex_idx-1; i >= 0; i--) {
      GMutex *gm = &g_mutex[i];
      if (gm->mp == mp) {
	gm->mp = 0;
	gm->xid = 0;
	if (i == g_mutex_idx-1)
	  --g_mutex_idx;
	pthread_mutex_unlock(&local_mp);
	return Success;
      }
    }

    pthread_mutex_unlock(&local_mp);
    ESM_ASSERT(0, 0, xid);
    return Success;
  }

#define wakeupInterval 4
#define lockTimeout    8

  static void
  dumpMutex(Mutex *mp)
  {
    int i;
    printf("Mutex %s, xid = %d, state = %d {\n", mp->pmp->mtname,
	   mp->pmp->xid, mp->pmp->locked);
    printf("};\n\n");
  }

  /*
    #define THR_TRACE
    #define THR_TRACE_1
    #define THR_TRACE_2
  */

  void
  mutexLightInit(DbDescription *vd, Mutex *mp, MutexP *pmp)
  {
    assert(pmp);
    if (!mp)
      return;

    mp->pmp = pmp;
    mp->cond.pcond = &pmp->pcond;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    mp->id = (vd ? ut_sem_open(vd->semkeys[0]) : -1);
    mp->plocked = &vd->locked;
#endif

#ifdef THR_TRACE
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    IDB_LOG(IDB_LOG_MTX,
	    ("mutexLightInit(mp=%p, name=%s, id=%d, key=%d)\n", mp,
	     pmp->mtname, mp->id,
	     (vd ? vd->semkeys[0] : 0)));
#else
    IDB_LOG(IDB_LOG_MTX,
	    ("mutexLightInit(mp=%p, name=%s)\n", mp, mp->pmp->mtname));
#endif
#endif

    condLightInit(vd, &mp->cond, &mp->pmp->pcond);
  }

  int
  mutexInit(DbDescription *vd, Mutex *mp, MutexP *pmp,
	    const char *mtname)
  {
    mutexLightInit(vd, mp, pmp);
#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX,
	    ("mutexInit(mp=%p, pmp=%p, name=%s)\n", mp, pmp, mtname));
#endif
    memset(pmp, 0, sizeof(*pmp));
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    pmp->u.key = (vd ? vd->semkeys[0] : 0);
#else
    pthread_mutexattr_t mattr;

    assert (!pthread_mutexattr_init(&mattr));

#ifdef HAVE_PTHREAD_PROCESS_SHARED
    assert (!pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED));
#endif

    assert (!pthread_mutex_init(&pmp->u.mp, &mattr));
#endif
    strcpy(pmp->mtname, mtname);

    pmp->magic  = MT_MAGIC;
    pmp->xid    = 0;

    pmp->locked = 0;

    pmp->wait_cnt = 0;
    condInit(vd, (mp ? &mp->cond : 0), &pmp->pcond);

#ifdef HAVE_SEMAPHORE_POLICY_POSIX
    IDB_LOG(IDB_LOG_MTX,
	    ("mutexInit(%p [mp=%p], \"%s\")\n", mp, &pmp->u.mp,
	     pmp->mtname));
#endif
    return 1;
  }

#define RETURN_ERROR(R, S) \
do { \
       IDB_LOG(IDB_LOG_MTX, ("mutex" S " (xid = %d, mp->pmp->xid = %d, locked %d) [mp = 0x%x, \"%s\"], error mutex lock r=%d, errno=%d\n", xid, mp->pmp->xid, mp->pmp->locked, mp, (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"), R, errno)); \
       fprintf(stderr, "mutex" S " (xid = %d, mp->pmp->xid = %d, locked %d) [mp = 0x%x, \"%s\"], error mutex lock r=%d, errno=%d\n", xid, mp->pmp->xid, mp->pmp->locked, mp, (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"), R, errno); \
  return statusMake(ERROR, "mutexLock (xid = %d, mp->pmp->xid = %d, state %d) [mp = 0x%x, \"%s\"], error mutex lock r=%d, errno=%d\n", xid, mp->pmp->xid, mp->pmp->locked, mp, (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"), R, errno); \
} while(0)      

#define RETURN_MAGIC_ERROR() \
      ESM_ASSERT_ABORT(0, 0, xid); \
      return statusMake(ERROR, "invalid magic number for mutex: perharps there is a log format incompatibility.\nRun 'eyedbsmtool shmmem cleanup <dbfile>'")

  // added the 10/01/02 to improve high concurrency programs:
  // MIND: currently not fully validated !
#ifdef HAVE_SEMAPHORE_POLICY_POSIX
#define MUTEX_FAST
#endif

  static Status
  mutexLock_realize(Mutex *mp, unsigned int xid, Boolean reentrant)
  {
    int r, r1;

    if (mp->pmp->magic != MT_MAGIC) {
      IDB_LOG(IDB_LOG_MTX, ("mutexLock (xid = %d) [mp = 0x%x, \"%s\"], invalid magic 0x%x, expected 0x%x\n",
			    xid, mp, (mp->pmp->mtname ? mp->pmp->mtname : "<unknown>"), mp->pmp->magic, MT_MAGIC));

      RETURN_MAGIC_ERROR();
    }

#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX, ("trying to lock %s %p reentrant %d\n", mp->pmp->mtname, mp, reentrant));
#endif

    if (cleanup)
      return Success;

#ifdef MUTEX_FAST
    if (!reentrant) {
      r = pthread_mutex_lock((pthread_mutex_t *)&mp->pmp->u.mp);
      if (r)
	RETURN_ERROR(r, "Lock");
    }
    appendGMutex(mp, xid);
    return Success;
#endif

#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    ESM_ASSERT_ABORT(mp->id>=0, 0, 0);
    ESM_ASSERT_ABORT(mp->plocked, 0, 0);
    int sid = mp->id;
#else
    int sid = 0;
#endif

#ifdef UT_SEM_FAST
    if (!reentrant) {
      ESM_ASSERT_ABORT(*mp->plocked >= 0, 0, 0);

      if (!(*mp->plocked)++) {
	// NOTE THAT: timedlock take a lot of times!!!
	//r = ut_sem_timedlock(sid, lockTimeout*1000);
	//if (r < 0)
	//return statusMake(FATAL_MUTEX_LOCK_TIMEOUT, "mutex %s", mp->pmp->mtname);
	r = ut_sem_lock(sid);
	if (r)
	  RETURN_ERROR(r, "Lock");
      }
    }
#else

    if (!reentrant) {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      r = ut_sem_lock(sid);
#else
      r = pthread_mutex_lock((pthread_mutex_t *)&mp->pmp->u.mp);
      sleeping_mp = mp;
#endif
      if (r)
	RETURN_ERROR(r, "Lock");
    }

    for (;;) {
      int wait_cnt;
      if (!mp->pmp->locked) {
	mp->pmp->xid = xid;
	mp->pmp->locked = 1;

#ifdef THR_TRACE
	IDB_LOG(IDB_LOG_MTX, ("locking %s %p\n", mp->pmp->mtname, mp));
#endif
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
	r = ut_sem_unlock(sid);
#else
	r = pthread_mutex_unlock((pthread_mutex_t *)&mp->pmp->u.mp);
	sleeping_mp = 0;
#endif
	if (r)
	  RETURN_ERROR(r, "Lock");

	break;
      }

      wait_cnt = mp->pmp->wait_cnt++;
#ifdef THR_TRACE_1
      IDB_LOG(IDB_LOG_MTX, ("waiting for unlocked %s [wait_cnt = %d]...\n",
			    mp->pmp->mtname, wait_cnt));
#endif
      r = COND_WAIT(&mp->cond, mp, xid, lockTimeout);
#ifdef THR_TRACE_1
      IDB_LOG(IDB_LOG_MTX, ("got it %s %p [%d]?\n", mp->pmp->mtname, mp, r));
#endif
      mp->pmp->wait_cnt--;

      if (r) {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
	r1 = ut_sem_unlock(sid);
#else
	r1 = pthread_mutex_unlock((pthread_mutex_t *)&mp->pmp->u.mp);
	sleeping_mp = 0;
#endif
	if (r1)
	  RETURN_ERROR(r1, "Lock");

	if (r < 0)
	  return statusMake(FATAL_MUTEX_LOCK_TIMEOUT, "mutex %s", mp->pmp->mtname);
	  
	RETURN_ERROR(r, "Lock");
      }
    }

#endif
    appendGMutex(mp, xid);

    return Success;
  }

  static Status
  mutexUnlock_realize(Mutex *mp, unsigned int xid, Boolean reentrant)
  {
    int r, mpxid;

    if (mp->pmp->magic != MT_MAGIC) {
      IDB_LOG(IDB_LOG_MTX, ("mutexUnlock (xid = %d) [mp = 0x%x, \"%s\"], "
			    "invalid magic 0x%x, expected 0x%x\n",
			    xid, mp, (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"),
			    mp->pmp->magic, MT_MAGIC));
      RETURN_MAGIC_ERROR();
    }

    if (cleanup)
      return Success;
#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX, ("trying to unlock %s %p xid %d==%d?\n",
			  mp->pmp->mtname, mp, mp->pmp->xid, xid));
#endif

    ESM_ASSERT_ABORT(mp->pmp->xid == xid || !mp->pmp->xid || !xid, 0, 0);

#ifdef MUTEX_FAST
    if (!reentrant) {
      r = pthread_mutex_unlock((pthread_mutex_t *)&mp->pmp->u.mp);
      if (r)
	RETURN_ERROR(r, "UnLock");
    }
    return releaseGMutex(mp, xid);
#endif

#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    //  assert(mp->pmp->u.key || mp->id);
    ESM_ASSERT_ABORT(mp->id>=0, 0, 0);
    ESM_ASSERT_ABORT(mp->plocked, 0, 0);
    int sid = mp->id;
#else
    int sid = 0;
#endif

#ifdef UT_SEM_FAST
    if (!reentrant) {
      ESM_ASSERT_ABORT(*mp->plocked > 0, 0, 0);
      if (!--(*mp->plocked)) {
	r = ut_sem_unlock(sid);
	if (r)
	  RETURN_ERROR(r, "Unlock");
      }
    }
#else

    ESM_ASSERT_ABORT(mp->pmp->locked, 0, 0);

#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    r = ut_sem_lock(sid);
#else
    r = pthread_mutex_lock((pthread_mutex_t *)&mp->pmp->u.mp);
    sleeping_mp = mp;
#endif

    if (r)
      RETURN_ERROR(r, "Unlock");

    mp->pmp->xid = 0;
    mp->pmp->locked = 0;

    if (mp->pmp->wait_cnt)
      COND_SIGNAL(&mp->cond);

#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX, ("unlocking %s %p\n", mp->pmp->mtname, mp));
#endif

    if (!reentrant) {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      r = ut_sem_unlock(sid);
#else
      r = pthread_mutex_unlock((pthread_mutex_t *)&mp->pmp->u.mp);
      sleeping_mp = 0;
#endif

      if (r)
	RETURN_ERROR(r, "Unlock");
    }
#endif

    return releaseGMutex(mp, xid);
  }

  Status
  mutexLock(Mutex *mp, unsigned int xid)
  {
    return mutexLock_realize(mp, xid, False);
  }

  Status
  mutexLock_r(Mutex *mp, unsigned int xid)
  {
    return mutexLock_realize(mp, xid, True);
  }

  Status
  mutexUnlock(Mutex *mp, unsigned int xid)
  {
    return mutexUnlock_realize(mp, xid, False);
  }

  Status
  mutexUnlock_r(Mutex *mp, unsigned int xid)
  {
    return mutexUnlock_realize(mp, xid, True);
  }

  int
  mutexCheckNotLock(Mutex *mp, unsigned int xid)
  {
    if (mp->pmp->xid == xid) {
      IDB_LOG(IDB_LOG_MTX, ("WARNING mutex \"%s\" is locked by CURRENT xid = %d\n",
			    (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"), xid));
      MUTEX_UNLOCK((Mutex *)mp, xid);
    }
    else if (mp->pmp->xid) {
      IDB_LOG(IDB_LOG_MTX, ("mutex \"%s\" is locked by OTHER xid = %d\n",
			    (mp->pmp->mtname ?  mp->pmp->mtname : "<unknown>"), mp->pmp->xid));
    }

    return 0;
  }

  XMOffset
  condNew(DbDescription *vd, XMHandle *xmh, CondWait *cond)
  {
    CondWaitP *pcond;
    XMOffset pcond_off;

    pcond = (CondWaitP *)XMAlloc(xmh, sizeof(CondWaitP));
    pcond_off = XM_OFFSET(xmh, pcond);

    condInit(vd, cond, pcond);
    return pcond_off;
  }

  void
  condDelete(DbDescription *vd, XMHandle *xmh, XMOffset pcond_off)
  {
    CondWaitP *pcond = (CondWaitP *)XM_ADDR(xmh, pcond_off);
    XMFree(xmh, pcond);
#ifdef HAVE_SEMAPHORE_POLICY_POSIX
    pthread_cond_destroy(&pcond->u.cond);
#endif
  }

  CondWait *
  condMake(DbDescription *vd, XMHandle *xmh, XMOffset pcond_off,
	   CondWait *cond)
  {
    CondWaitP *pcond = (CondWaitP *)XM_ADDR(xmh, pcond_off);
    condLightInit(vd, cond, pcond);
    return cond;
  }

  void
  condLightInit(DbDescription *vd, CondWait *cond, CondWaitP *pcond)
  {
    assert(pcond);
    if (!cond)
      return;

    cond->pcond = pcond;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    cond->id = (vd ? ut_sem_open(vd->semkeys[1]) : -1);
#endif
#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX,
	    ("condLightInit(cond=%p, pcond=%p, cid=%d)\n",
	     cond, pcond, cond->id));
#endif
  }

  int
  condInit(DbDescription *vd, CondWait *cond, CondWaitP *pcond)
  {
    condLightInit(vd, cond, pcond);

#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX,
	    ("condInit(cond = %p, pcond = %p, cid = %d)\n",
	     cond, pcond, (cond ? cond->id : -1)));
#endif
    memset(pcond, 0, sizeof(*pcond));
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    pcond->u.key = (vd ? vd->semkeys[1] : 0);
#else
    pthread_condattr_t cattr;

    assert (!pthread_condattr_init(&cattr));

#ifdef _POSIX_THREAD_PROCESS_SHARED
    assert (!pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED));
#endif

    assert (!pthread_cond_init(&pcond->u.cond, &cattr));
#endif

    pcond->magic = MT_MAGIC;

    return 1;
  }

  static int
  condWait_realize(CondWait *cond, Mutex *mp, unsigned int xid,
		   unsigned int timeout, Boolean reentrant)
  {
    int r;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    ESM_ASSERT_ABORT(mp->id>=0, 0, 0);
    int sid = mp->id;
    if (cond->id < 0)
      cond->id = ut_sem_open(cond->pcond->u.key);
    int cid = cond->id;
#endif
    struct timespec tm;

    if (cond->pcond->magic != MT_MAGIC) {
      IDB_LOG(IDB_LOG_MTX, ("condWait (xid = %d) [cond = 0x%x], invalid magic 0x%x, expected 0x%x\n",
			    xid, cond, cond->pcond->magic, MT_MAGIC));
      ESM_ASSERT_ABORT(0, 0, xid);
      return 1;
    }

    if (!timeout)
      timeout = wakeupInterval;

    tm.tv_sec  = time(0) + timeout;
    tm.tv_nsec = 0;

#define WK_TIMEDWAIT_BUG
#ifdef WK_TIMEDWAIT_BUG
    for (;;) { // 10/01/02: workaround problem false timeout return
#endif
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      if (reentrant) {
	Status s = mutexUnlock_r(mp, xid);
	if (s) {
	  IDB_LOG(IDB_LOG_MTX, ("condWait [cond = 0x%x], fatal error, errno=%d\n",
				cond, errno));
	  return 1;
	}
      }

      //r = ut_sem_condwait(sid, cid);
      r = ut_sem_timedcondwait(sid, cid, timeout*1000);

      if (reentrant) {
	Status s = mutexLock_r(mp, xid);
	if (s)
	  {
	    IDB_LOG(IDB_LOG_MTX, ("condWait [cond = 0x%x], fatal error, errno=%d\n",
				  cond, errno));
	    return 1;
	  }
      }
#else
      if (reentrant) {
	Status s = mutexUnlock_r(mp, xid);
	if (s)
	  {
	    IDB_LOG(IDB_LOG_MTX, ("condWait [cond = 0x%x], fatal error, errno=%d\n",
				  cond, errno));
	    return 1;
	  }
      }


#ifdef THR_TRACE
      IDB_LOG(IDB_LOG_MTX, ("condWait [xid = %d, cond = 0x%x] sleeping for %d seconds [%sreentrant] %s\n",
			    xid, cond, timeout, (reentrant ? "" : "non "), mp->pmp->mtname));
#endif

      /*
	printf("condWait [xid = %d, cond = 0x%x] sleeping for %d seconds [%sreentrant] %s\n",
	xid, cond, timeout, (reentrant ? "" : "non "), mp->pmp->mtname);
      */

      r = pthread_cond_timedwait(&cond->pcond->u.cond, &mp->pmp->u.mp, &tm);

#ifdef THR_TRACE
      IDB_LOG(IDB_LOG_MTX,
	      ("condWait [xid = %d, cond = 0x%x] wakingup [return=%d]\n",
	       xid, cond, r));
#endif

      if (reentrant) {
	Status s = mutexLock_r(mp, xid);
	if (s)
	  {
	    IDB_LOG(IDB_LOG_MTX, ("condWait [cond = 0x%x], fatal error, errno=%d\n",
				  cond, errno));
	    return 1;
	  }
      }

#ifdef THR_TRACE_2
      IDB_LOG(IDB_LOG_MTX, ("condWait (xid = %d) [cond = 0x%x] wakeup %d OK reentrant %d\n",
			    xid, cond, r, reentrant));
#endif
#endif

      if (r == ETIMEDOUT ) {
	IDB_LOG(IDB_LOG_MTX, ("condWait timedwait [cond = 0x%x]\n", cond));
	time_t t = time(0);
	//printf("elapsed %d @%d\n", t - tm.tv_sec, pthread_self());
#ifdef WK_TIMEDWAIT_BUG
	if (t - tm.tv_sec >= 0)
	  return -(timeout);
	continue;
#else
	return -(timeout);
#endif
      }

      if (r) {
	IDB_LOG(IDB_LOG_MTX, ("condWait [cond = 0x%x], fatal error, r=%d, errno=%d, reentrant=%d\n", cond, r, errno, reentrant));
	perror("condWait");
	return r;
      }

      return r;
#ifdef WK_TIMEDWAIT_BUG
    }
#endif
  }

  int
  condWait(CondWait *cond, Mutex *mp, unsigned int xid,
	   unsigned int timeout)
  {
    return condWait_realize(cond, mp, xid, timeout, False);
  }

  int
  condWait_r(CondWait *cond, Mutex *mp, unsigned int xid,
	     unsigned int timeout)
  {
    return condWait_realize(cond, mp, xid, timeout, True);
  }

  int
  condSignal(CondWait *cond)
  {
    int r;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    if (cond->id < 0)
      cond->id = ut_sem_open(cond->pcond->u.key);
    int cid = cond->id;
#endif

    if (cond->pcond->magic != MT_MAGIC) {
      IDB_LOG(IDB_LOG_MTX, ("condSignal [cond = 0x%x], invalid magic 0x%x, expected 0x%x\n",
			    cond, cond->pcond->magic, MT_MAGIC));

      return 1;
    }

#ifdef THR_TRACE
    IDB_LOG(IDB_LOG_MTX, ("condSignal [cond = 0x%x]\n", cond));
#endif
    //printf("condSignal [cond = 0x%x]\n", cond);

#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    r = ut_sem_signal(cid);
#else
    r = pthread_cond_signal(&cond->pcond->u.cond);
#endif

    if (r) {
      IDB_LOG(IDB_LOG_MTX, ("condSignal [cond = 0x%x], fatal error, r=%d, errno=%d\n", cond, r, errno));
      perror("condSignal");

      /*      ESM_ASSERT(0, 0, 0);*/
      return r;
    }

    return r;
  }

  static eyedblib::ThreadPool *thrpool;
  static eyedblib::ThreadPool *(*thrpool_get)();

  void
  setThreadPool(eyedblib::ThreadPool *_thrpool)
  {
    thrpool = _thrpool;
  }

  void
  setThreadPoolGet(eyedblib::ThreadPool *(*_thrpool_get)())
  {
    thrpool_get = _thrpool_get;
  }

  eyedblib::ThreadPool *
  getThreadPool()
  {
    if (thrpool)
      return thrpool;
    if (thrpool_get)
      thrpool = thrpool_get();

    return thrpool;
  }
}
