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


#ifndef _EYEDBSM_MUTEX_H
#define _EYEDBSM_MUTEX_H

#include "xm_alloc.h"
#include <eyedblib/machtypes.h>
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
#include <eyedblib/semlib.h>
#endif
#include <pthread.h>

namespace eyedbsm {
#define MAXCLS  0

  struct CondWaitP {
    eyedblib::uint32 magic;
    union {
      int key; /* semaphore version */
      pthread_cond_t cond; /* mutex version */
    } u;
  };

  struct CondWait {
    CondWaitP *pcond;
    int id; /* semaphore version */
  };

  struct MutexP {
    eyedblib::uint32 magic;
    union {
      int key; /* semaphore version */
      pthread_mutex_t mp; /* mutex version */
    } u;
    char mtname[16];
    unsigned int xid;
    int locked;
    int wait_cnt;
    CondWaitP pcond;
  };

  struct Mutex {
    MutexP *pmp;
    CondWait cond;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    int id;
    int *plocked;
#endif
  };

  struct CondWaitLink;

  struct CondWaitList {
    int link_cnt;
    CondWaitLink *first;
    CondWaitLink *last;
  };

#define MUTEX_LOCK_TRACE(MP, XID)\
 utlog("XLOCK %s, %d\n", __FILE__, __LINE__); \
 mutexLock(MP, XID)

#define MUTEX_UNLOCK_TRACE(MP, XID) \
 utlog("UNLOCK %s, %d\n", __FILE__, __LINE__); \
 mutexUnlock(MP, XID)

#define MUTEX_LOCK(MP, XID) \
 do { \
    Status se = mutexLock(MP, XID); \
    if (se) return se; \
 } while(0)

#define MUTEX_UNLOCK(MP, XID) mutexUnlock(MP, XID)
#define MUTEX_LOCK_VOID(MP, XID)  mutexLock(MP, XID)

#define COND_WAIT(C, MP, XID, TIMEOUT)   condWait(C, MP, XID, TIMEOUT)
#define COND_WAIT_R(C, MP, XID, TIMEOUT) condWait_r(C, MP, XID, TIMEOUT)
#define COND_SIGNAL(C)        condSignal(C)

  struct DbDescription;

  extern void mutexLightInit(DbDescription *vd, Mutex *mp, MutexP *pmp);
  //  mutexLightInit(int semkeys[], int *plocked, Mutex *mp, MutexP *pmp);

  extern int mutexInit(DbDescription *vd, Mutex *, MutexP *, const char *),
  //mutexInit(int semkeys[], int *plocked, Mutex *, MutexP *, const char *),
    mutexCheckNotLock(Mutex *_mp, unsigned int xid);

  extern Status mutexLock(Mutex *, unsigned int),
    mutexUnlock(Mutex *, unsigned int);

  extern int condInit(DbDescription *, CondWait *, CondWaitP *),
    //condInit(int semkeys[], CondWait *, CondWaitP *),
    condSignal(CondWait *),
    condWait(CondWait *, Mutex *, unsigned int, unsigned int timeout),
    condWait_r(CondWait *, Mutex *, unsigned int, unsigned int timeout);

  extern void condLightInit(DbDescription *, CondWait *, CondWaitP *);
    //condLightInit(int semkeys[], CondWait *, CondWaitP *);

  extern XMOffset
  condNew(DbDescription *, XMHandle *, CondWait *);

  extern void
  condDelete(DbDescription *, XMHandle *, XMOffset);

  extern CondWait *
  condMake(DbDescription *, XMHandle *, XMOffset, CondWait *);

  extern void
  mutexes_init(),
    mutexes_release();


  class MutexLocker {

  public:
    MutexLocker(Mutex &_mut) : mut(&_mut) {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      MUTEX_LOCK_VOID(mut, mut->id);
#else
      MUTEX_LOCK_VOID(mut, 0);
#endif
      locked = true;
    }
    void lock() {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      MUTEX_LOCK_VOID(mut, mut->id);
#else
      MUTEX_LOCK_VOID(mut, 0);
#endif
      locked = true;
    }

    void unlock() {
      locked = false;
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      MUTEX_UNLOCK(mut, mut->id);
#else
      MUTEX_UNLOCK(mut, 0);
#endif
    }

    ~MutexLocker() {
      if (locked) {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
	MUTEX_UNLOCK(mut, mut->id);
#else
	MUTEX_UNLOCK(mut, 0);
#endif
      }
    }

  private:
    Mutex *mut;
    bool locked;
  };
}

#endif
