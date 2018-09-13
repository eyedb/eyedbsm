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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <eyedblib/semlib.h>

/* WARNING!!!!!!!!!!!!!!!! */
/*#define SEM_UNDO 0*/

//#define SECURE_LOCK

/*#define TRACE*/

#ifdef TRACE
int semlib_trace;

#define RETURN(R) \
  if (semlib_trace) \
    printf("%d: semlib: returning %d\n", pthread_self(), R); \
  return r

#define PTRACE(X) if (semlib_trace) printf X
#else
#define RETURN(R) \
  return r
#define PTRACE(X)
#endif

int ut_sem_create(int key)
{
  int r;
  PTRACE(("%d: ut_sem_create(%d)\n", pthread_self(), key));

  if (ut_sem_open(key) >= 0)
    r = -1;
  else {
    /* mind: permission! */
    r = semget(key, 1, 0666|IPC_CREAT);
  }
  RETURN(r);
}

int ut_sem_open(int key)
{
  int r;
  PTRACE(("%d: ut_sem_open(%d)\n", pthread_self(), key));
  if (!key)
    r = -1;
  else
    r = semget(key, 1, 0);
  RETURN(r);
}

int ut_sem_rm(int id)
{
  int r;
  PTRACE(("%d: ut_sem_rm(%d)\n", pthread_self(), id));
  r = semctl(id, 0, IPC_RMID, 0);
  RETURN(r);
}

int ut_sem_close(int id)
{
  return 0;
}

int ut_sem_wait(int id)
{
  static struct sembuf op = {0, -1, SEM_UNDO};
  int r;
  PTRACE(("%d: ut_sem_wait(%d)\n", pthread_self(), id));
  r = semop(id, &op, 1);
  RETURN(r);
}

int ut_sem_condwait(int id1, int id2)
{
  int r;
  PTRACE(("%d: ut_sem_condwait(%d, %d)\n", pthread_self(), id1, id2));
  r = ut_sem_unlock(id1);
  if (r < 0) return r;
  r = ut_sem_wait(id2);
  if (r < 0) return r;
  return ut_sem_lock(id1);
}

static void alarm_handler(int sig)
{
}

static int
ut_setitimer(int msecs)
{
  struct itimerval timer_value;

  timer_value.it_value.tv_sec = msecs/1000;
  timer_value.it_value.tv_usec = (msecs - (msecs/1000)*1000)*1000;
  timer_value.it_interval.tv_sec = 0;
  timer_value.it_interval.tv_usec = 0;

  signal(SIGALRM, alarm_handler);

  if (setitimer(ITIMER_REAL, &timer_value, 0) < 0)
    return -1;

  return 0;
}

static int
ut_unsetitimer(void)
{
  struct itimerval timer_value;

  signal(SIGALRM, SIG_DFL);

  timer_value.it_value.tv_sec = 0;
  timer_value.it_value.tv_usec = 0;
  timer_value.it_interval.tv_sec = 0;
  timer_value.it_interval.tv_usec = 0;

  if (setitimer(ITIMER_REAL, &timer_value, 0) < 0)
    return -1;

  return 0;
}

int ut_sem_timedwait(int id, int msecs)
{
  static struct sembuf op = {0, -1, SEM_UNDO};
  int r;

  PTRACE(("%d: ut_sem_timedwait(%d, msecs=%d)\n", pthread_self(), id, msecs));
  if (ut_setitimer(msecs))
    return -1;

  r = semop(id, &op, 1);

  if (r < 0 && errno == EINTR)
    r = ETIMEDOUT;

  if (ut_unsetitimer())
    return -1;

  RETURN(r);
}

int ut_sem_timedcondwait(int id1, int id2, int msecs)
{
  int tr = 0;
  int r;
  PTRACE(("%d: ut_sem_timedcondwait(%d, %d, msecs=%d)\n", pthread_self(), id1, id2, msecs));
  r = ut_sem_unlock(id1);
  if (r < 0) return r;
  r = ut_sem_timedwait(id2, msecs);
  if (r < 0) return r;

  if (r == ETIMEDOUT)
    {
      (void)ut_sem_lock(id1);
      return ETIMEDOUT;
    }

  return ut_sem_lock(id1);
}

int ut_sem_signal(int id)
{
  static struct sembuf op = {0, 1, SEM_UNDO};
  int r;
  PTRACE(("%d: ut_sem_condsignal(%d)\n", pthread_self(), id));
  r = semop(id, &op, 1);
  RETURN(r);
}

int ut_sem_lock(int id)
{
#ifdef SECURE_LOCK
  return ut_sem_timedlock(id, 4000);
#else
  static struct sembuf op[2] = {
    0, 0, 0,
    0, 1, SEM_UNDO
  };
  int r;
  PTRACE(("%d: ut_sem_lock(%d)\n", pthread_self(), id));
  r = semop(id, op, 2);
  RETURN(r);
#endif
}

int ut_sem_timedlock(int id, int msecs)
{
  int r;
  static struct sembuf op[2] = {
    0, 0, 0,
    0, 1, SEM_UNDO
  };

  PTRACE(("%d: ut_sem_timedlock(%d, msecs=%d)\n", pthread_self(), id, msecs));

  if (ut_setitimer(msecs))
    return -1;

  r = semop(id, op, 2);

  if (r < 0 && errno == EINTR) {
#ifdef SECURE_LOCK
    printf("%d: timeout on sem %d\n", id);
#endif
    r = ETIMEDOUT;
  }

  if (ut_unsetitimer())
    return -1;

  RETURN(r);
}

int ut_sem_unlock(int id)
{
  static struct sembuf op = {0, -1, SEM_UNDO};
  int r;
  PTRACE(("%d: ut_sem_unlock(%d)\n", pthread_self(), id));
  r = semop(id, &op, 1);
  RETURN(r);
}

int ut_sem_createSX(int key)
{
  int r;
  PTRACE(("%d: ut_sem_createSX(%d)\n", pthread_self(), key));
  if (ut_sem_open(key) >= 0)
    r = -1;
  else
    /* mind: permission! */
    r = semget(key, 2, 0666|IPC_CREAT);
  RETURN(r);
}

int ut_sem_openSX(int key)
{
  int r;
  PTRACE(("%d: ut_sem_openSX(%d)\n", pthread_self(), key));
  if (!key)
    r = -1;
  else
    r = semget(key, 2, 0);
  RETURN(r);
}

int ut_sem_lockX(int id)
{
  static struct sembuf op[3] = {
    0, 0, 0,
    1, 0, 0,
    0, 1, SEM_UNDO
  };
  int r;
  PTRACE(("%d: ut_sem_lockX(%d)\n", pthread_self(), id));
  r = semop(id, op, 3);
  RETURN(r);
}

int ut_sem_lockS(int id)
{
  static struct sembuf op[2] = {
    0, 0, 0,
    1, 1, SEM_UNDO
  };
  int r;
  PTRACE(("%d: ut_sem_lockS(%d)\n", pthread_self(), id));
  r = semop(id, op, 2);
  RETURN(r);
}

int ut_sem_unlockX(int id)
{
  static struct sembuf op = {0, -1, SEM_UNDO};
  int r;
  PTRACE(("%d: ut_sem_unlockX(%d)\n", pthread_self(), id));
  r = semop(id, &op, 1);
  RETURN(r);
}

int ut_sem_unlockS(int id)
{
  static struct sembuf op = {1, -1, SEM_UNDO};
  int r;
  PTRACE(("%d: ut_sem_unlockS(%d)\n", pthread_self(), id));
  r = semop(id, &op, 1);
  RETURN(r);
}

int ut_sem_get(int id)
{
  return semctl(id, 0, GETVAL, 0);
}

int ut_sem_set(int id, int val)
{
#ifdef HAVE_UNION_SEMUN_VAL
  union semun s;
#else
  union semun {
    int val;
    struct semid_ds *buf;
    ushort *array;
  } s;
#endif

  s.val = val;
  return semctl(id, 0, SETVAL, s);
}

#define FIRST_SEM_KEY   100
#define LAST_SEM_KEY  20000

int ut_sem_find(int *pkey, int sx)
{
  int key, id;

  for (key = FIRST_SEM_KEY; key < LAST_SEM_KEY; key++)
    if ((id = ((*(sx ? ut_sem_createSX : ut_sem_create))(key))) >= 0) {
      *pkey = key;
      return id;
    }

  *pkey = 0;
  return -1;
}
