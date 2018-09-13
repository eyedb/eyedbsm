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


#ifndef _EYEDBLIB_SEMLIB_H
#define _EYEDBLIB_SEMLIB_H

extern int
  ut_sem_create(int key),
  ut_sem_rm(int id),
  ut_sem_open(int key),
  ut_sem_close(int id),
  ut_sem_wait(int id),
  ut_sem_condwait(int id1, int id2),
  ut_sem_timedwait(int id, int msecs),
  ut_sem_timedcondwait(int id1, int id2, int msecs),
  ut_sem_signal(int id),
  ut_sem_lock(int id),
  ut_sem_unlock(int id),
  ut_sem_timedlock(int id, int msecs),
  ut_sem_get(int id),
  ut_sem_set(int id, int val),

  ut_sem_createSX(int key),
  ut_sem_openSX(int key),
  ut_sem_lockS(int id),
  ut_sem_lockX(int id),
  ut_sem_unlockS(int id),
  ut_sem_unlockX(int id),

  ut_sem_find(int *pkey, int sx);

#endif
