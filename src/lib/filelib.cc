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
#include <unistd.h>
#include <fcntl.h>
#include <eyedblib/filelib.h>

#ifdef HAVE_FLOCK_T
#define FLOCK_DECL flock_t
#else
#define FLOCK_DECL struct flock
#endif

int ut_file_lock(int fd, ut_Lock excl, ut_Block block)
{
  FLOCK_DECL flk = {0};

  flk.l_type = (excl == ut_LOCKX ? F_WRLCK : F_RDLCK);

  return fcntl(fd, (block == ut_BLOCK ? F_SETLKW : F_SETLK), &flk);
}

int ut_file_unlock(int fd)
{
  FLOCK_DECL flk = {0};

  flk.l_type = F_UNLCK;

  return fcntl(fd, F_SETLK, &flk);
}
