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

#include <string.h>

#include <eyedbsm/eyedbsm.h>
#include <eyedblib/log.h>
#include <pthread.h>
#include <eyedblib/butils.h>
#include <stdlib.h>
#include <stdarg.h>
#include <eyedblib/m_mem.h>
#include "lib/m_mem_p.h"

/*extern char *eyedblib::getFBuffer(const char *fmt, va_list ap);*/

#define NSTATUS 8

namespace eyedbsm {

  static int w_status;

  struct StatusContext {
    StatusRec status;
    char *err_msg;
    int err_msg_len;
  };

  static StatusContext statusCtx[NSTATUS];

  static StatusContext *
  getStatusContext(int *pnstatus)
  {
    if (w_status >= NSTATUS)
      w_status = 0;
    if (pnstatus)
      *pnstatus = w_status;
    return &statusCtx[w_status++];
  }

  Status
  statusMake(Error err, const char *fmt, ...)
  {
    va_list ap;
    StatusContext *s;
    int nstatus;
    char *buf;

    va_start(ap, fmt);
    buf = eyedblib::getFBuffer(fmt, ap);
    va_end(ap);

    va_start(ap, fmt);
    vsprintf(buf, fmt, ap);
    va_end(ap);

    IDB_LOG(IDB_LOG_EXCEPTION, ("%s\n", buf));

    s = getStatusContext(&nstatus);

    if (strlen(buf) >= s->err_msg_len) {
      s->err_msg_len = strlen(buf)+10;
      s->err_msg = (char *)m_realloc(s->err_msg, s->err_msg_len);
    }

    s->status.err = err;
    s->status.err_msg = s->err_msg;
    strcpy(s->status.err_msg, buf);

    nstatus++;

    return &s->status;
  }

  Status
  statusMake_s(Error err)
  {
    StatusContext *s;

    s = getStatusContext(0);

    s->status.err = err;
    s->status.err_msg = (char*)""; /*@@@@warning cast*/

    return &s->status;
  }

  static const char* _seError[N_ERROR];

#define PREFIX "storage manager: "

  void
  errorInit(void)
  {
    if (!_seError[SUCCESS]) {
      _seError[SUCCESS] =
	PREFIX "success";
      _seError[ERROR] =
	PREFIX "error";
      _seError[SYS_ERROR] =
	PREFIX "system error";
      _seError[CONNECTION_FAILURE] =
	PREFIX "connection failure";
      _seError[SERVER_FAILURE] =
	PREFIX "server failure";
      _seError[CANNOT_LOCK_SHMFILE] =
	PREFIX "cannot lock shm file";
      _seError[DB_ALREADY_LOCK_BY_A_SERVER] =
	PREFIX "db already lock by a server";
      _seError[INVALID_DBID] =
	PREFIX "invalid dbid";
      _seError[INVALID_MAXSIZE] =
	PREFIX "invalid maxsize";
      _seError[INVALID_SIZESLOT] =
	PREFIX "invalid sizeslot";
      _seError[INVALID_NBSLOTS] =
	PREFIX "invalid slot number";
      _seError[INVALID_NBOBJS] =
	PREFIX "invalid object number";
      _seError[DATABASE_CREATION_ERROR] =
	PREFIX "database creation error";
      _seError[DATABASE_ACCESS_DENIED] =
	PREFIX "database access denied";
      _seError[DATABASE_OPEN_FAILED] =
	PREFIX "database open failed";
      _seError[INVALID_DATAFILE_CNT] =
	PREFIX "invalid datafile count";
      _seError[INVALID_DATASPACE_CNT] =
	PREFIX "invalid dataspace count";
      _seError[INVALID_DATAFILE_CNT_IN_DATASPACE] =
	PREFIX "invalid datafile count in a dataspace";
      _seError[INVALID_DBFILE] =
	PREFIX "invalid database file";
      _seError[INVALID_DBFILE_ACCESS] =
	PREFIX "invalid database file access";
      _seError[INVALID_SHMFILE] =
	PREFIX "invalid shm file";
      _seError[INVALID_SHMFILE_ACCESS] =
	PREFIX "invalid shm file access";
      _seError[INVALID_OBJMAP_ACCESS] =
	PREFIX "invalid oid map file access";
      _seError[INVALID_DATAFILE] =
	PREFIX "invalid datafile";
      _seError[INVALID_DATASPACE] =
	PREFIX "invalid dataspace";
      _seError[INVALID_DMPFILE] =
	PREFIX "invalid data map file";
      _seError[INVALID_DATAFILEMAXSIZE] =
	PREFIX "invalid datafile maxsize";
      _seError[INVALID_FILES_COPY] =
	PREFIX "invalid files copy";
      _seError[INVALID_DBFILES_COPY] =
	PREFIX "invalid database files copy";
      _seError[INVALID_DATAFILES_COPY] =
	PREFIX "invalid data files copy";
      _seError[INVALID_SHMFILES_COPY] =
	PREFIX "invalid shm files copy";
      _seError[INVALID_OBJMAPFILES_COPY] =
	PREFIX "invalid object map files copy";
      _seError[DBFILES_IDENTICAL] =
	PREFIX "database files are identical";
      _seError[DATAFILES_IDENTICAL] =
	PREFIX "data files are identical";
      _seError[DBFILE_ALREADY_EXISTS] =
	PREFIX "database file already exists";
      _seError[SHMFILE_ALREADY_EXISTS] =
	PREFIX "shm file already exists";
      _seError[OBJMAPFILE_ALREADY_EXISTS] =
	PREFIX "object map file already exists";
      _seError[DATAFILE_ALREADY_EXISTS] =
	PREFIX "data file already exists";
      _seError[SIZE_TOO_LARGE] =
	PREFIX "size too large";
      _seError[WRITE_FORBIDDEN] =
	PREFIX "write forbidden";
      _seError[BACKEND_INTERRUPTED] =
	PREFIX "backend interrupted";
      _seError[CONN_RESET_BY_PEER] =
	PREFIX "connection reset by peer";
      _seError[FATAL_MUTEX_LOCK_TIMEOUT] =
	PREFIX "fatal mutex lock timeout: the shmem must be cleanup "
	"(or possibly the computer is overloaded)";
      _seError[LOCK_TIMEOUT] =
	PREFIX "lock timeout";
      _seError[INVALID_FLAG] =
	PREFIX "invalid flag";
      _seError[INVALID_DB_HANDLE] =
	PREFIX "invalid database handle";
      _seError[TRANSACTION_TOO_MANY_NESTED] =
	PREFIX "too many transactions nested";
      _seError[TOO_MANY_TRANSACTIONS] =
	PREFIX "too many transactions";
      _seError[TRANSACTION_NEEDED] =
	PREFIX "transaction needed";
      _seError[TRANSACTION_LOCKING_FAILED] =
	PREFIX "transaction locking failed";
      _seError[TRANSACTION_UNLOCKING_FAILED] =
	PREFIX "transaction unlocking failed";
      _seError[DEADLOCK_DETECTED] =
	PREFIX "deadlock detected";
      _seError[INVALID_TRANSACTION_MODE] =
	PREFIX "invalid transaction mode";
      _seError[RW_TRANSACTION_NEEDED] =
	PREFIX "read write mode transaction needed";
      _seError[NOT_YET_IMPLEMENTED] =
	PREFIX "not yet implemented";
      _seError[MAP_ERROR] =
	PREFIX "map error";
      _seError[INVALID_MAPTYPE] =
	PREFIX "invalid map type";
      _seError[INVALID_OBJECT_SIZE] =
	PREFIX "invalid object size";
      _seError[INVALID_OFFSET] =
	PREFIX "invalid object offset";
      _seError[TOO_MANY_OBJECTS] =
	PREFIX "maximum object count has been reached";
      _seError[NO_DATAFILESPACE_LEFT] =
	PREFIX "no space left on dataspace";
      _seError[NO_SHMSPACE_LEFT] =
	PREFIX "no space left on shm";
      _seError[INVALID_SIZE] =
	PREFIX "invalid size";
      _seError[PROTECTION_INVALID_UID] =
	PREFIX "protection invalid uid";
      _seError[PROTECTION_DUPLICATE_UID] =
	PREFIX "protection duplicate uid";
      _seError[PROTECTION_DUPLICATE_NAME] =
	PREFIX "protection duplicate name";
      _seError[PROTECTION_NOT_FOUND] =
	PREFIX "protection not found";
      _seError[INVALID_OID] =
	PREFIX "invalid oid";
      _seError[OBJECT_PROTECTED] =
	PREFIX "object protected";
      _seError[INVALID_ROOT_ENTRY_SIZE] =
	PREFIX "invalid root entry size";
      _seError[INVALID_ROOT_ENTRY_KEY] =
	PREFIX "invalid root entry key";
      _seError[INVALID_READ_ACCESS] =
	PREFIX "invalid read access";
      _seError[INVALID_WRITE_ACCESS] =
	PREFIX "invalid write access";
      _seError[PROT_NAME_TOO_LONG] =
	PREFIX "prot name too long";
      _seError[ROOT_ENTRY_EXISTS] =
	PREFIX "root entry exists";
      _seError[TOO_MANY_ROOT_ENTRIES] =
	PREFIX "too many root entries";
      _seError[ROOT_ENTRY_NOT_FOUND] =
	PREFIX "root entry not found";
      _seError[NOTIMPLEMENTED] =
	PREFIX "notimplemented";
      _seError[NO_SETUID_PRIVILEGE] =
	PREFIX "no setuid privilege";
      _seError[COMPATIBILITY_ERROR] =
	PREFIX "compatibility error";
      _seError[INTERNAL_ERROR] =
	PREFIX "internal error";
      _seError[FATAL_ERROR] =
	PREFIX "fatal error";
      _seError[COLLAPSING_LIMIT] =
	PREFIX "collapsing limit";
#if 1
      {
	int i;
	for (i = 0; i < N_ERROR; i++)
	  if (!_seError[i])
	    fprintf(stderr, "_seError not set for %d\n", i);
      }
#endif
    }
  }

  const char *
  statusGet(Status status)
  {
    if (status != Success)
      {
	const char *s = status->err_msg;
	errorInit();

	if (s && *s)
	  {
	    static int buf_len;
	    static char *buf;
	    int len = strlen(_seError[status->err]) + strlen(s) + 12;
	    if (len >= buf_len) {
	      buf_len = len + 256;
	      free(buf);
	      buf = (char *)m_malloc(buf_len);
	    }
	    sprintf(buf, "%s: %s", _seError[status->err], s);
	    return buf;
	  }
	else
	  return _seError[status->err];
      }

    return "";
  }

  const char *
  statusGet_err(int err)
  {
    if (err != SUCCESS) {
      errorInit();
      if (err >= SUCCESS && err < N_ERROR)
	return _seError[err];
      else
	return "";
    }

    return "";
  }

  Status
  statusPrint(Status status, const char *fmt, ...)
  {
    va_list ap;

    va_start(ap, fmt);

    if (status != Success) {
      const char *s = status->err_msg;
      char *buf;

      errorInit();

      buf = eyedblib::getFBuffer(fmt, ap);
      vsprintf(buf, fmt, ap);

      fprintf(stderr, "%s: ", _seError[status->err]);
      if (*buf) {
	fprintf(stderr, "%s: ", buf);

	if (s && *s)
	  fprintf(stderr, "%s\n", s);
      }
      else {
	if (s && *s)
	  fprintf(stderr, ": %s", s);
	fprintf(stderr, "\n");
      }

      fflush(stderr);
    }

    va_end(ap);
    return status;
  }
}
