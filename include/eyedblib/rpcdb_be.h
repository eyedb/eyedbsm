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


#ifndef _EYEDBLIB_RPCDB_BE_H
#define _EYEDBLIB_RPCDB_BE_H

#include <eyedblib/rpcdb.h>

typedef unsigned int rpcDB_TransactionMode;

typedef struct {
  int id;
  rpcDB_LocalDBContext ldbctx;
  int refcnt;
} rpcDB_DbHandleInfo;

typedef struct {
  rpcDB_DbHandleInfo *dbhinfo;
  void *dbh;
  int flags;
  rpcDB_TransactionMode trmode;
  rpc_Boolean local;
} rpcDB_DbHandleClientInfo;

#define RPCDB_MAX_DBH 128

typedef struct {
  rpcDB_DbHandleClientInfo *dbhclientinfo[RPCDB_MAX_DBH];
  void *user_data;
} rpcDB_ClientInfo;

extern rpcDB_DbHandleInfo *
rpcDB_dbhinfoNew(int id);

extern rpcDB_DbHandleInfo *
rpcDB_dbhinfoGet(int id);

extern void
rpcDB_clientDbhDelete(rpcDB_DbHandleClientInfo *dcinfo);

extern int
rpcDB_clientDbhSet(rpc_ClientId, rpc_Boolean, int, rpcDB_DbHandleInfo *, void *);

extern rpcDB_DbHandleClientInfo *
rpcDB_clientDbhGet(rpc_ClientId, int);

extern void rpcDB_mutexInit(void);

extern void rpcDB_lock(void);
extern void rpcDB_unlock(void);

extern rpcDB_ClientInfo *rpcDB_clientInfoGet(rpc_ClientId);

extern rpcDB_DbHandleInfo *rpcDB_open_realize(rpc_Server *, int);
extern rpcDB_DbHandleInfo *rpcDB_open_simple_realize(rpc_Server *, int);

extern rpc_Boolean
rpcDB_close_do(rpc_Server *, rpcDB_DbHandleClientInfo **,
	       void *(*close)(rpcDB_DbHandleClientInfo *),
	       void **);

extern rpc_Boolean
rpcDB_close_realize(rpc_Server *, rpc_ClientId, int,
		    void *(*close)(rpcDB_DbHandleClientInfo *),
		    void **);
extern int
rpcDB_getDbhId();

#endif
