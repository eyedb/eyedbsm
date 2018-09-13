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


#ifndef _EYEDBLIB_RPC_BE_H
#define _EYEDBLIB_RPC_BE_H

#include <eyedblib/rpc.h>
#include <eyedblib/connman.h>

/* back end: server */
typedef struct rpc_Server rpc_Server;

typedef struct rpc_PortHandle rpc_PortHandle;

typedef struct {
  RPC_DATA;
  int fd;
  int buff_size;
  void (*garbage_fun)(void *, void *);
  void *garbage_data;
} rpc_ServerData;

enum {
  rpc_BuffUsed = 10,
  rpc_TempDataUsed,
  rpc_PermDataUsed
};

typedef enum {
  rpc_MonoProc = 1,
  rpc_MultiThreaded,
  rpc_MultiProcs,
  rpc_FrontThreaded
} rpc_ServerMode;

typedef unsigned int rpc_ClientId;

typedef struct rpc_ServerFunction rpc_ServerFunction;

typedef void (*rpc_UserServerFunction)(rpc_ClientId, void *);
typedef void (*rpc_ConnectionHandlerFunction)(rpc_Server *, rpc_ClientId, rpc_Boolean);

extern rpc_Server *rpc_serverCreate(rpc_ServerMode, unsigned long,
				    int, int,
				    void (*init)(int *, int, rpc_ConnInfo *),
				    void (*release)(rpc_ConnInfo *),
				    void (*begin)(int, void *),
				    void (*end)(int, void *), void *);

extern rpc_ServerFunction *
rpc_makeUserServerFunction(rpc_Server *, rpc_RpcDescription *, rpc_UserServerFunction);

extern rpc_Status
rpc_setServerArgSize(rpc_Server *, int);

extern rpc_Status
rpc_portOpen(rpc_Server *, const char *, const char *, rpc_PortHandle **);

extern rpc_Status
rpc_serverMainLoop(rpc_Server *, rpc_PortHandle **, int);

extern rpc_ArgType rpc_makeServerUserType(rpc_Server *, int,
					  rpc_UserArgFunction);

extern void
rpc_serverOptionsGet(int, char *[], char **, char **);

extern rpc_ConnectionHandlerFunction
rpc_setConnectionHandler(rpc_Server *, rpc_ConnectionHandlerFunction);

extern rpc_Server *rpc_getMainServer(void);

extern void rpc_setProgName(const char *);

extern int rpc_checkConn();

extern void rpc_setTimeOut(int timeout);

extern rpc_ClientId rpc_client_id;

#endif
