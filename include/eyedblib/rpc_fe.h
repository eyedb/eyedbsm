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


#ifndef _EYEDBLIB_RPC_FE_H
#define _EYEDBLIB_RPC_FE_H

#include <eyedblib/rpc.h>
#include <string>

typedef struct rpc_Client rpc_Client;

typedef struct {
  RPC_DATA;
} rpc_ClientData;

typedef struct rpc_ConnHandle rpc_ConnHandle;

typedef struct {
  rpc_RpcDescription *rd;
} rpc_ClientFunction;

/* function prototypes */
extern rpc_Client *rpc_clientCreate(void);

extern rpc_ArgType rpc_makeClientUserType(rpc_Client *, int,
					  rpc_UserArgFunction, rpc_Boolean);
				   
extern rpc_ClientFunction *
rpc_makeUserClientFunction(rpc_Client *, rpc_RpcDescription *);

extern rpc_Status
rpc_connOpen(rpc_Client *, const char *, const char *, rpc_ConnHandle **, unsigned long, int, int, std::string &);

extern rpc_Status
rpc_connClose(rpc_ConnHandle *);

extern rpc_Status
rpc_setClientArgSize(rpc_Client *, int);

extern rpc_Status
rpc_rpcMake(rpc_ConnHandle *, int which, rpc_ClientFunction *, void *);

#endif
