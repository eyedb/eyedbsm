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


#ifndef _EYEDBLIB_RPC_H
#define _EYEDBLIB_RPC_H

#include <stdio.h>
#include <eyedblib/machtypes.h>

enum {
  rpc_VoidType = 1,
  rpc_ByteType,
  rpc_Int16Type,
  rpc_Int32Type,
  rpc_Int64Type,
  rpc_StringType,
  rpc_DataType,
  rpc_StatusType,
  rpc_NBaseType
};

typedef unsigned int rpc_ArgType;

typedef enum {
  rpc_Send = 0x1,
  rpc_Rcv  = 0x2
} rpc_SendRcv;

typedef struct {
  rpc_ArgType type;
  rpc_SendRcv send_rcv;
} rpc_Arg;

enum {
  rpc_Success = 0,
  rpc_ConnectionFailure,
  rpc_ServerFailure,
  rpc_Error
};

typedef unsigned int rpc_Status;
typedef unsigned int rpc_RpcCode;

typedef enum {
  rpc_False = 0,
  rpc_True = 1
} rpc_Boolean;

typedef struct {
  rpc_RpcCode code;
  int nargs;
  rpc_Arg *args;
  rpc_ArgType arg_ret;
} rpc_RpcDescription;

typedef enum {
  rpc_To   = 0x10,
  rpc_From = 0x11
} rpc_FromTo;

#define RPC_DATA \
  int size; \
  void *data; \
  int status

typedef struct {
  RPC_DATA;
} rpc_Data;

typedef void (*rpc_UserArgFunction)(rpc_Arg *, char **, void *, rpc_SendRcv,
				    rpc_FromTo);

/* function prototypes */
extern rpc_RpcDescription *rpc_newRpcDescription(rpc_RpcCode, int);
extern void rpc_deleteRpcDescription(rpc_RpcDescription *);
extern rpc_Boolean rpc_portIsAddress(const char *);

extern const char *rpc_getPortAttr(const char *, int *domain, int *type);

#define rpc_ObjectNone (void *)-1
#define rpc_SizeVariable -1

#define rpc_assert(X) \
  if (!(X)) \
    { \
       fprintf(stderr, "assertion failed `%s' in file `%s', line %d\n", #X, \
                __FILE__, __LINE__); \
       return 0; \
    }

#endif
