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


#include <sys/types.h>
#include <eyedblib/rpc_be.h>
#include <eyedblib/rpc_lib.h>
#include <sys/select.h>

typedef char *rpc_ServerArg;

typedef struct {
  rpc_ServerArg *ua;
  pthread_t *tid;
  char **comm_buff;
  rpc_Boolean dead;
  int refcnt;
  int fd_cnt;
} rpc_ClientInfo;

struct rpc_Server {
  rpc_ServerMode mode;
  int conn_cnt;
  int comm_size;
  int nclients;
  void (*init)(int *, int, rpc_ConnInfo *);
  void (*release)(rpc_ConnInfo *);
  void (*begin)(int, void *);
  void (*end)(int, void *);
  void *user_data;
  rpc_ClientInfo *cinfos;
#ifdef RPC_FUN_CHAIN
  rpc_ServerFunction *first;
#else
  rpc_ServerFunction *funcs[256];
#endif
  rpc_ConnectionHandlerFunction connh;
  int last_type;
  int args_size;
  rpc_UserType utyp[RPC_UTYPS];
  fd_set fds_used;
  eyedblib::uint32 magic;
};

enum {
  rpc_OutOfBandSTART = 0x100,
  rpc_OutOfBandSTOP  = 0x200,
  rpc_OutOfBandOK    = 0x300
};

struct rpc_PortHandle {
  rpc_Server *server;
  int domain, type;
  char *portname;
  union {
    struct {
      int sockin_fd;
      struct sockaddr_in sock_in_name;
    } in;
    struct {
      int sockun_fd;
      struct sockaddr_un sock_un_name;
    } un;
  } u;
};

struct rpc_ServerFunction {
  rpc_RpcDescription *rd;
  rpc_UserServerFunction uf;
  rpc_ServerFunction *next;
};

extern rpc_ServerFunction *rpc_rpcGet(rpc_Server *, rpc_RpcCode);
