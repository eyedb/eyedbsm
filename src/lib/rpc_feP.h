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


#include <eyedblib/rpc_fe.h>
#include <eyedblib/rpc_lib.h>

struct rpc_Client {
  rpc_ArgType last_type;
  int args_size;
  rpc_UserType utyp[RPC_UTYPS];
};

struct rpc_ConnHandle {
  rpc_Client *client;
  int conn_cnt;
  int *fd;
  int domain, type;
  int comm_size;
  char **comm_buff;
  eyedblib::uint32 magic;
};

typedef char *rpc_ClientArg;

