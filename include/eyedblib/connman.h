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


#ifndef _EYEDBLIB_CONNMAN_H
#define _EYEDBLIB_CONNMAN_H

#ifdef HAVE_FATTACH
#include <stropts.h>
#endif

#include <netinet/in.h>

struct rpc_Auth {
  int uid;
  int gid;
};

struct rpc_User {
  enum {
    ON,
    NOT,
    DEF,
    ALL
  } mode;
  char *user;
};

struct rpc_TcpIp {
  int user_cnt;
  rpc_User *users;
};

struct rpc_ConnInfo {

  rpc_Auth auth;

  enum {
    STREAM,
    UNIX,
    TCPIP
  } mode;

  struct in_addr peer_addr;
  bool is_localhost;

  rpc_TcpIp tcpip;
};

extern int
rpc_connman_init(const char *access_file);

struct in_addr;

extern rpc_ConnInfo *
rpc_check_addr(struct in_addr *addr);

extern rpc_ConnInfo *
rpc_make_tcpip_conninfo(int fd);


#ifdef HAVE_FATTACH
extern rpc_ConnInfo *
rpc_make_stream_conninfo(int fd, struct strrecvfd *);
#else
extern rpc_ConnInfo *
rpc_make_unix_conninfo(int fd);
#endif

extern void
rpc_print_tcpip(FILE *fd, rpc_TcpIp *ci);

#endif
