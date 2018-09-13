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


#ifndef _EYEDBLIB_RPC_LIB_H
#define _EYEDBLIB_RPC_LIB_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>

#include <eyedblib/rpc.h>
#include <eyedblib/log.h>

typedef struct {
  eyedblib::uint32 magic;
  eyedblib::int32 serial;
  rpc_RpcCode code;
  int size, ndata;
  rpc_Status status;
} rpc_RpcHeader;

enum {
  rpc_SyncData  = 13,
  rpc_ASyncData = 18
};

typedef struct {
  int size;
  rpc_UserArgFunction func;
  rpc_Boolean is_pointer;
} rpc_UserType;

typedef enum {
  rpc_NewConnection = 0x76,
  rpc_AssociatedConnection,
  rpc_ReplyNewConnection
} rpc_MultiConnCommand;

typedef struct {
  eyedblib::int32 err;
  char err_msg[1024];
} rpc_StatusRec;

typedef struct {
  eyedblib::uint32 magic;
  rpc_MultiConnCommand cmd;
  int xid;
} rpc_MultiConnInfo;
  
#define rpc_new(X) (X *)calloc(1, sizeof(X))

#define rpc_copy(ARG, BUFF, X, SZ, SEND_RCV, FROM_TO) \
  do { \
  if ((ARG)->send_rcv & SEND_RCV) \
    { \
      if (FROM_TO == rpc_To) \
	memcpy(BUFF, X, SZ); \
      else \
	memcpy(X, BUFF, SZ); \
      BUFF += SZ; \
    } \
  } while(0)

#define eyedblib_mcp(D, S, N) \
do { \
  int __n__ = (N); \
  char *__d__ = (char *)(D), *__s__ = (char *)(S); \
  while(__n__--) \
    *__d__++ = *__s__++; \
} while(0)

#define rpc_copy_fast(ARG, BUFF, X, SZ, SEND_RCV, FROM_TO) \
do { \
  if ((ARG)->send_rcv & SEND_RCV) \
    { \
      if ((FROM_TO) == rpc_To) \
	eyedblib_mcp(BUFF, X, (SZ)); \
      else \
	eyedblib_mcp(X, BUFF, (SZ)); \
      BUFF += (SZ); \
    } \
  } while(0)

#define rpc_copy_fast_xdr(ARG, BUFF, X, SZ, SEND_RCV, FROM_TO, X2H, H2X) \
do { \
  if ((ARG)->send_rcv & SEND_RCV) \
    { \
      if ((FROM_TO) == rpc_To) \
	H2X(BUFF, X); \
      else \
	X2H(X, BUFF); \
      BUFF += (SZ); \
    } \
  } while(0)

#define rpc_buff_size(COMM_SZ, COMM_BUFF, BUFF) \
(int)((COMM_SZ - 8*sizeof(int)) - (int)((BUFF)-(COMM_BUFF)))

#define RPC_UTYPS 32

#define rpc_getUTyp(X, I) (&((X)->utyp[(I) - rpc_NBaseType]))

/* function prototypes */
extern int
rpc_socketWrite(int, void *, int);

extern int
rpc_socketRead(int, void *, int);

extern int
rpc_socketReadTimeout(int, void *, int, int);

extern int
rpc_hostNameToAddr(const char *, struct in_addr *);

#define RPC_NDATA 4

#define RPC_COMM_SIZE 4096

#define MM(X) ((X) + 0x11111111)

extern void (*rpc_quit_handler)(void *, int);
extern void *rpc_quit_data;

extern void rpc_setQuitHandler(void (*_quit_handler)(void *, int), void *_quit_data);

extern void rpc_getStats(unsigned int *read_cnt,
			 unsigned int *read_tm_cnt,
			 unsigned int *write_cnt,
			 unsigned int *byte_read_cnt,
			 unsigned int *byte_write_cnt);

extern void rpc_socket_nodelay(int s);
extern void h2x_rpc_multiconninfo(rpc_MultiConnInfo *xinfo, rpc_MultiConnInfo *hinfo);
extern void x2h_rpc_multiconninfo(rpc_MultiConnInfo *info);
extern void x2h_rpc_hd(rpc_RpcHeader *rhd);
extern void h2x_rpc_hd(rpc_RpcHeader *xrhd, const rpc_RpcHeader *hrhd);
extern void rpc_setConnFd(int fd);
extern void rpc_checkAFUnixPort(const char *portname);

/*@@@@ #ifdef LINUX */
#if defined(LINUX) || defined(LINUX64) || defined(LINUX_IA64) || defined(LINUX_PPC64) || defined(ORIGIN) || defined(ALPHA) || defined(AIX) || defined(DARWIN64)
#define  _sys_siglistp  _sys_siglist
#endif

/* 24/09/04: disconnected for test */
/*#define RPC_MIN_SIZE 128*/

extern void
print_addr(FILE *fd, struct in_addr *addr);
extern int
cmp_addr(const struct in_addr *a1, const struct in_addr *a2);
extern int
hostname2addr(const char *name, struct in_addr *addr);

extern pid_t rpc_getpid();

#endif
