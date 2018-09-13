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

#include "eyedbsmconfig.h"

#include <assert.h>
#include <sys/select.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

#include "rpc_feP.h"
#include <eyedblib/rpc_lib.h>
#include <eyedblib/log.h>
#include <eyedblib/xdr.h>

#define USE_RPC_MIN_SIZE

extern int RPC_MIN_SIZE;

#ifdef AIX
#define _NO_BITFIELDS
#endif

#include <netinet/tcp.h>

void (*rpc_release_all)(void);
extern int rpc_from_core;

static void
signal_handler(int sig) 
{
  int s;
  for (s = 0; s < NSIG; s++)
    signal(s, SIG_DFL);

  if (sig == SIGBUS || sig == SIGSEGV)
    {
      rpc_from_core = 1;

      if (getenv("EYEDBDBG")) for (;;) sleep(1000);

      if (rpc_quit_handler)
	rpc_quit_handler(rpc_quit_data, 1);

      if (rpc_release_all)
	rpc_release_all();

      raise(sig);
      return;
    }

  IDB_LOG(IDB_LOG_CONN, ("got %s [signal=%d]\n", strsignal(sig), sig));

  if (rpc_quit_handler)
    rpc_quit_handler(rpc_quit_data, 0);

  if (rpc_release_all)
    rpc_release_all();

  raise(sig);
  exit(0x80|sig);
}

static void
rpc_feInit()
{
  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGBUS, signal_handler);
  signal(SIGABRT, signal_handler);
  signal(SIGPIPE, signal_handler);
}

rpc_Client *rpc_clientCreate(void)
{
  rpc_Client *client = rpc_new(rpc_Client);

  client->last_type = rpc_NBaseType;

  // EV : disconnected 22/10/06
#if 0
  rpc_feInit();
#endif

  return client;
}

/*#define TRACE*/

rpc_ArgType rpc_makeClientUserType(rpc_Client *client, int size,
				   rpc_UserArgFunction func,
				   rpc_Boolean is_pointer)
{
  rpc_UserType *utyp = rpc_getUTyp(client, client->last_type);

  utyp->size = size;
  utyp->func = func;
  utyp->is_pointer = is_pointer;

  return client->last_type++;
}

rpc_ClientFunction *
rpc_makeUserClientFunction(rpc_Client *client, rpc_RpcDescription *rd)
{
  rpc_ClientFunction *func = rpc_new(rpc_ClientFunction);

  rd->args[rd->nargs-1].type     = rd->arg_ret;
  rd->args[rd->nargs-1].send_rcv = rpc_Rcv;

  while (rd->args[rd->nargs-1].type == rpc_VoidType)
    rd->nargs--;

  func->rd = rd;

  return func;
}

pid_t rpc_pid;

pid_t rpc_getpid()
{
  if (!rpc_pid)
    return getpid();
  return rpc_pid;
}

rpc_Status
rpc_connOpen(rpc_Client *client, const char *hostname, const char *portname,
	     rpc_ConnHandle **pconn, unsigned long magic,
	     int conn_cnt, int comm_size, std::string &errmsg)
{
  int domain, sock_fd, length;
  struct sockaddr_in sock_in_name;
  struct sockaddr_un sock_un_name;
  struct sockaddr *sock_addr;
  rpc_ConnHandle *conn;
  int i;
  int xid = 0;

  errmsg = "";

  const char *t_portname;
  int type;

  t_portname = rpc_getPortAttr(portname, &domain, &type);
  if (!t_portname) {
    errmsg = std::string("invalid port: " ) + hostname;
    return rpc_ConnectionFailure;
  }

  portname = t_portname;

  *pconn = (rpc_ConnHandle *)0;

  if (domain == AF_INET) {
    char hname[64];
    /*domain = AF_INET;*/
    sock_in_name.sin_family = domain;
    sock_in_name.sin_port = htons(atoi(portname));

    if (hostname) // && strcmp(hostname, "localhost"))
      strcpy(hname, hostname);
    else
      gethostname(hname, sizeof(hname)-1);

    if (!rpc_hostNameToAddr(hname, &sock_in_name.sin_addr)) {
      errmsg = std::string("unknown host: " ) + hostname;
      return rpc_ConnectionFailure;
    }
    sock_addr = (struct sockaddr *)&sock_in_name;
    length = sizeof(sock_in_name);
  }
  else {
    /*domain = AF_UNIX;*/
    if (hostname) {
      if (!rpc_hostNameToAddr(hostname, &sock_in_name.sin_addr)) {
	errmsg = std::string("unknown host: " ) + hostname;
	return rpc_ConnectionFailure;
      }

      if (strcmp(hostname, "localhost")) {
	errmsg = std::string("localhost expected (got ") +
	  hostname + ") for named pipe " + portname;
	return rpc_ConnectionFailure;
      }	
    }

    sock_un_name.sun_family = domain;
    strcpy(sock_un_name.sun_path, portname);
    sock_addr = (struct sockaddr *)&sock_un_name;
    length = sizeof(sock_un_name);
  }

  conn = rpc_new(rpc_ConnHandle);
  conn->fd = (int *)malloc(conn_cnt * sizeof(int));

  for (i = 0; i < conn_cnt; i++) {
    rpc_MultiConnInfo info;
    rpc_MultiConnInfo xinfo;
#ifdef HAVE_FATTACH
    if (domain == AF_UNIX) {
      sock_fd = open(portname, O_RDWR);
      if (sock_fd  < 0) {
	errmsg = std::string("server unreachable: ") +
	  "host " + hostname + ", port " + portname;
	goto failure;
      }
    }
    else {
#endif
      if ((sock_fd = socket(domain, type, 0))  < 0) {
	errmsg = std::string("server unreachable: ") +
	  "host " + hostname + ", port " + portname;
	goto failure;
      }
#if 0
      if (domain == AF_INET)
	rpc_socket_nodelay(sock_fd);
#endif

#ifdef TRACE
      utlog("opening sock_fd=%d\n", sock_fd);
#endif

      if (connect(sock_fd, sock_addr, length) < 0) {
	errmsg = std::string("server unreachable: ") +
	  "host " + hostname + ", port " + portname;
	goto failure;
      }

#ifdef HAVE_FATTACH
    }
#endif
    conn->fd[i] = sock_fd;

    if (conn_cnt == 1)
      break;

    info.magic = MM(magic);

    if (!i) {
      info.cmd = rpc_NewConnection;
      info.xid = 0;
    }
    else {
      info.cmd = rpc_AssociatedConnection;
      info.xid = xid;
    }
	  
    h2x_rpc_multiconninfo(&xinfo, &info);
    if (rpc_socketWrite(sock_fd, &xinfo, sizeof(xinfo)) != sizeof(xinfo)) {
      errmsg = std::string("cannot write on socket: ") +
	"host " + hostname + ", port " + portname;
      goto failure;
    }

    if (rpc_socketRead(sock_fd, &info, sizeof(info)) != sizeof(info)) {
      errmsg = std::string("client connection not granted by server: ") +
	"host " + hostname + ", port " + portname;
      goto failure;
    }

    x2h_rpc_multiconninfo(&info);

    if (info.magic != MM(magic) || info.cmd != rpc_ReplyNewConnection) {
      errmsg = std::string("protocol error: ") +
	"host " + hostname + ", port " + portname;
      goto failure;
    }


    if (!i)
      xid = info.xid;
  }
    
  conn->client = client;
  conn->magic = magic;
  conn->conn_cnt = conn_cnt;

  if (!comm_size)
    comm_size = RPC_COMM_SIZE;

  conn->comm_size = comm_size;
  conn->comm_buff = (char **)malloc(conn_cnt * sizeof(char *));

  for (i = 0; i < conn_cnt; i++) {
    conn->comm_buff[i] = (char *)calloc(comm_size, 1);
  }

  *pconn = conn;

  return rpc_Success;

 failure:
  free(conn->fd);
  free(conn);
  return rpc_ConnectionFailure;
}

rpc_Status
rpc_connClose(rpc_ConnHandle *conn)
{
  int i;
#ifdef TRACE
  utlog("rpc_connClose(0x%x, 0x%x)\n", conn, conn->fd);
#endif

  if (conn && conn->fd)
    {
      for (i = 0; i < conn->conn_cnt; i++)
	{
#ifdef TRACE
	  utlog("closing %d\n", conn->fd[i]);
#endif
	  if (close(conn->fd[i]))
	    perror("rpc_ConnClose");
	}

      free(conn->fd);
      conn->fd = 0;
    }

  for (i = 0; i < conn->conn_cnt; i++)
    free(conn->comm_buff[i]);

  free(conn->comm_buff);

  conn->comm_buff = NULL;
	 
  free(conn);

  return rpc_Success;
}

rpc_Status
rpc_setClientArgSize(rpc_Client *client, int args_size)
{
  client->args_size = args_size;
  return rpc_Success;
}

static int
rpc_clientArgsMake(rpc_ConnHandle *conn, int which, rpc_RpcDescription **prd,
		   rpc_SendRcv send_rcv, rpc_FromTo fromto,
		   rpc_ClientArg ua)
{
  int i, fd = conn->fd[which], commsz;
  char *buff, *commb;
  register rpc_Arg *arg;
  rpc_ClientArg pua;
  rpc_RpcHeader rhd;
  rpc_RpcHeader xrhd;
  int ndata = 0;
  rpc_ClientData *p_data[RPC_NDATA];
  rpc_RpcDescription *rd;
  static long serial = 1000;
  char *comm_buff = conn->comm_buff[which];
  int args_size = conn->client->args_size;
  int buff_size = 0;
  rpc_UserType *utyp;
  rpc_StatusRec *rstatus = 0;
  commb = comm_buff;
  commsz = conn->comm_size;

  /*#ifdef RPC_MIN_SIZE*/
#if 1
  if (fromto == rpc_From)
    buff = commb;
  else
    buff = commb + sizeof(rhd);
#else
  buff = commb + sizeof(rhd);
#endif

#ifdef TRACE
  utlog("clientArgsMake code #%d, %s [which %d]\n",
	  (*prd)->code, (fromto == rpc_From ? "FROM" : "TO"), which);
#endif

  if (fromto == rpc_From)
    {
      int sz;
#ifdef USE_RPC_MIN_SIZE
      if ((sz = rpc_socketRead(fd, buff, RPC_MIN_SIZE)) != RPC_MIN_SIZE)
	{
	  IDB_LOG_FX(("Client Protocol Error #1: size=%d, expected=%d\n",
		      sz, RPC_MIN_SIZE));
	  return 0;
	}
      memcpy(&rhd, buff, sizeof(rhd));
      x2h_rpc_hd(&rhd);
      buff += sizeof(rhd);
#else
      if ((sz = rpc_socketRead(fd, buff, sizeof(rhd))) != sizeof(rhd))
	{
	  IDB_LOG_FX(("Client Protocol Error #1: size=%d, expected=%d\n",
		     sz, sizeof(rhd)));
	  return 0;
	}
      memcpy(&rhd, buff, sizeof(rhd));
      x2h_rpc_hd(&rhd);
      buff += sizeof(rhd);
#endif

#ifdef TRACE
      utlog(".... code #%d FROM\n", rhd.code);
#endif

      if (rhd.magic != conn->magic)
	{
	  IDB_LOG_FX(("Client Protocol Error #2: invalid magic=%p, "
		     "expected=%p\n", rhd.magic, conn->magic));
	  return 0;
	}

      if (rhd.code != (*prd)->code)
	{
	  IDB_LOG_FX(("Client Protocol Error #3: invalid code=%p, expected=%p\n",
		     rhd.code, (*prd)->code));
	  return 0;
	}

#ifdef USE_RPC_MIN_SIZE
      if (rhd.size-RPC_MIN_SIZE > 0) {
	if (rpc_socketRead(fd, buff+RPC_MIN_SIZE-sizeof(rhd),
			   rhd.size-RPC_MIN_SIZE) != rhd.size-RPC_MIN_SIZE)
	  {
	    IDB_LOG_FX(("Client Protocol Error #4: read failed for %d bytes\n",
			rhd.size-sizeof(rhd)));
	    return 0;
	  }
      }
#else
      if (rhd.size-sizeof(rhd))
	if (rpc_socketRead(fd, buff, rhd.size-sizeof(rhd)) !=
	    rhd.size-sizeof(rhd))
	{
	  IDB_LOG_FX(("Client Protocol Error #4: read failed for %d bytes\n",
		      rhd.size-sizeof(rhd)));
	  return 0;
	}
#endif

      rd = *prd;

      if (rhd.size > commsz)
	{
	  IDB_LOG_FX(("Client Protocol Error #5: size exceeded=%d, max=%d\n",
		     rhd.size, commsz));
	  return 0;
	}
    }
  else
    rd = *prd;

  for (i = 0, arg = rd->args, pua = ua; i < rd->nargs; i++, arg++, pua += args_size)
    switch(arg->type)
      {
      case rpc_Int16Type:
	rpc_copy_fast_xdr(arg, buff, pua, sizeof(eyedblib::int16), send_rcv, fromto, x2h_16_cpy, h2x_16_cpy);
	break;
	
      case rpc_Int32Type:
	rpc_copy_fast_xdr(arg, buff, pua, sizeof(eyedblib::int32), send_rcv, fromto, x2h_32_cpy, h2x_32_cpy);
	break;
	
      case rpc_Int64Type:
	rpc_copy_fast_xdr(arg, buff, pua, sizeof(eyedblib::int64), send_rcv, fromto, x2h_64_cpy, h2x_64_cpy);
	break;
	
      case rpc_StatusType:
	if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_From)
	  {
	    int err;
	    x2h_32_cpy(&err, buff);
	    if (err)
	      rstatus = (rpc_StatusRec *)pua;
	  }
	rpc_copy_fast_xdr(arg, buff, pua, sizeof(eyedblib::int32), send_rcv, fromto, x2h_32_cpy, h2x_32_cpy);
	break;
	
      case rpc_StringType:
	if ((arg->send_rcv & rpc_Send) && fromto == rpc_To)
	  {
	    int len = strlen(*(char **)pua)+1;
	    h2x_32_cpy(buff, &len);
	    buff += sizeof(len);
	    if (len)
	      {
		memcpy(buff, *(char **)pua, len);
		buff += len;
	      }
	  }
	else if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_From)
	  {
	    int len;
	    x2h_32_cpy(&len, buff);
	    buff += sizeof(len);
	    if (len)
	      *(char **)pua = buff; /* oups? */
	    else
	      *(char **)pua = (char*)"" /*@@@@cast to avoid warning*/;
	    buff += len;
	  }
	break;
	
      case rpc_DataType:
	if ((arg->send_rcv & rpc_Send) && fromto == rpc_To)
	  {
	    int status;
	    rpc_ClientData *a_data = (rpc_ClientData *)pua;
	    /* write pointer value: in case of rpc_ObjectZero or
	       rpc_ObjectNone */
	    h2x_32_cpy(buff, &a_data->data);
	    buff += 8;

	    h2x_32_cpy(buff, &a_data->size);
	    buff += sizeof(a_data->size);

	    if (!a_data->data || a_data->data == rpc_ObjectNone)
	      a_data = 0;
	    else if (a_data->size < rpc_buff_size(commsz, commb, buff))
	      {
		status = rpc_SyncData;
		h2x_32_cpy(buff, &status);
		buff += sizeof(status);
		memcpy(buff, a_data->data, a_data->size);
		buff += a_data->size;
	      }
	    else
	      {
		status = rpc_ASyncData;
		h2x_32_cpy(buff, &status);
		buff += sizeof(status);
		p_data[ndata++] = a_data;
	      }
	  }
	else if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_From)
	  {
	    int status, offset;
	    rpc_ClientData *a_data = (rpc_ClientData *)pua;
	    /* must read real size */
	    x2h_32_cpy(&a_data->size, buff);
	    buff += sizeof(a_data->size);

	    x2h_32_cpy(&status, buff);
	    buff += sizeof(status);

	    if (!a_data->data)
	      a_data->data = (void *)malloc(a_data->size);

	    if (status == rpc_SyncData)
	      {
		x2h_32_cpy(&offset, buff);
		memcpy(a_data->data, buff+offset, a_data->size);
		buff += sizeof(offset);
		buff_size += a_data->size;
	      }
	    else
	      {
		memset(buff, 0, sizeof(offset));
		buff += sizeof(offset);
		p_data[ndata++] = a_data;
	      }
	  }
	break;
	
      case rpc_VoidType:
	break;

      default:
	rpc_assert(arg->type >= rpc_NBaseType && arg->type < conn->client->last_type);
	utyp = rpc_getUTyp(conn->client, arg->type);

	if (utyp->func)
	  utyp->func(arg, &buff, pua, send_rcv, fromto);
	else if (utyp->is_pointer)
	  rpc_copy(arg, buff, *(char **)pua, utyp->size, send_rcv, fromto);
	else
	  rpc_copy(arg, buff, pua, utyp->size, send_rcv, fromto);
      }
  
  if (fromto == rpc_To)
    {
      /* writing header */
      rhd.code = rd->code;

      rhd.magic = conn->magic;
      rhd.serial = ++serial;
      rhd.ndata = ndata;
      rhd.status = 0;

      rhd.size = (int)(buff-commb) + buff_size;

      if (rhd.size > commsz)
	{
	  IDB_LOG_FX(("Client Protocol Error #6: size exceeded=%d, max=%d, "
		     "buff_size=%d\n",
		     rhd.size, commsz, buff_size));
	  return 0;
	}

      /*
#ifdef USE_RPC_MIN_SIZE
      if (rhd.size < RPC_MIN_SIZE)
	rhd.size = RPC_MIN_SIZE;
#endif
      */

      h2x_rpc_hd(&xrhd, &rhd);
      memcpy(commb, &xrhd, sizeof(xrhd));

#ifdef USE_RPC_MIN_SIZE
      if (rhd.size < RPC_MIN_SIZE)
	rhd.size = RPC_MIN_SIZE;
#endif

      if (rpc_socketWrite(fd, commb, rhd.size) != rhd.size)
	{
	  IDB_LOG_FX(("Client Protocol Error #7: write failed for %d bytes\n",
		     rhd.size));
	  return 0;
	}
      
      if (ndata)
	{
	  int d[RPC_NDATA], i;
	  for (i = 0; i < ndata; i++)
	    d[i] = h2x_32(p_data[i]->size);

	  if (rpc_socketWrite(fd, d, ndata*sizeof(int)) != ndata*sizeof(int))
	    {
	      IDB_LOG_FX(("Client Protocol Error #8: write failed for %d "
			 "bytes\n", ndata*sizeof(int)));
	      return 0;
	    }
	  for (i = 0; i < ndata; i++) {
	    if (rpc_socketWrite(fd, p_data[i]->data, p_data[i]->size) !=
		p_data[i]->size)
	      {
		IDB_LOG_FX(("Client Protocol Error #9: write failed for "
			   "%d bytes\n",
			   p_data[i]->size));
		return 0;
	      }
	  }
	}
    }

  if (fromto == rpc_From && (send_rcv & rpc_Rcv) && ndata)
    {
      int d[RPC_NDATA], i;

      if (rpc_socketRead(fd, d, ndata*sizeof(int)) != ndata*sizeof(int))
	{
	  IDB_LOG_FX(("Client Protocol Error #10: write failed for "
		     "%d bytes\n",
		     ndata*sizeof(int)));
	  return 0;
	}

      for (i = 0; i < ndata; i++) {
	d[i] = x2h_32(d[i]);
	if (d[i] > 0)
	  {
	    if (rpc_socketRead(fd, p_data[i]->data, d[i]) != d[i])
	      {
		IDB_LOG_FX(("Client Protocol Error #11: write failed for "
			   "%d bytes\n", d[i]));
		return 0;
	      }
	  }
      }
    }

  if (rstatus)
    {
      int len;
      int tmp;
      if (rpc_socketRead(fd, &tmp, sizeof(tmp)) != sizeof(tmp))
	return 0;
      rstatus->err = x2h_32(tmp);
      if (rpc_socketRead(fd, &tmp, sizeof(tmp)) != sizeof(tmp))
	return 0;
      len = x2h_32(tmp);
      if (rpc_socketRead(fd, rstatus->err_msg, len+1) != len+1)
	return 0;
    }

#ifdef TRACE
  utlog("clientArgsMake code #%d, %s [which %d] done!\n",
	(*prd)->code, (fromto == rpc_From ? "FROM" : "TO"), which);
#endif
  return 1;
}

rpc_Status
rpc_rpcMake(rpc_ConnHandle *conn, int which, rpc_ClientFunction *func, void *ua)
{
  if (conn && conn->fd)
    {
      rpc_RpcDescription *rd;

      if (which < 0 || which >= conn->conn_cnt)
	return rpc_Error;

      rd = func->rd;

      rpc_assert(rd);

      if (!rpc_clientArgsMake(conn, which, &rd, rpc_Send, rpc_To,
			      (rpc_ClientArg)ua))
	return rpc_ServerFailure;

      if (!rpc_clientArgsMake(conn, which, &rd, rpc_Rcv, rpc_From,
			      (rpc_ClientArg)ua))
	return rpc_ServerFailure;

      return rpc_Success;
    }

  return rpc_Error; /* for now */
}
