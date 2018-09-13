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

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
// // @@@ ???
// #ifdef AIX
// #define _NO_BITFIELDS
// #endif
#include <netinet/in.h>
#include <netinet/tcp.h>

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#include <unistd.h>

#include <eyedblib/rpc_lib.h>
#include <eyedblib/xdr.h>
#include <lib/rpc_lib_p.h>

int RPC_MIN_SIZE = 128;
//int RPC_MIN_SIZE = 1024;

void
print_addr(FILE *fd, struct in_addr *addr)
{
  if (!RPC_BYTE1(addr))
    fprintf(fd, "+");
  else
    fprintf(fd, "%d.%d.%d.%d", RPC_BYTE1(addr), RPC_BYTE2(addr), RPC_BYTE3(addr), RPC_BYTE4(addr));
}

int
cmp_addr(const struct in_addr *a1, const struct in_addr *a2)
{
  if (RPC_BYTE1(a1) && RPC_BYTE1(a1) != RPC_BYTE1(a2))
    return 0;

  if (RPC_BYTE2(a1) && RPC_BYTE2(a1) != RPC_BYTE2(a2))
    return 0;
  
  if (RPC_BYTE3(a1) && RPC_BYTE3(a1) != RPC_BYTE3(a2))
    return 0;
  
  if (RPC_BYTE4(a1) && RPC_BYTE4(a1) != RPC_BYTE4(a2))
    return 0;

  return 1;
}

int
rpc_hostNameToAddr(const char *name, struct in_addr *address)
{
  struct hostent *hp;

  if (!(hp = gethostbyname(name)))
    return 0;

  memcpy((char *)address, (char *)hp->h_addr, hp->h_length);
  return 1;
}

int
hostname2addr(const char *name, struct in_addr *addr)
{
  return !rpc_hostNameToAddr(name, addr);
  /*
  struct hostent *hp;

  memset(addr, 0, sizeof(*addr));

  if (!(hp = gethostbyname(name)))
    return 1;

  memcpy((char *)addr, (char *)hp->h_addr, hp->h_length);

  return 0;
  */
}

typedef int (*perform_func)(int, void *, size_t, int ud);

static int
read_timeval(int fd, void *buf, size_t n, struct timeval *tv)
{
  fd_set fds;
  /*  struct timeval tm;*/

  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  if (select(fd+1, &fds, 0, 0, tv) <= 0)
    return -1;

  return read(fd, buf, n); //@@@@ the type of return should be size_t
}

static int
read_tm(int fd, void *buf, size_t n, int ud)
{
  struct timeval tv;

  if (!ud)
    return read(fd, buf, n);

  tv.tv_sec = ud;
  tv.tv_usec = 0;
  return read_timeval(fd, buf, n, &tv);
}

static int
socketRealize(int fd, void *data, int sz, perform_func perform, int ud)
{ 
  char *p = (char *)data;
  int n = 0;
  errno = 0;

  if (!sz)
    return 0;

  for (;;)
    {
      int rn;

      rn = (*perform)(fd, p, sz - n, ud);

      if (rn < 0 && errno == EINTR)
	continue;

      if (rn <= 0)
	return rn;

      else if (rn == sz - n)
	return sz;

      n += rn;
      p += rn;
    }
}

static unsigned int total_bytes_read, total_bytes_write;
static unsigned int total_read, total_read_tm, total_write;

/* #define SOCKET_PROFILE 1000 */
#ifdef SOCKET_PROFILE
static int socket_ms = 0;
#endif

int
rpc_socketWrite(int fd, void *data, int sz)
{
  total_bytes_write += sz;
#ifdef SOCKET_PROFILE
  struct timeval tv;
  if (!socket_ms) {
    gettimeofday(&tv, 0);
    socket_ms = (unsigned long long)tv.tv_sec * 1000ULL +
      (unsigned long long)tv.tv_usec / 1000ULL;
  }
#endif
  total_write++;
#ifdef SOCKET_PROFILE
  if (!(total_write % SOCKET_PROFILE)) {
    gettimeofday(&tv, 0);
    int ms = (unsigned long long)tv.tv_sec * 1000ULL +
      (unsigned long long)tv.tv_usec / 1000ULL;
    fprintf(stdout, "total_write: %d [%d ms]\n", total_write,
	    ms - socket_ms);
  }
#endif
  return socketRealize(fd, data, sz, (perform_func)write, 0);
}

int
rpc_socketRead(int fd, void *data, int sz)
{
  total_bytes_read += sz;
#ifdef SOCKET_PROFILE
  struct timeval tv;
  if (!socket_ms) {
    gettimeofday(&tv, 0);
    socket_ms = (unsigned long long)tv.tv_sec * 1000ULL +
      (unsigned long long)tv.tv_usec / 1000ULL;
  }
#endif
  total_read++;
#ifdef SOCKET_PROFILE
    gettimeofday(&tv, 0);
    int ms = (unsigned long long)tv.tv_sec * 1000ULL +
      (unsigned long long)tv.tv_usec / 1000ULL;
  if (!(total_read % SOCKET_PROFILE))
    fprintf(stdout, "total_read: %d [%d ms]\n", total_read, ms-socket_ms);
#endif
  return socketRealize(fd, data, sz, (perform_func)read, 0);
}

int
rpc_socketReadTimeout(int fd, void *data, int sz, int ud)
{
  total_bytes_read += sz;
  total_read_tm++;
  return socketRealize(fd, data, sz, (perform_func)read_tm, ud);
}

rpc_RpcDescription *
rpc_newRpcDescription(rpc_RpcCode code, int nargs)
{
  rpc_RpcDescription *rd = rpc_new(rpc_RpcDescription);

  rd->code     = code;
  rd->nargs    = nargs+1;
  rd->args     = (rpc_Arg *)calloc(sizeof(rpc_Arg), rd->nargs);

  return rd;
}

void
rpc_deleteRpcDescription(rpc_RpcDescription *rd)
{
  if (rd->args)
    free(rd->args);
  free(rd);
}

#define isnumber(c) ((c) >= '0' && (c) <= '9')

rpc_Boolean
rpc_portIsAddress(const char *portname)
{
  register const char *s = portname;
  char c;

  if (!s || !*s)
    return rpc_False;

  while (c = *s++)
    if (!isnumber(c))
      return rpc_False;

  return rpc_True;
}

const char *rpc_getPortAttr(const char *port, int *domain, int *type)
{
  const char *x = strchr(port, ':');

  if (!x)
    {
      *domain = rpc_portIsAddress(port) ? AF_INET : AF_UNIX;
      *type = SOCK_STREAM;
      /*
      printf("rpc_getPortAttr: '%s' (domain = %d, type = %d)\n",
	     port, *domain, *type);
	     */
      return port;
    }

  if (!strncasecmp(port, "udp:", 4))
    *type = SOCK_DGRAM;
  else if (!strncasecmp(port, "tcp:", 4))
    *type = SOCK_STREAM;
  else
    return NULL;

  port = &x[1];
  *domain = rpc_portIsAddress(port) ? AF_INET : AF_UNIX;
  /*
  printf("rpc_getPortAttr: '%s' (domain = %d, type = %d)\n",
	 port, *domain, *type);
	 */
  return port;
}

#include <sys/stat.h>

static int conn_fd;

void rpc_setConnFd(int fd)
{
  conn_fd = fd;
}

int
rpc_checkConn()
{
  struct stat stat;
  return fstat(conn_fd, &stat);
}

void (*rpc_quit_handler)(void *, int);
void *rpc_quit_data;

void
rpc_setQuitHandler(void (*_rpc_quit_handler)(void *, int),
		   void *_rpc_quit_data)
{
  rpc_quit_handler = _rpc_quit_handler;
  rpc_quit_data    = _rpc_quit_data;
}

void
rpc_getStats(unsigned int *read_cnt,
	     unsigned int *read_tm_cnt,
	     unsigned int *write_cnt,
	     unsigned int *byte_read_cnt,
	     unsigned int *byte_write_cnt)
{
  *read_cnt = total_read;
  *read_tm_cnt = total_read_tm;
  *write_cnt = total_write;

  *byte_read_cnt = total_bytes_read;
  *byte_write_cnt = total_bytes_write;
}

eyedblib::int16
hton16(eyedblib::int16 x)
{
  return htons(x);
}

eyedblib::int32
hton32(eyedblib::int32 x)
{
  return htonl(x);
}

eyedblib::int64
hton64(eyedblib::int64 x)
{
  eyedblib::int32 h = x >> 32;
  eyedblib::int32 l = x & 0xffffffff;
  return ((unsigned long long)htonl(l)) << 32 | htonl(h);
}

void x2h_rpc_hd(rpc_RpcHeader *rhd)
{
  rhd->magic = x2h_u32(rhd->magic);
  rhd->serial = x2h_32(rhd->serial);
  rhd->code = x2h_32(rhd->code);
  rhd->size = x2h_32(rhd->size);
  rhd->ndata = x2h_32(rhd->ndata);
  rhd->status = x2h_u32(rhd->status);
}

void h2x_rpc_hd(rpc_RpcHeader *xrhd, const rpc_RpcHeader *hrhd)
{
  xrhd->magic = h2x_u32(hrhd->magic);
  xrhd->serial = h2x_32(hrhd->serial);
  xrhd->code = h2x_32(hrhd->code);
  xrhd->size = h2x_32(hrhd->size);
  xrhd->ndata = h2x_32(hrhd->ndata);
  xrhd->status = h2x_u32(hrhd->status);
}

void x2h_rpc_multiconninfo(rpc_MultiConnInfo *info)
{
  info->magic = x2h_u32(info->magic);
  info->cmd = (rpc_MultiConnCommand)x2h_32(info->cmd);
  info->xid = x2h_32(info->xid);
}

void h2x_rpc_multiconninfo(rpc_MultiConnInfo *xinfo, rpc_MultiConnInfo *hinfo)
{
  xinfo->magic = h2x_u32(hinfo->magic);
  xinfo->cmd = (rpc_MultiConnCommand)h2x_32(hinfo->cmd);
  xinfo->xid = h2x_32(hinfo->xid);
}

/*
void
terminate__Fv()
{
  fprintf(stderr, "terminate__Fv\n");
  exit(1);
}
*/

void rpc_socket_nodelay(int s)
{
  int flag = 1;
  socklen_t size = sizeof(int);
  int sz = 0;

  if (getenv("NO_TCP_NODELAY"))
    return;

  if (getsockopt(s,
		 IPPROTO_TCP,     /* set option at TCP level */
		 TCP_NODELAY,     /* name of option */
		 (char *) &flag,  /* the cast is historical 
				     cruft */
		 &size) < 0)
    perror("getsockopt nodelay");
  
  //#define TCP_TRACE

#ifdef TCP_TRACE
  fprintf(stderr, "NODELAY: %d [flag=%d, size=%d]\n", s, flag, size);
#endif

  flag = 1;
  if (setsockopt(s,
		 IPPROTO_TCP,     /* set option at TCP level */
		 TCP_NODELAY,     /* name of option */
		 (char *) &flag,  /* the cast is historical 
				     cruft */
		 sizeof(int)) < 0)
    perror("setsockopt nodelay");

  if (getsockopt(s,
		 IPPROTO_TCP,     /* set option at TCP level */
		 TCP_NODELAY,     /* name of option */
		 (char *) &flag,  /* the cast is historical 
				     cruft */
		 &size) < 0)
    perror("getsockopt nodelay");
  
#ifdef TCP_TRACE
  fprintf(stderr, "after NODELAY: %d [flag=%d]\n", s, flag);
#endif

  if (!getenv("TCP_BUFSZ"))
    return;

  if (getsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_SNDBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 &size) < 0)
    perror("getsockopt sndbuf");
  
#ifdef TCP_TRACE
  fprintf(stderr, "snd buf: %d\n", sz);
#endif

  if (getsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_RCVBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 &size) < 0)
    perror("getsockopt rcvbuf");
  
#ifdef TCP_TRACE
  fprintf(stderr, "rcv buf: %d\n", sz);
#endif

  sz = 2048;
  //sz = 8192;
  //sz = 16384;
  //sz = 32766;
  if (setsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_SNDBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 sizeof(int)) < 0)
    perror("setsockopt sndbuf");

  sz = 2048;
  if (setsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_RCVBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 sizeof(int)) < 0)
    perror("setsockopt sndbuf");

  if (getsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_SNDBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 &size) < 0)
    perror("getsockopt sndbuf");
  
#ifdef TCP_TRACE
  fprintf(stderr, "snd buf 2: %d\n", sz);
#endif

  if (getsockopt(s,
		 SOL_SOCKET,     /* set option at TCP level */
		 SO_RCVBUF,     /* name of option */
		 (char *)&sz,  /* the cast is historical 
				  cruft */
		 &size) < 0)
    perror("getsockopt rcvbuf");
  
#ifdef TCP_TRACE
  fprintf(stderr, "rcv buf 2: %d\n", sz);
#endif


  fflush(stderr);
}

void rpc_checkAFUnixPort(const char *portname)
{
  int r = access(portname, O_RDONLY);
  if (r < 0)
    return;

  int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock_fd < 0)
    return;

  struct sockaddr_un sock_un_name;
  struct sockaddr *sock_addr;

  sock_un_name.sun_family = AF_UNIX;
  strcpy(sock_un_name.sun_path, portname);
  sock_addr = (struct sockaddr *)&sock_un_name;

  r = connect(sock_fd, sock_addr, sizeof(sock_un_name));
  if (r < 0) {
    //fprintf(stderr, "eyedb notice: unlinking unix socket %s\n", portname);
    unlink(portname);
  }
  close(sock_fd);
}
