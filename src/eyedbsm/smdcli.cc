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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <eyedblib/rpc_lib.h>

#include <stdlib.h>
#include <string.h>
#include "eyedbsm_p.h"
#include <eyedbsm/smd.h>
#include "lib/compile_builtin.h"

smdcli_conn_t *
smdcli_open(const char *port)
{
  struct sockaddr_un sock_un_name;
  struct sockaddr *sock_addr;
  int sock_fd;

  sock_un_name.sun_family = AF_UNIX;
  strcpy(sock_un_name.sun_path, port);
  sock_addr = (struct sockaddr *)&sock_un_name;
  if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0))  < 0)
    {
      //fprintf(stderr, "smd client: cannot create socket\n");
      return 0;
    }

  if (connect(sock_fd, sock_addr, sizeof(sock_un_name)) < 0)
    {
      //fprintf(stderr, "smd client: cannot connect to smd daemon\n");
      //perror("connect");
      return 0;
    }

  smdcli_conn_t *conn = new smdcli_conn_t();
  conn->sock_fd = sock_fd;
  return conn;
}

void
smdcli_close(smdcli_conn_t *conn)
{
  close(conn->sock_fd);
  delete conn;
  conn = 0;
}

int
smdcli_init_getsems(smdcli_conn_t *conn, const char *dbfile, int sm[])
{
  int msg = SMD_INIT_GETSEMS;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }
  int len = strlen(dbfile)+1;
  if (rpc_socketWrite(conn->sock_fd, &len, sizeof(len)) != sizeof(len))
    {
      perror("write");
      return 1;
    }

  if (rpc_socketWrite(conn->sock_fd, (void *)dbfile, len) != len)
    {
      perror("write");
      return 1;
    }

  if (rpc_socketRead(conn->sock_fd, sm, sizeof(int)*ESM_NSEMS) !=
      sizeof(int)*ESM_NSEMS)
    {
      perror("read");
      return 1;
    }

  return 0;
}

int
smdcli_release(smdcli_conn_t *conn, const char *dbfile)
{
  int msg = SMD_RELEASE;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }
  int len = strlen(dbfile)+1;
  if (rpc_socketWrite(conn->sock_fd, &len, sizeof(len)) != sizeof(len))
    {
      perror("write");
      return 1;
    }

  if (rpc_socketWrite(conn->sock_fd, (void *)dbfile, len) != len)
    {
      perror("write");
      return 1;
    }

  return 0;
}

int
smdcli_stop(smdcli_conn_t *conn)
{
  int msg = SMD_STOP;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }

  return 0;
}

int
smdcli_status(smdcli_conn_t *conn)
{
  int msg = SMD_STATUS;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }

  return 0;
}

int
smdcli_declare(smdcli_conn_t *conn)
{
  int msg = SMD_DECL;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }

  return 0;
}

int
smdcli_undeclare(smdcli_conn_t *conn)
{
  int msg = SMD_UNDECL;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }

  return 0;
}

int
smdcli_init(smdcli_conn_t *conn, const char *dbfile)
{
  int msg = SMD_INIT;
  if (rpc_socketWrite(conn->sock_fd, &msg, sizeof(msg)) != sizeof(msg))
    {
      perror("write");
      return 1;
    }

  int len = strlen(dbfile)+1;
  if (rpc_socketWrite(conn->sock_fd, &len, sizeof(len)) != sizeof(len))
    {
      perror("write");
      return 1;
    }

  if (rpc_socketWrite(conn->sock_fd, (void *)dbfile, len) != len)
    {
      perror("write");
      return 1;
    }

  if (rpc_socketRead(conn->sock_fd, &msg, sizeof(msg)) !=  sizeof(msg))
    {
      perror("read");
      return 1;
    }

  return 0;
}

#define SMD_PORT_ENV "EYEDBSV_SMDPORT"
#define SMD_PORT "/smd"

static std::string smd_port;

static const char *smd_get_port_p()
{
  if (smd_port.length())
    return smd_port.c_str();

  const char *s = getenv(SMD_PORT_ENV);
  if (s)
    return s;

  static std::string path = eyedblib::CompileBuiltin::getPipedir();
  path += SMD_PORT;
    
  return path.c_str();
}

const char *smd_get_port()
{
  static struct sockaddr_un sock_un_name;
  static unsigned sun_path_len = sizeof(sock_un_name.sun_path);

  const char *port = smd_get_port_p();
  if (strlen(port) <= sun_path_len)
    return port;

  static std::string stpath = port;
  stpath[sun_path_len] = 0;

  return stpath.c_str();
}

void smd_set_port(const char *port)
{
  smd_port = std::string(port);
}
