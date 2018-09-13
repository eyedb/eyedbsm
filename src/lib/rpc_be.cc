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

#include <string.h>
#include <pthread.h>

#include <eyedblib/thread.h>

#define USE_RPC_MIN_SIZE

extern int RPC_MIN_SIZE;

/* MIND: this constant is used in idbrpclib.h: should be factorized */
#define START_CODE 0x100

/* disconnected the 21/08/01 */
/*#define RPC_TIMEOUT 7200*/

extern pid_t rpc_pid;

#ifdef HAVE_STROPTS
#include <stropts.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <sys/wait.h>

#include <time.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <eyedblib/log.h>
#include <eyedblib/xdr.h>

#include "rpc_beP.h"
#include <eyedblib/rpc_lib.h>

static  rpc_ClientInfo *clientInfo[256];

/* static functions */
static int rpc_inputHandle(rpc_Server *, int, int);
static void rpc_garbClientInfo(rpc_Server *server, int, int);
static void rpc_garbRealize(rpc_Server *server, rpc_ClientInfo *ci,
			    int force);
static rpc_Boolean abortProgram;
static rpc_Server *rpc_mainServer;
static const char* progName = "rpc";
static int rpc_timeout;

rpc_ClientId rpc_client_id;

#define rpc_isSocketValid(S) ((S) >= 0)

#define TRACE
/*#define TRACE2*/

void rpc_setTimeOut(int _timeout)
{
#ifdef RPC_TIMEOUT
  rpc_timeout = (_timeout ? _timeout : RPC_TIMEOUT);
#else
  rpc_timeout = _timeout;
#endif
}

void
PERROR(const char *msg)
{
  const char *s = strerror(errno);
  utlog("%s : %s\n", msg, (s ? s : "<unknown>"));
  fprintf(stderr, "%s : %s\n", msg, (s ? s : "<unknown>"));
}

//static pthread_mutex_t msg_mp, gen_mp;
eyedblib::Mutex msg_mp;
eyedblib::Mutex gen_mp;

/* MIND: I THINK THAT THIS MODULE IS NOT *QUITE* THREAD SAFE */

#include <limits.h>

static void
msg_init()
{
  //pthread_mutex_init(&msg_mp, NULL);
  //pthread_mutex_init(&gen_mp, NULL);
}

static const char *
msg_make(const char *fmt, ...)
{
  va_list ap;
  static char str[256];
  char buf[256];

  //pthread_mutex_lock(&msg_mp);
  eyedblib::MutexLocker _(msg_mp);
  va_start(ap, fmt);

#if 0
  sprintf(str, "\n[thread %d#%d] %s: ", rpc_getpid(), pthread_self(), progName);
  vsprintf(buf, fmt, ap);
  (void)strcat(str, buf);
#else
  vsprintf(str, fmt, ap);
#endif
  va_end(ap);

  //pthread_mutex_unlock(&msg_mp);
  return str;
}

static void
close_files(void)
{
#if 0
  int fd;
  int maxfd = sizeof(fd_mask) * 8;
  
  for (fd = 1; fd <= maxfd; fd++)
    if (FD_ISSET(fd, &rpc_mainServer->fds_used))
      {
	if (close(fd) < 0)
	  PERROR (msg_make("error closing file %d", fd));
      }
#endif
}

static void
close_clients(void)
{
  int fd;

  abortProgram = rpc_True;

  for (fd = 0; fd < sizeof(clientInfo)/sizeof(clientInfo[0]); fd++)
    if (clientInfo[fd])
      rpc_garbClientInfo(rpc_mainServer, 0, fd);

  /*
    if (unixname)
    unlink(unixname);
  */
}

static char *rpc_unixPort;

#define DO_NOT_EXIT -128000

namespace eyedbsm {
  extern void mutexes_release();
}

namespace eyedb {
  extern void IDB_releaseConn();
}

static void
_QUIT_(int fromcore)
{
  eyedbsm::mutexes_release();
  eyedb::IDB_releaseConn();

  if (rpc_quit_handler)
    rpc_quit_handler(rpc_quit_data, fromcore);
}

void
rpc_quit(int rc, int fromcore)
{
  _QUIT_(fromcore);

  close_clients();
  close_files();

  if (rc != DO_NOT_EXIT)
    exit(rc);
}

void
rpc_unlink_socket()
{
  if (rpc_unixPort)
    unlink(rpc_unixPort);
}

static void
signal_handler(int sig) 
{
  int s;
  for (s = 0; s < NSIG; s++)
    signal(s, SIG_DFL);
  IDB_LOG(IDB_LOG_CONN, ("backend got %s [signal=%d]\n", strsignal(sig), sig));

  if (getenv("EYEDBDEBUG_"))
    sleep(1000);

  if (sig == SIGBUS || sig == SIGSEGV || sig == SIGABRT) {
    IDB_LOG(IDB_LOG_CONN, ("backend fatal signal...\n"));

    rpc_quit(DO_NOT_EXIT, 1);

    if (getenv("EYEDBDBG")) {
      for (;;) sleep(1000);
    }

    /* the following code implies sometimes a loop! */
    /* disconnected it the 27/10/00 */
    /*
      IDB_LOG(IDB_LOG_CONN, ("backend tries to abort and core dumped\n"));

      raise(sig);
      return;
    */
  }

  rpc_quit(0, 0);
  raise(sig);
  exit(0x80|sig);
}

void rpc_setProgName(const char *name)
{
  progName = strdup(name);
}

static void
rpc_ServerInit()
{
  static rpc_Boolean init = rpc_False;;

  if (!init) {
    struct rlimit rlp;

    if (!getrlimit(RLIMIT_NOFILE, &rlp)) {
      rlp.rlim_cur = rlp.rlim_max;
      setrlimit(RLIMIT_NOFILE, &rlp);
    }

    msg_init();

    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGBUS,  signal_handler);
    signal(SIGABRT,  signal_handler);

    signal(SIGPIPE, SIG_IGN);

    init = rpc_True;
  }
}

#define RPC_MAXARGS 32

static rpc_ClientInfo*
rpc_newClientInfo(rpc_Server *server, int fd[], int fd_cnt)
{
  rpc_ClientInfo *ci = rpc_new(rpc_ClientInfo);
  int i;

  for (i = 0; i < fd_cnt; i++)
    clientInfo[fd[i]] = ci;

  ci->fd_cnt = fd_cnt;
  ci->refcnt = fd_cnt;

  ci->tid       = (pthread_t *)malloc(server->conn_cnt * sizeof(pthread_t));
  ci->ua        = (rpc_ServerArg *)malloc(server->conn_cnt * sizeof(rpc_ServerArg));
  ci->comm_buff = (char **)malloc(server->conn_cnt * sizeof(char *));

  for (i = 0; i < server->conn_cnt; i++) {
    ci->comm_buff[i] = (char *)calloc(server->comm_size, 1);
    ci->ua[i]        = (rpc_ServerArg)calloc(server->args_size * RPC_MAXARGS, 1);
  }

  return ci;
}

/* API functions */
rpc_Server *rpc_serverCreate(rpc_ServerMode mode, unsigned long magic,
			     int conn_cnt, int comm_size,
			     void (*init)(int *, int, rpc_ConnInfo *),
			     void (*release)(rpc_ConnInfo *),
			     void (*begin)(int, void *),
			     void (*end)(int, void *), void *user_data)
{
  if (mode != rpc_MonoProc && mode != rpc_MultiProcs &&
      mode != rpc_MultiThreaded && mode != rpc_FrontThreaded)
    return 0;
  else {
    rpc_Server *server = rpc_new(rpc_Server);

    server->last_type = rpc_NBaseType;
    server->conn_cnt  = conn_cnt;
    if (!comm_size)
      comm_size = RPC_COMM_SIZE;
    server->comm_size = comm_size;
    server->mode      = mode;
    server->magic     = magic;
    server->init      = init;
    server->release   = release;
    server->begin     = begin;
    server->end       = end;
    server->user_data = user_data;

#ifdef TRACE
    utlog(msg_make("serverCreate conn_cnt = %d\n", conn_cnt));
#endif
    rpc_ServerInit();
      
    return server;
  }
}

rpc_ArgType rpc_makeServerUserType(rpc_Server *server, int size,
				   rpc_UserArgFunction func)
				   
{
  rpc_UserType *utyp = rpc_getUTyp(server, server->last_type);
  utyp->size = size;
  utyp->func = func;
  return server->last_type++;
}

rpc_ServerFunction *
rpc_makeUserServerFunction(rpc_Server *server, rpc_RpcDescription *rd,
			   rpc_UserServerFunction uf)
{
  rpc_ServerFunction *func = rpc_new(rpc_ServerFunction);

  rd->args[rd->nargs-1].type     = rd->arg_ret;
  rd->args[rd->nargs-1].send_rcv = rpc_Rcv;

  while (rd->args[rd->nargs-1].type == rpc_VoidType)
    rd->nargs--;

  func->rd = rd;
  func->uf = uf;

#ifdef RPC_FUN_CHAIN
  func->next = server->first;
  server->first = func;
#else
  assert(rd->code - START_CODE < sizeof(server->funcs)/sizeof(server->funcs[0]) && rd->code - START_CODE >= 0);
  server->funcs[rd->code - START_CODE] = func;
#endif

  return func;
}

rpc_Status
rpc_setServerArgSize(rpc_Server *server, int args_size)
{
  server->args_size = args_size;
  return rpc_Success;
}

void
rpc_serverOptionsGet(int argc, char *argv[], char **portname, char **unixname)
{
  int i;

  *portname = 0;
  *unixname = 0;

  for (i = 1; i < argc; ) {
    char *s = argv[i];
    if (s[0] == '-') {
      if (!strcmp(s, "-inetd")) {
	if (i+1 >= argc)
	  return;

	*portname = argv[++i];
	i++;
      }
      else if (!strcmp(s, "-unixd")) {
	if (i+1 >= argc)
	  return;

	*unixname = argv[++i];
	if (strlen(*unixname) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
	  utlog(msg_make("eyedb fatal error: unix filename too long (must be < %d\n"),
		sizeof(((struct sockaddr_un *)0)->sun_path));
	  return;
	}
	i++;
      }
    }
    else
      return;
  }
}

/*extern int gethostname(const char *, int);*/

static void
bind_error(const char *portname, bool tcpip)
{
  fprintf(stderr, "\nPerharps another eyedbd is running on ");
  if (tcpip)
    fprintf(stderr, "TCP/IP port %s\n", portname);
  else
    fprintf(stderr, "named pipe port:\n%s\n", portname);

  fprintf(stderr, "\nYou may check this by launching:\n");
  fprintf(stderr, "eyedbctl status --port=%s\n", portname);
  if (!tcpip) {
    fprintf(stderr, "\nIf no, unlink this port as follows:\n");
    fprintf(stderr, "rm -f %s\n", portname);
    fprintf(stderr, "and relaunch the server.\n");
  }
}

static void
rpc_socket_reuse_addr(int s)
{
  int val;
  val = 1;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val)) < 0)
    PERROR("setsockopt reuseaddr");
}

rpc_Status
rpc_portOpen(rpc_Server *server, const char *servname, const char *portname,
	     rpc_PortHandle **pport)
{
  char hname[128];
  int portnumber;
  rpc_PortHandle *port = rpc_new(rpc_PortHandle);
  const char *t_portname;

  t_portname = rpc_getPortAttr(portname, &port->domain, &port->type);
  if (!t_portname) {
    fprintf(stderr, "invalid port '%s'", portname);
    return rpc_Error;
  }
  portname = t_portname;
  port->server = server;
  port->portname = strdup(portname);

  *pport = port;

  if (port->domain == AF_INET) {
    if ((port->u.in.sockin_fd = socket(AF_INET, port->type, 0)) < 0) {
      PERROR(msg_make("eyedb fatal error: unable to create inet socket port '%s'", port->portname) );
      return rpc_Error;
    }

    rpc_socket_reuse_addr(port->u.in.sockin_fd);
    rpc_socket_nodelay(port->u.in.sockin_fd);
      
    port->u.in.sock_in_name.sin_family = AF_INET;
    port->u.in.sock_in_name.sin_port   = htons(atoi(portname));
      
    /* get host name */
    if (servname == 0) {
      if (gethostname(hname, sizeof(hname)-1) < 0) {
	PERROR(msg_make("eyedb fatal error: gethostname failed") );
	return rpc_Error;
      }
      hname[sizeof(hname)-1] = 0;
    }
    else
      strcpy(hname, servname);

    if (!rpc_hostNameToAddr(hname, &port->u.in.sock_in_name.sin_addr)) {
      utlog(msg_make("eyedb fatal error: unknown host '%s'\n", hname));
      fprintf(stderr, msg_make("unknown host '%s'\n", hname));
      return rpc_Error;
    }
      
    if (bind(port->u.in.sockin_fd, (struct sockaddr *)&port->u.in.sock_in_name,
	     sizeof(port->u.in.sock_in_name)) < 0 ) {
      PERROR(msg_make("eyedb fatal error: bind (naming the socket) failed port '%s'", port->portname));
      bind_error(port->portname, true);
      return rpc_Error;
    }

    if (rpc_isSocketValid(port->u.in.sockin_fd) &&
	(port->type == SOCK_STREAM && listen(port->u.in.sockin_fd, 2) < 0)) {
      PERROR(msg_make("eyedb fatal error: listen for inet socket port '%s'", port->portname) );
      return rpc_Error;
    }
  }

  if (port->domain == AF_UNIX) {
    rpc_checkAFUnixPort(portname);

#ifdef HAVE_FATTACH
    int pfd[2];
    int fd;
    int created = 0;

    if ((fd = open(portname, O_RDONLY)) < 0) {
      if ((fd = creat(portname, 0666)) < 0) {
	PERROR(msg_make("eyedb fatal error: cannot create file '%s'",
			portname));
	return rpc_Error;
      }
      created = 1;
    }
      
    if (fchmod(fd, 0666) < 0)	{
      if (created) unlink(portname);
      PERROR(msg_make("eyedb fatal error: cannot change file '%s' mode",
		      portname));
      return rpc_Error;
    }
      
    close(fd);

    if (pipe(pfd) < 0) {
      if (created) unlink(portname);
      PERROR(msg_make("eyedb fatal error: unable to create pipe"));
      return rpc_Error;
    }

    // solaris platform only ?
    if (ioctl(pfd[0], I_PUSH, "connld") < 0) {
      if (created) unlink(portname);
      PERROR(msg_make("eyedb fatal error: unable to configure pipe"));
      return rpc_Error;
    }
    //

    if (fattach(pfd[0], port->portname) < 0) {
      if (created) unlink(portname);
      PERROR(msg_make("eyedb fatal error: unable to attach stream to file '%s'", port->portname) );
      return rpc_Error;
    }

    port->u.un.sockun_fd = pfd[1];
#else
    if ((port->u.un.sockun_fd = socket(AF_UNIX, port->type, 0)) < 0) {
      PERROR(msg_make("eyedb fatal error: unable to create unix socket port '%s'", port->portname) );
      return rpc_Error;
    }

    port->u.un.sock_un_name.sun_family = AF_UNIX;
    strcpy(port->u.un.sock_un_name.sun_path, portname);

    if (bind(port->u.un.sockun_fd,
	     (struct sockaddr *)&port->u.un.sock_un_name,
	     sizeof(port->u.un.sock_un_name)) < 0 ) {
      PERROR(msg_make("eyedb fatal error: bind (naming the socket) failed port '%s'", port->portname));
      bind_error(port->portname, false);
      /*
	fprintf(stderr, "\nPerharps another eyedbd is running on port:\n%s\n",
	port->portname);
	fprintf(stderr, "\nYou may check this by launching:\n");
	fprintf(stderr, "eyedbctl status --port=%s\n", port->portname);
	fprintf(stderr, "\nIf no, unlink this port as follows:\n");
	fprintf(stderr, "rm -f %s\n", port->portname);
	fprintf(stderr, "and relaunch the server.\n");
      */
      return rpc_Error;
    }

    chmod(portname, 0777);
    if (rpc_isSocketValid(port->u.un.sockun_fd) &&
	listen(port->u.un.sockun_fd, 2) < 0 ) {
      PERROR(msg_make("eyedb fatal error: listen for unix socket port '%s'", port->portname) );
      return rpc_Error;
    }
#endif
  }

  return rpc_Success;
}

typedef struct {
  rpc_Server *server;
  int fd;
  int which;
} rpc_ThreadArg;

static void check_fd(int fd, const char *msg)
{
  struct stat stat;
  if (fstat(fd, &stat) < 0)
    utlog(msg_make("%s: error fd=%d is not a valid file descriptor\n",
		   msg, fd));
}

static char exiting = 0;

static eyedblib::Mutex exit_mp;
static eyedblib::Mutex wait_thr_mp;
static eyedblib::Condition *wait_thr_cond;

static void *wait_thr(void *arg)
{
  pid_t pid = *(pid_t *)arg;
  free(arg);
#ifdef TRACE2
  printf("%d:%d waiting for pid %d\n", rpc_getpid(), pthread_self(), pid);
#endif
  int status;
  wait_thr_cond->signal();
  unsigned max_loop = 0;
  do {
    if (max_loop > 100) // to avoid infinite loop
      break;
    errno = 0;
    waitpid(pid, &status, 0);
    max_loop++;
  } while(errno);

#ifdef TRACE2
  printf("%d:%d done pid %d\n", rpc_getpid(), pthread_self(), pid);
#endif
  pthread_detach(pthread_self());
  pthread_exit(&status);

  return 0;
}

static void *serv_thr(void *arg)
{
  rpc_ThreadArg *thr_arg = (rpc_ThreadArg *)arg;
  int fd = thr_arg->fd;
  int which = thr_arg->which;
  rpc_Server *server = thr_arg->server;
  free(thr_arg);

  rpc_setConnFd(fd);
  IDB_LOG(IDB_LOG_CONN, ("new thread %d [fd = %d, which=%d], stack = 0x%x\n", pthread_self(),
			 fd, which, &server));

  rpc_client_id = (rpc_ClientId)fd;

  for (;;)
    if (!rpc_inputHandle(server, which, fd)) /* for now */ {
      if (server->mode == rpc_MultiThreaded || server->conn_cnt > 1) {
	eyedblib::MutexLocker _(exit_mp);
	void *status = 0;
#ifdef TRACE
	utlog(msg_make("%d thread EXIT\n", pthread_self()));
#endif
#ifdef TRACE2
	fprintf(stderr, "%d:%d thread EXIT\n", rpc_getpid(), pthread_self());
	fflush(stderr);
#endif
	//	    rpc_garbClientInfo(server, which, fd);
	rpc_garbClientInfo(server, 0, fd); // force which
	exit(0);
	pthread_exit(&status);
      }
      else
	break;
    }
  return 0;
}

/* needed by sekern.c but chelou! */
static int rpc_serverPort;

int rpc_serverPortGet()
{
  return rpc_serverPort;
}

static void
rpc_serverStart(rpc_Server *server, int *fd, int fd_cnt, rpc_ConnInfo *rpc_ci)
{
  if (server->connh)
    (*server->connh)(server, (rpc_ClientId)fd[0], rpc_True);
  
  if (server->init)
    server->init(fd, fd_cnt, rpc_ci);
}

static void
rpc_serverEnd(rpc_Server *server, rpc_ConnInfo *rpc_ci)
{
  if (server->release)
    server->release(rpc_ci);
}

static void
rpc_makeThread(rpc_Server *server, int which, int fd, rpc_ClientInfo *ci)
{
  rpc_ThreadArg *thr_arg = rpc_new(rpc_ThreadArg);

  thr_arg->server = server;
  thr_arg->fd     = fd;
  thr_arg->which  = which;

#ifdef TRACE
  utlog(msg_make("rpc_makeThread which=%d, fd=%d\n", which, fd));
#endif

  pthread_create(&ci->tid[which], NULL, serv_thr, thr_arg);
}

static void
rpc_makeNewConnection(rpc_Server *server, int new_fd[], int fd_cnt,
		      int *pmax_fd, rpc_ConnInfo *rpc_ci)
{
  /* We have a new connection. */
  rpc_ThreadArg *thr_arg;
  int main_fd = new_fd[0];
  rpc_ClientInfo *ci;
  int i;

  ci = rpc_newClientInfo(server, new_fd, fd_cnt);

#ifdef TRACE
  {
    char buf[2048];
    strcpy(buf, "new connection : ");
    for (i = 0; i < fd_cnt; i++) {
      char tok[32];
      if (i)
	strcat(buf, ", ");

      sprintf(tok, "fd = %d", new_fd[i]);
      strcat(buf, tok);
    }
    strcat(buf, "\n");

    utlog(buf);
  }
#endif

  if (server->mode == rpc_MonoProc) {
    for (i = 0; i < fd_cnt; i++)
      {
	if (new_fd[i] > *pmax_fd)
	  *pmax_fd = new_fd[i];
	FD_SET(new_fd[i], &server->fds_used);
      }
    rpc_serverStart(server, new_fd, fd_cnt, rpc_ci);
    rpc_serverEnd(server, rpc_ci);
  }
  else {
    if (server->mode == rpc_MultiThreaded) {
      rpc_serverStart(server, new_fd, fd_cnt, rpc_ci);
      for (i = 0; i < fd_cnt; i++)
	rpc_makeThread(server, i, new_fd[i], ci);
      rpc_serverEnd(server, rpc_ci);
    }
    else if (server->mode == rpc_MultiProcs) {
      pid_t child_pid;

      if ((child_pid = fork()) == 0) {
	rpc_pid = getpid();
	const char *w;
	if ((w = getenv("EYEDBWAIT"))) {
	  int sec = atoi(w);
	  if (!sec)
	    sec = 30;
	  printf("Pid %d waiting for %d seconds\n", rpc_getpid(), sec);
	  sleep(sec);
	  printf("Continuing...\n");
	}

	rpc_serverStart(server, new_fd, fd_cnt, rpc_ci);
	if (fd_cnt > 1) {
	  for (i = 0; i < fd_cnt; i++)
	    rpc_makeThread(server, i, new_fd[i], ci);

	  for (i = 0; i < fd_cnt; i++) {
	    void *status;
	    pthread_join(ci->tid[i], &status);
	  }

	  free(ci->tid);
	  free(ci);
#ifdef TRACE
	  utlog(msg_make("all threads terminated\n"));
#endif
	}
	else {
	  thr_arg = rpc_new(rpc_ThreadArg);
	  thr_arg->server = server;
	  thr_arg->fd     = new_fd[0];
	  thr_arg->which  = 0;
	  serv_thr(thr_arg);
	}

	rpc_serverEnd(server, rpc_ci);
	rpc_quit(0, 0);
      }

      wait_thr_cond = new eyedblib::Condition();
      pthread_t wait_thr_p;
      pid_t *pid = new pid_t(child_pid);
      errno = 0;
      if (!pthread_create(&wait_thr_p, 0, wait_thr, pid))
	wait_thr_cond->wait();
      else
	IDB_LOG(IDB_LOG_CONN, ("cannot create waiting thread\n"));

      delete wait_thr_cond;

      rpc_garbRealize(server, ci, 1);
      free(rpc_ci);
    }
  }
}

typedef struct {
  time_t begin;
  int *fd;
  int fd_cnt;
} rpc_MultiConnEntry;

#define MAX_MULTICONN_ENTRIES 64 /* should be 16 */

static rpc_MultiConnEntry multiConnEntry[MAX_MULTICONN_ENTRIES];
static rpc_ConnInfo *multiConnInfo[256];
static rpc_Boolean multiConn[256];

static void
rpc_multiConnClear(rpc_Server *server, int fd, const char *msg)
{
  int r;
  multiConn[fd] = rpc_False;
  /*free(multiConnInfo[fd]);*/ /* shure ? */
  multiConnInfo[fd] = 0;
  FD_CLR(fd, &server->fds_used);
  r = close(fd);
  utlog(msg_make("%s: multi close fd=%d r = %d\n", msg, fd, r));
}

static void
rpc_multiConnSuppress(rpc_Server *server, rpc_MultiConnEntry *mce,
		      rpc_Boolean do_close)
{
  int i;

  for (i = 0; i < mce->fd_cnt; i++) {
    int fd = mce->fd[i];
    if (do_close) {
      close(fd);
    }
    multiConn[fd] = rpc_False;
    FD_CLR(fd, &server->fds_used);
  }

  free(mce->fd);
  mce->fd = (int *)0;
  mce->fd_cnt = 0;
}

static void
rpc_addRealize(rpc_MultiConnEntry *mce, int fd_cnt, int new_fd)
{
  time(&mce->begin);
  mce->fd = (int *)calloc(sizeof(int), fd_cnt);
  mce->fd[0] = new_fd;
  mce->fd_cnt = 1;
}

static int
rpc_multiConnAddEntry(rpc_Server *server, int new_fd)
{
  rpc_MultiConnEntry *mce = multiConnEntry;
  int fd_cnt = server->conn_cnt;
  int i;
  time_t now;

  for (i = 0; i < MAX_MULTICONN_ENTRIES; i++, mce++)
    if (!mce->fd_cnt) {
      rpc_addRealize(mce, fd_cnt, new_fd);
      return i;
    }

#ifdef TRACE
  utlog(msg_make("multiConnAddEntry: TRIES GARBAGE!\n"));
#endif

  /* no found, tries to garbage according to begin time */
  time(&now);
  mce = multiConnEntry;
  for (i = 0; i < MAX_MULTICONN_ENTRIES; i++, mce++)
    if ((now - mce->begin) > 10) {
      rpc_multiConnSuppress(server, mce, rpc_True);
      rpc_addRealize(mce, fd_cnt, new_fd);
      return i;
    }

  return -1;
}

static rpc_MultiConnEntry *
rpc_multiConnGetEntry(int xid)
{
  rpc_MultiConnEntry *mce;

  if (xid < 0 || xid >= MAX_MULTICONN_ENTRIES)
    return 0;

  mce = &multiConnEntry[xid];
  if (!mce->fd_cnt)
    return 0;

  return mce;
}

static void
rpc_multiConnManage(rpc_Server *server, int fd, int *pmaxfd)
{
  rpc_MultiConnInfo info;
  rpc_MultiConnInfo xinfo;

#ifdef TRACE
  utlog(msg_make("rpc_multiConnManage %d\n", fd));
#endif

  if (rpc_socketReadTimeout(fd, &info, sizeof(info), 10) != sizeof(info)) {
#ifdef TRACE
    utlog(msg_make("timeout for fd=%d\n", fd));
#endif
    rpc_multiConnClear(server, fd, "timeout");
    return;
  }
  x2h_rpc_multiconninfo(&info);

#ifdef TRACE2
  utlog(msg_make("get magic %x, cmd = %x, xid = %d\n", info.magic, info.cmd,
		 info.xid));
#endif
  if (info.magic != MM(server->magic)) {
    fprintf(stderr, "bad magic: %x vs %x\n", info.magic, MM(server->magic));
    rpc_multiConnClear(server, fd, "bad magic");
    return;
  }

  if (info.cmd == rpc_NewConnection) {
    info.xid = rpc_multiConnAddEntry(server, fd);

    info.cmd = rpc_ReplyNewConnection;

    h2x_rpc_multiconninfo(&xinfo, &info);
    if (rpc_socketWrite(fd, &xinfo, sizeof(xinfo)) != sizeof(xinfo)) {
      rpc_multiConnClear(server, fd, "bad new connection");
      return;
    }
  }
  else if (info.cmd == rpc_AssociatedConnection) {
    rpc_MultiConnEntry *mce;
    mce = rpc_multiConnGetEntry(info.xid);
    if (!mce) {
      rpc_multiConnClear(server, fd, "no mce");
      return;
    }
      
#ifdef TRACE2
    utlog(msg_make("rpc_AssociatedConnection\n"));
#endif
    mce->fd[mce->fd_cnt++] = fd;

    info.cmd = rpc_ReplyNewConnection;
    h2x_rpc_multiconninfo(&xinfo, &info);
    if (rpc_socketWrite(fd, &xinfo, sizeof(xinfo)) != sizeof(xinfo)) {
      rpc_multiConnClear(server, fd, "bad reply connection");
      return;
    }
    if (mce->fd_cnt == server->conn_cnt) {
      rpc_makeNewConnection(server, mce->fd, mce->fd_cnt, pmaxfd,
			    multiConnInfo[fd]);

      rpc_multiConnSuppress(server, mce, rpc_True);
    }
  }
  else
    rpc_multiConnClear(server, fd, "command not understood");
}

rpc_Status
rpc_serverMainLoop(rpc_Server *server, rpc_PortHandle **ports, int nports)
{
  int max_fd = 0;
  int n, fd, new_fd;
  fd_set fds_ready_to_read;
  rpc_PortHandle *portdb[sizeof(fd_set)*8];

  rpc_mainServer = server;

  memset(portdb, 0, sizeof(portdb));

  FD_ZERO(&server->fds_used);

  for (n = 0; n < nports; n++) {
    rpc_PortHandle *port = ports[n];

    if (port->domain == AF_INET) {
      fd = port->u.in.sockin_fd;
      rpc_serverPort = atoi(port->portname);
    }
    else if (port->domain == AF_UNIX) {
      fd = port->u.un.sockun_fd;
      rpc_unixPort = port->portname;
    }

    if (fd > max_fd)
      max_fd = fd;

    portdb[fd] = port;

    FD_SET(fd, &server->fds_used);
  }

  for (;;) {
#ifdef HAVE_FATTACH
    struct strrecvfd info;
#endif
    fds_ready_to_read = server->fds_used;
    
    /* select sets those which are ready to read */
    n = select (max_fd+1, &fds_ready_to_read, 0, 0, 0);

    if (n < 0) {
      if (errno == EINTR) {
	continue;
      }
      else {
	PERROR(msg_make("error in select"));
	/*
	  utlog("fds_ready_to_read %p, max_fd = %d\n",
	  fds_ready_to_read, max_fd);
	*/
	/* workaround! */
	{
	  int ifd;
	  struct stat stat;
	  for (ifd = 0; ifd <= max_fd; ifd++)
	    if (FD_ISSET(ifd, &server->fds_used) && fstat(ifd, &stat)<0) {
	      utlog("warning, fd is invalid %d\n", ifd);
	      FD_CLR(ifd, &server->fds_used);
	    }
	  continue;
	}
	/*return rpc_Error;*/
      }
    }

    for (fd = 0; fd <= max_fd; fd++)
      if (FD_ISSET(fd, &fds_ready_to_read)) {
	rpc_PortHandle *port;
	if (port = portdb[fd]) {
	  /* we have a new connection */
	  struct sockaddr *sock_addr;
	  socklen_t length;

	  if (port->domain == AF_INET) {
	    sock_addr = (struct sockaddr *)&port->u.in.sock_in_name;
	    length = sizeof(port->u.in.sock_in_name);
	  }
	  else {
	    sock_addr = (struct sockaddr *)&port->u.un.sock_un_name;
	    length = sizeof(port->u.un.sock_un_name);
	  }

#ifdef HAVE_FATTACH
	  if (port->domain == AF_UNIX) {
	    if (ioctl(fd, I_RECVFD, &info) < 0) {
	      PERROR("ioctl");
	      continue;
	    }

	    IDB_LOG(IDB_LOG_CONN,
		    ("connection from %s %s\n",
		     getpwuid(info.uid)->pw_name,
		     (getgrgid(info.gid) ?
		      getgrgid(info.gid)->gr_name : "")));

	    new_fd = info.fd;
	  }
	  else
#endif
	    if ((new_fd = accept(fd, sock_addr, &length)) < 0)
	      PERROR("accept connection");

	  if (new_fd >= 0) {
	    rpc_ConnInfo *ci;
	    if (port->domain == AF_UNIX) {
#ifdef HAVE_FATTACH
	      ci = rpc_make_stream_conninfo(new_fd, &info);
#else
	      ci = rpc_make_unix_conninfo(new_fd);
#endif
	    }
	    else {
	      rpc_socket_nodelay(new_fd);
	      ci = rpc_make_tcpip_conninfo(new_fd);
	    }

	    if (!ci) {
	      close(new_fd);
	      continue;
	    }

	    if (server->conn_cnt > 1) {
	      FD_SET(new_fd, &server->fds_used);
	      if (new_fd > max_fd)
		max_fd = new_fd;
	      multiConn[new_fd] = rpc_True;
	      multiConnInfo[new_fd] = ci;
	    }
	    else
	      rpc_makeNewConnection(server, &new_fd, 1, &max_fd, ci);
	  }
	}
	else if (multiConn[fd])
	  rpc_multiConnManage(server, fd, &max_fd);
	else {
	  if (!rpc_inputHandle(server, 0, fd)) {
	    rpc_garbClientInfo(server, 0, fd);
	  }
	}
      }
  }

  return rpc_Success;
}

rpc_Server *
rpc_getMainServer()
{
  return rpc_mainServer;
}

rpc_ConnectionHandlerFunction
rpc_setConnectionHandler(rpc_Server *server,
			 rpc_ConnectionHandlerFunction connh)
{
  rpc_ConnectionHandlerFunction oconnh = server->connh;

  server->connh = connh;

  return oconnh;
}


static int rpc_serverArgsMake(rpc_Server *, int, int, rpc_ServerFunction **,
			      rpc_SendRcv, rpc_FromTo);

static int
rpc_inputHandle(rpc_Server *server, int which, int fd)
{
  rpc_ServerFunction *func;
  rpc_Status status;
  rpc_ClientInfo *ci = clientInfo[fd];

  if (server->begin)
    server->begin(which, server->user_data);

  if (which < 0 || which >= server->conn_cnt)
    return 0;

  if (!rpc_serverArgsMake(server, which, fd, &func, rpc_Send,
			  rpc_From))
    return 0;
	    
  (*func->uf)((rpc_ClientId)fd, ci->ua[which]);
	    
  if (!rpc_serverArgsMake(server, which, fd, &func, rpc_Rcv,
			  rpc_To))
    return 0;
  
  if (server->end)
    server->end(which, server->user_data);
  
  return 1;
}

static void
rpc_garbRealize(rpc_Server *server, rpc_ClientInfo *ci, int force)
{
  int i;
  
  for (i = 0; i < server->conn_cnt; i++) {
    free(ci->comm_buff[i]);
    free(ci->ua[i]);
  }
  
  free(ci->comm_buff);
  free(ci->ua);
  if (force) {
    free(ci->tid);
    free(ci);
  }

  for (i = 0; i < sizeof(clientInfo)/sizeof(clientInfo[0]); i++)
    if (clientInfo[i] == ci)
      clientInfo[i] = 0;
}

static void
rpc_garbClientInfo(rpc_Server *server, int which, int fd)
{
  rpc_ClientInfo *ci = clientInfo[fd];

#ifdef TRACE2
  printf("%d:%d garbClientInfo...\n", rpc_getpid(), pthread_self());
#endif
#ifdef TRACE
  utlog(msg_make("rpc_garbClientInfo(which = %d, fd = %d, ci = %p)\n",
		 which, fd, ci));
#endif
  if (!ci)
    return;

  eyedblib::MutexLocker _(gen_mp);
  //pthread_mutex_lock(&gen_mp);
#ifdef TRACE
  utlog(msg_make("refcnt = %d, fd_cnt = %d\n",
		 ci->refcnt, ci->fd_cnt));
#endif

  if (!which && server->connh)
    (*server->connh)(server, (rpc_ClientId)fd, rpc_False);

  if (!--ci->refcnt)
    rpc_garbRealize(server, ci, 0);

  clientInfo[fd] = 0;

  FD_CLR(fd, &server->fds_used);
#ifdef TRACE
  //utlog("rpc_garbClientInfo: close(%d)\n", fd);
#endif
  close(fd);

#if 0
  if (ci->refcnt) {
    _.unlock();
    int i = 0;
    for (i = 0; i < ci->fd_cnt; i++) {
      if (ci->tid[i] == pthread_self())
	break;
    }

    for (++i; i < ci->fd_cnt; i++) {
      printf("%d:%d killing thread %d:%d\n", rpc_getpid(),
	     pthread_self(), rpc_getpid(), ci->tid[i]);
      pthread_kill(ci->tid[i], SIGTERM);
    }
  }
#endif

#ifdef TRACE
  utlog(msg_make("close connection fd=%d\n", fd));
#endif
  //pthread_mutex_unlock(&gen_mp);
}

/* send_rcv: select interesting arguments : rpc_Send || rpc_Rcv
   fromto  : rpc_From or rpc_To socket
*/

rpc_ClientInfo *
rpc_clientInfoGet(int fd)
{
  return clientInfo[fd];
}

int rpc_serverArgsMake(rpc_Server *server, int which, int fd,
		       rpc_ServerFunction **pfunc,
		       rpc_SendRcv send_rcv, rpc_FromTo fromto)
{
  int i, commsz;
  char *buff, *commb;
  register rpc_Arg *arg;
  rpc_ServerArg pua;
  rpc_RpcHeader rhd;
  rpc_RpcHeader xrhd;
  int ndata = 0;
  rpc_ServerData *p_data[RPC_NDATA];
  rpc_RpcDescription *rd;
  register rpc_ClientInfo *ci = clientInfo[fd];
  char *comm_buff = ci->comm_buff[which];
  rpc_ServerArg ua = ci->ua[which];
  int comm_size = server->comm_size;
  int args_size = server->args_size;
  rpc_ServerFunction *func;
  int buff_size = 0;
  rpc_UserType *utyp;
  rpc_StatusRec rstatus;

  rstatus.err = 0;

  int read_cnt = 0;
  int write_cnt = 0;
  commb = comm_buff;
  commsz = comm_size;
  /*#ifdef RPC_MIN_SIZE*/
#if 1
  if (fromto == rpc_From)
    buff = commb;
  else
    buff = commb + sizeof(rhd);
#else
  buff = commb + sizeof(rhd);
#endif

  if (fromto == rpc_From) {
    /* lecture de l'header */
#ifdef USE_RPC_MIN_SIZE
    read_cnt++;
#ifdef RPC_TIMEOUT
    if (rpc_socketReadTimeout(fd, buff, RPC_MIN_SIZE, rpc_timeout) !=
	RPC_MIN_SIZE)
      return 0;
#else
    if (rpc_socketRead(fd, buff, RPC_MIN_SIZE) != RPC_MIN_SIZE)
      return 0;
#endif

    memcpy(&rhd, buff, sizeof(rhd));
    x2h_rpc_hd(&rhd);
    buff += sizeof(rhd);
#else

#ifdef RPC_TIMEOUT
    read_cnt++;
    if (rpc_socketReadTimeout(fd, buff, sizeof(rhd), rpc_timeout) !=
	sizeof(rhd))
      return 0;
#else
    if (rpc_socketRead(fd, buff, sizeof(rhd)) != sizeof(rhd))
      return 0;
#endif

    memcpy(&rhd, buff, sizeof(rhd));
    x2h_rpc_hd(&rhd);
    buff += sizeof(rhd);

#endif
    if (rhd.magic != server->magic) {
      IDB_LOG_FX(("Server Error #1: invalid magic=%p, expected=%d, "
		  "serial=%d\n", rhd.magic, server->magic, rhd.serial));
      /*rpc_quit(1, 0);*/
      return 0;
    }

    func = rpc_rpcGet(server, rhd.code);

    if (!func) {
      IDB_LOG_FX(("Server Error #2: invalid function code=%d\n", rhd.code));
      /*rpc_quit(1, 0);*/
      return 0;
    }

#ifdef USE_RPC_MIN_SIZE
    if (rhd.size-RPC_MIN_SIZE > 0) {
      read_cnt++;
      if (rpc_socketRead(fd, buff+RPC_MIN_SIZE-sizeof(rhd),
			 rhd.size-RPC_MIN_SIZE) != rhd.size-RPC_MIN_SIZE) {
	IDB_LOG_FX(("Server Error #3: read failed for %d bytes\n",
		    rhd.size-sizeof(rhd)));
	/*rpc_quit(1, 0);*/
	return 0;
      }
    }
#else
    if (rhd.size-sizeof(rhd))
      if (rpc_socketRead(fd, buff, rhd.size-sizeof(rhd)) !=
	  rhd.size-sizeof(rhd)) {
	IDB_LOG_FX(("Server Error #3: read failed for %d bytes\n",
		    rhd.size-sizeof(rhd)));
	/*rpc_quit(1, 0);*/
	return 0;
      }
#endif
    *pfunc = func;
  }
  else {
    func = *pfunc;
#ifdef TRACE2
    utlog(msg_make("[%d] serverArgsMake code #%d, TO\n", pthread_self(), func->rd->code));
#endif
  }

  rd = func->rd;

  for (i = 0, arg = rd->args, pua = ua; i < rd->nargs; i++, arg++, pua += args_size)
    switch(arg->type) {
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
      if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_To) {
	eyedblib_mcp(&rstatus, pua, sizeof(rstatus));
      }

      /* assuming that the 'err' field is of sizeof(eyedblib::int32) and that
	 it is the first field in the rpc_StatusRec structure */
      rpc_copy_fast_xdr(arg, buff, pua, sizeof(eyedblib::int32), send_rcv, fromto, x2h_32_cpy, h2x_32_cpy);

      break;

    case rpc_StringType:
      if ((arg->send_rcv & rpc_Send) && fromto == rpc_From) {
	int len;
	x2h_32_cpy(&len, buff);

	buff += sizeof(len);
	if (len)
	  *(char **)pua = buff; /* oups? */
	else
	  *(char **)pua = (char*)""; /*@@@@warning suppress*/
	buff += len;
      }
      else if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_To) {
	int len;

	if (*(char **)pua)
	  len = strlen(*(char **)pua)+1;
	else
	  len = 0;
	h2x_32_cpy(buff, &len);
	buff += sizeof(len);
	if (len)
	  memcpy(buff, *(char **)pua, len);
	buff += len;
      }
      break;
	
    case rpc_DataType:
      if ((arg->send_rcv & rpc_Send) && fromto == rpc_From) {
	int status;
	rpc_ServerData *a_data = (rpc_ServerData *)pua;

	a_data->garbage_fun = 0;
	a_data->garbage_data = 0;

	x2h_32_cpy(&a_data->data, buff);

	buff += 8;
	x2h_32_cpy(&a_data->size, buff);
	buff += sizeof(a_data->size);
	x2h_32_cpy(&status, buff);
	buff += sizeof(status);
	if (status == rpc_SyncData) {
	  a_data->data = buff;
	  buff += a_data->size;
	  a_data->fd = -1;
	}
	else
	  a_data->fd = fd;
      }
      else if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_To) {
	int status, offset;
	rpc_ServerData *a_data = (rpc_ServerData *)pua;

	h2x_32_cpy(buff, &a_data->size);
	buff += sizeof(a_data->size);

	if (a_data->status == rpc_BuffUsed) {
	  status = rpc_SyncData;
	  h2x_32_cpy(buff, &status);
	  buff += sizeof(status);
	  offset = (char *)a_data->data - buff;
	  h2x_32_cpy(buff, &offset);
	  buff += sizeof(offset);
	  buff_size += a_data->size;
	}
	else if (a_data->status == rpc_TempDataUsed ||
		 a_data->status == rpc_PermDataUsed) {
	  status = rpc_ASyncData;
	  h2x_32_cpy(buff, &status);
	  buff += sizeof(status);
	  offset = 0;
	  h2x_32_cpy(buff, &offset);
	  buff += sizeof(offset);
	  p_data[ndata++] = a_data;
	}
      }
      else if ((arg->send_rcv & rpc_Rcv) && fromto == rpc_From) {
	char *pbuff = commb + sizeof(rhd);
	int j;
	rpc_Arg *parg;
	rpc_Boolean cant = rpc_False;
	rpc_ServerData *a_data = (rpc_ServerData *)pua;

	a_data->garbage_fun = 0;
	a_data->garbage_data = 0;

	for (j = 0, parg = rd->args; j < rd->nargs; j++, parg++)
	  switch(parg->type) {
	  case rpc_ByteType:
	    if (parg->send_rcv & rpc_Rcv)
	      pbuff += sizeof(char);
	    break;

	  case rpc_Int16Type:
	    if (parg->send_rcv & rpc_Rcv)
	      pbuff += sizeof(eyedblib::int16);
	    break;
	
	  case rpc_Int32Type:
	    if (parg->send_rcv & rpc_Rcv)
	      pbuff += sizeof(eyedblib::int32);
	    break;
	
	  case rpc_Int64Type:
	    if (parg->send_rcv & rpc_Rcv)
	      pbuff += sizeof(eyedblib::int64);
	    break;
	
	  case rpc_StatusType:
	    if (parg->send_rcv & rpc_Rcv)
	      pbuff += sizeof(eyedblib::int32);
	    break;

	  case rpc_StringType:
	    if (parg->send_rcv & rpc_Rcv)
	      cant = rpc_True;
	    break; 

	  case rpc_DataType:
	    if (parg->send_rcv & rpc_Rcv)
	      if (j != i)
		cant = rpc_True;
	    break;
		  
	  case rpc_VoidType:
	    break;

	  default:
	    rpc_assert(parg->type >= rpc_NBaseType &&
		       parg->type < server->last_type);
	    if (parg->send_rcv & rpc_Rcv) {
	      utyp = rpc_getUTyp(server, parg->type);

	      if (utyp->size == rpc_SizeVariable)
		cant = rpc_True;
	      else
		pbuff += utyp->size;
	      break;
	    }
	  }

	a_data->fd = fd;

	if (cant) {
	  a_data->data = 0;
	  a_data->buff_size = 0;
	}
	else {
	  /* data size + status + offset */
	  a_data->data = pbuff + 3*sizeof(int);
	  a_data->buff_size = rpc_buff_size(commsz, commb, pbuff);
	}
	buff += 3*sizeof(int);
      }
      break;
	
    case rpc_VoidType:
      break;

    default:
      rpc_assert(arg->type >= rpc_NBaseType && arg->type < server->last_type);
      utyp = rpc_getUTyp(server, arg->type);

      if (utyp->func)
	utyp->func(arg, &buff, pua, send_rcv, fromto);
      else
	rpc_copy(arg, buff, pua, utyp->size, send_rcv, fromto);
    }
  
  if (fromto == rpc_From) {
    if (rhd.ndata)
      {
	int d[RPC_NDATA], i;

	read_cnt++;
	if (rpc_socketRead(fd, d, rhd.ndata*sizeof(int)) != rhd.ndata*sizeof(int))
	  return 0;
      }
  }
  else if (fromto == rpc_To) {
    rhd.code = rd->code;

    rhd.magic = server->magic;
    rhd.serial = 0;
    rhd.ndata = ndata;
    rhd.status = 0;

    rhd.size = (int)(buff-commb) + buff_size;

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

    write_cnt++;
    if (rpc_socketWrite(fd, commb, rhd.size) <= 0)
      return 0;
      
    if (ndata) {
      int d[RPC_NDATA], i;
      for (i = 0; i < ndata; i++)
	d[i] = h2x_32(p_data[i]->size);
      write_cnt++;
      if (rpc_socketWrite(fd, d, ndata*sizeof(int)) <= 0)
	return 0;

      for (i = 0; i < ndata; i++) {
	if (p_data[i]->size) {
	  int error = 0;
	  write_cnt++;
	  if (rpc_socketWrite(fd, p_data[i]->data, p_data[i]->size) <= 0)
	    error = 1;
	  if (p_data[i]->status == rpc_TempDataUsed) {
	    /*
	      if (p_data[i]->garbage_fun)
	      p_data[i]->garbage_fun(p_data[i]->data,
	      p_data[i]->garbage_data);
	      else */
	    free((char *)p_data[i]->data);
	  }
	  if (error)
	    return 0;
	}
      }
    }

    if (rstatus.err) {
      int len = strlen(rstatus.err_msg);
      int tmp = h2x_32(rstatus.err);
      write_cnt++;
      if (rpc_socketWrite(fd, &tmp, sizeof(tmp)) != sizeof(tmp))
	return 0;
      tmp = h2x_32(len);
      write_cnt++;
      if (rpc_socketWrite(fd, &tmp, sizeof(tmp)) != sizeof(tmp))
	return 0;
      write_cnt++;
      if (rpc_socketWrite(fd, rstatus.err_msg, len+1) != len+1)
	return 0;
    }
  }

  return 1;
}

rpc_Boolean
rpc_serverCheck(int port)
{
  int sock_fd, length;
  struct sockaddr_in sock_in_name;
  struct sockaddr *sock_addr;
  char hname[128];

  sock_in_name.sin_family = AF_INET;
  sock_in_name.sin_port = htons(port);
  /* get host name */
  if (gethostname(hname, sizeof(hname)-1) < 0) {
    PERROR(msg_make("gethostname failed") );
    return rpc_False;
  }
  hname[sizeof(hname)-1] = 0;
  if (!rpc_hostNameToAddr(hname, &sock_in_name.sin_addr))
    return rpc_False;
  sock_addr = (struct sockaddr *)&sock_in_name;
  length = sizeof(sock_in_name);

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0))  < 0) {
    PERROR(msg_make("unable to create socket"));
    return rpc_False;
  }

  if (connect(sock_fd, sock_addr, length) < 0) {
    PERROR(msg_make("unable to connect socket"));
    return rpc_False;
  }

  close(sock_fd);
  return rpc_True;
}

rpc_ServerFunction *rpc_rpcGet(rpc_Server *server, rpc_RpcCode code)
{
#ifdef RPC_FUN_CHAIN
  register rpc_ServerFunction *func = server->first;

  while (func) {
    if (func->rd->code == code)
      return func;
    func = func->next;
  }

  return 0;
#else
  return server->funcs[code - START_CODE];
#endif
}

void
eyedblib_abort()
{
  time_t t;
  static int reentrant = 0;
  char msg[256];
  time(&t);
  
  if (reentrant)
    exit(1);

  reentrant = 1;

  sprintf(msg, "EyeDB aborting [pid = %d]\n", rpc_getpid());
  write(2, msg, strlen(msg));

  utlog("EyeDB aborting [pid = %d]\n", rpc_getpid());
  if (getenv("EYEDBDBG")) for (;;) sleep(1000);

  _QUIT_(0);

  kill(SIGABRT, rpc_getpid());
  exit(2);
}

void
abort()
{
  eyedblib_abort();
}
