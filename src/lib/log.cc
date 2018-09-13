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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
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

#include <eyedblib/log.h>
#include <eyedblib/rpc_lib.h>

#ifndef HAVE_CTIME_R
#define CTIME_R(T, S, L) S = ctime(T)
#else
#ifdef HAVE_CTIME_R_3
#define CTIME_R(T, S, L) ctime_r(T, S, L)
#else
#define CTIME_R(T, S, L) ctime_r(T, S)
#endif
#endif

static FILE *logfd;
static char *logProgName;
static char *logDevName;
static FILE *fdnull;

eyedblib::LogMask eyedblib::log_mask;

void
utlogInit(const char *progName, const char *devname)
{
  if (!fdnull)
    fdnull = fopen("/dev/null", "w");

  if (logfd && logfd != stdout && logfd != stderr)
    fclose(logfd);

  logfd = (FILE *)0;

  if (!devname)
    return;

  free(logDevName);
  logDevName = strdup(devname);

  free(logProgName);
  logProgName = strdup(progName);

  if (!strcmp(devname, "stderr"))
    logfd = stderr;
  else if (!strcmp(devname, "stdout"))
    logfd = stdout;
  else {
    logfd = fopen(devname, "w");

    if (!logfd) {
      fprintf(stderr, "%s: cannot open log file '%s' for writing\n",
	      logProgName, devname);
      /*exit(1);*/
    }
  }
}

FILE *
utlogFDGet()
{
  return (logfd ? logfd : fdnull);
}

FILE *
utlogFDSet(FILE *fd)
{
  FILE *oldlogfd = logfd;
  logfd = fd;
  return oldlogfd;
}

const char *utlogDevNameGet()
{
  /*  check(); */
  return logDevName;
}

int rpc_from_core;

static unsigned long long ms_start;
static int log_date = 1;
static int log_timer;
static int log_progname;
static int log_pid;

void
utlogResetTimer()
{
  ms_start = 0;
}

void
utlogSetLogDate(int on)
{
  log_date = on;
}

void
utlogSetLogTimer(int on)
{
  log_timer = on;
}

void
utlogSetLogPid(int on)
{
  log_pid = on;
}

void
utlogSetLogProgName(int on)
{
  log_progname = on;
}

void
utlog_p(const char *s)
{
  static const char prefix[] = "IDB_LOG_";
  static const int prefix_len = 8;
  const char *x;

  if (!logfd || rpc_from_core)
    return;

  if (!strncmp(s, prefix, prefix_len))
    x = s + prefix_len;
  else
    x = s;

  fprintf(logfd, "%s ", x);
}


void
utlog(const char *fmt, ...)
{
  va_list ap;
  struct timeval tv;
  unsigned long long ms;
  time_t t;
#ifdef HAVE_CTIME_R
  char time_str[64];
#else
  char *time_str;
#endif

  if (!logfd || rpc_from_core)
    return;

  if (log_date) {
    time(&t);
    CTIME_R(&t, time_str, sizeof(time_str)-1);
    time_str[strlen(time_str)-1] = 0;
    fprintf(logfd, "%s ", time_str);
  }

  if (log_timer) {
    gettimeofday(&tv, NULL);
    ms = (unsigned long long)tv.tv_sec * 1000ULL +
      (unsigned long long)tv.tv_usec / 1000ULL;
    if (!ms_start)
      ms_start = ms;
    fprintf(logfd, "%llu ms ", ms-ms_start);
  }


  if (log_pid)
    fprintf(logfd, "[thread %d#%d] ", rpc_getpid(), pthread_self());

  if (log_progname)
    fprintf(logfd, "%s ", logProgName);

  if (log_date || log_timer || log_pid || log_progname)
    fprintf(logfd, ": ");

  va_start(ap, fmt);
  vfprintf(logfd, fmt, ap);
  va_end(ap);

  fflush(logfd);
}
