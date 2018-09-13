
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


#include "olib.h"
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#define _eyedb_eyedbsm_P_
#include <eyedblib/log.h>
#include <eyedblib/butils.h>
#include <eyedblib/log.h>
#include <eyedbsm/xdr.h>

/* database */
char *o_dbfile;
eyedbsm::DbHandle *o_dbh;

/* transaction parameters */
eyedbsm::TransactionParams o_params = eyedbsm::DEFAULT_TRANSACTION_PARAMS;
eyedbsm::LockMode o_read_lock = eyedbsm::LockS;
o_TransEpilogue o_trans_epilogue = o_Commit;

/* oids */
char *o_oidfile;
int o_oidfd;
eyedbsm::Oid *o_oids;
unsigned int o_count;

/* oid control */
eyedbsm::Boolean o_reverse;
int o_from;
int o_incr = 1;

/* open hints */
eyedbsm::OpenHints o_open_hints;

/* wait hints */
eyedbsm::Boolean o_wait_start = eyedbsm::False;
int o_wait_op = -1;
eyedbsm::Boolean o_wait_trans = eyedbsm::False;
int o_wait_timeout;

/* miscelleanous */
const char *o_progname;
eyedbsm::Boolean o_verbose = eyedbsm::False;
eyedbsm::Boolean o_location = eyedbsm::False;
eyedbsm::Boolean o_register = eyedbsm::False;
eyedblib::ThreadPool *o_perf_pool = 0;
unsigned int o_ntimes = 1;
unsigned int o_thread_cnt = 0;
unsigned int o_performer_cnt = 0;
int o_dspid = eyedbsm::DefaultDspid;
int o_pid;
time_t o_stime;

static eyedbsm::Boolean o_creating;
static eyedbsm::Boolean o_need_oidfile = eyedbsm::True;
static int o_default_count = o_NeedCount;

int
o_usage(eyedbsm::Boolean complete)
{
  fprintf(stderr,
	  "o_usage: %s\n"
	  "       [-open_hints whole | -open_hints segment <mapwide>]\n"
	  "       [-trans on|off] [-trans_recov partial|full|off]\n"
	  "       [-trans_magorder <magorder>] [-trans_timeout <timeout]\n"
	  "       [-trans_ratioalrt <ratioalrt>]\n"
	  "       [-trans_lock R_S_W_S|R_S_W_SX|R_S_W_X|R_SX_W_SX|R_SX_W_X|R_X_W_X|\n"
	  "        R_N_W_S||R_N_W_SX|R_N_W_X|R_N_W_N|DB_X]\n"
	  "       [-read_lock N|S|X|SX] [-abort|-commit|-forget]\n"
	  "       [-verbose] [-location] [-register] [-threads <cnt>]\n"
	  "       [-ntimes <cnt>] [-wait_start] [-wait_op] <n> [-wait_trans]\n"
	  "       [-wait_timeout <timeout>]\n"
	  "       %s <dbfile>%s%s%s",
	  o_progname, (o_creating ? "[-dspid <dspid>]" :
		       "[-reverse] [-from <from>] [-incr <incr>]"),
	  (o_need_oidfile ? " <oidfile>" : ""),
	  (o_default_count == o_NeedCount ? " <count>" : 
	   (o_default_count == o_OidFileCount ? " [<count>]" : "")),
	  (complete ? "\n" : " "));
  return 1;
}

int
o_dbopen()
{
  eyedbsm::Status s = eyedbsm::dbOpen(o_dbfile, eyedbsm::VOLRW|eyedbsm::LOCAL,
				      (o_open_hints.maph ? &o_open_hints : 0), 0,
				      0, &o_dbh);
  if (s) {
    fprintf(stderr, "%s: cannot open database %s\n", o_progname, o_dbfile);
    //eyedbsm::statusPrint(s, "%s: opening database %s", o_progname, o_dbfile);
    return 1;
  }

  /*
  if (eyedbsm::statusPrint(eyedbsm::dbOpen(o_dbfile, eyedbsm::VOLRW|eyedbsm::LOCAL,
			       (o_open_hints.maph ? &o_open_hints : 0), 0,
			       0, &o_dbh),
		     "%s: opening database \"%s\"", o_progname, o_dbfile))
    return 1;

  */
  return 0;
}

int o_fileopen(o_FileType type)
{
  if (type == o_Skip) return 0;
  int rcount, i;

  if (type == o_Create) {
    o_oidfd = creat(o_oidfile, 0666);
  
    if (o_oidfd < 0) {
      fprintf(stderr, "cannot create file `%s'\n", o_oidfile);
      return 1;
    }

    o_oids = (eyedbsm::Oid *)calloc(o_count, sizeof(eyedbsm::Oid));
    return 0;
  }

  if (type == o_Read)
    o_oidfd = open(o_oidfile, O_RDONLY);
  else
    o_oidfd = open(o_oidfile, O_RDWR);

  if (o_oidfd < 0) {
    fprintf(stderr, "cannot open file `%s' for reading\n", o_oidfile);
    return 1;
  }

  read(o_oidfd, &rcount, sizeof(rcount));
  rcount = x2h_32(rcount);

  if (o_default_count == o_OidFileCount || o_count > rcount-o_from)
    o_count = rcount-o_from;

  if (o_count <= 0) {
    fprintf(stderr, "o_from %d cannot be greater than object count %d\n",
	    o_from, rcount);
    return 1;
  }

  o_count = o_count/o_incr;
  o_oids = (eyedbsm::Oid *)calloc(o_count, sizeof(eyedbsm::Oid));
  lseek(o_oidfd, o_from*sizeof(eyedbsm::Oid), SEEK_CUR);
  if (o_incr > 1)
    for (i = 0; i < o_count; i++) {
      read(o_oidfd, &o_oids[i], sizeof(eyedbsm::Oid));
      eyedbsm::x2h_oid(&o_oids[i], &o_oids[i]);
      lseek(o_oidfd, sizeof(eyedbsm::Oid), SEEK_CUR);
    }
  else {
    read(o_oidfd, o_oids, o_count*sizeof(eyedbsm::Oid));
    eyedbsm::x2h_oids(o_oids, o_oids, o_count);
  }

  lseek(o_oidfd, 0, SEEK_SET);
  return 0;
}

void
o_write_oids(const eyedbsm::Oid *oids, unsigned int count)
{
  unsigned int xcount = h2x_u32(count);
  assert(write(o_oidfd, &xcount, sizeof(o_count)) == sizeof(o_count));

  eyedbsm::Oid *xoids = new eyedbsm::Oid[count];
  eyedbsm::h2x_oids(xoids, oids, count);
  assert(write(o_oidfd, xoids, count * sizeof(eyedbsm::Oid)) == count * sizeof(eyedbsm::Oid));
  delete [] xoids;
}

#define o_FMT "%-12s"

static void
o_trace_params()
{
  printf(o_FMT " %s\n", "Trsmode",
	 (o_params.trsmode == eyedbsm::TransactionOn ? "ON" : "OFF"));
  printf(o_FMT " ", "Lockmode");
  if (o_params.lockmode == eyedbsm::ReadSWriteS)
    printf("eyedbsm::ReadSWriteS\n");
  else if (o_params.lockmode == eyedbsm::ReadSWriteX)
    printf("eyedbsm::ReadSWriteX\n");
  else if (o_params.lockmode == eyedbsm::ReadSXWriteSX)
    printf("eyedbsm::ReadSXWriteXX\n");
  else if (o_params.lockmode == eyedbsm::ReadXWriteX)
    printf("eyedbsm::ReadXWriteX\n");
  else if (o_params.lockmode == eyedbsm::ReadSWriteSX)
    printf("eyedbsm::ReadSWriteSX\n");
  else if (o_params.lockmode == eyedbsm::ReadNWriteN)
    printf("eyedbsm::ReadNWriteN\n");
  else if (o_params.lockmode == eyedbsm::DatabaseRW)
    printf("eyedbsm::DatabaseX\n");

  printf(o_FMT " %s\n", "Recovmode",
	 (o_params.recovmode == eyedbsm::RecoveryFull ? "Full" : 
	  (o_params.recovmode == eyedbsm::RecoveryPartial ? "Partial" : 
	   "Off")));
  printf(o_FMT " %u\n", "Magorder", o_params.magorder);
  printf(o_FMT " %u\n", "Timeout", o_params.wait_timeout);
  printf(o_FMT " %u\n", "Ratioalrt", o_params.ratioalrt);

  printf(o_FMT " ", "Readlock");
  if (o_read_lock == eyedbsm::LockS)
    printf("S\n");
  else if (o_read_lock == eyedbsm::LockN)
    printf("N\n");
  else if (o_read_lock == eyedbsm::LockX)
    printf("X\n");
  else if (o_read_lock == eyedbsm::LockSX)
    printf("SX\n");
}

int
o_stdusage()
{
  return o_usage(eyedbsm::True);
}

namespace eyedbsm {
  extern Boolean backend;
}

int
o_init(int &argc, char *argv[], o_FileType type, int (*usage)(),
       int default_count)
{
  const char *logmask = getenv("IDB_LOG_MASK");
  if (!logmask)
    logmask = getenv("EYEDBLOGMASK");
  int i;
  o_progname = argv[0];
  o_need_oidfile = (type != o_Skip) ? eyedbsm::True : eyedbsm::False;
  o_default_count = default_count;

  assert(!(!o_need_oidfile && o_default_count == o_NeedCount));
  assert(!(!o_need_oidfile && o_default_count == o_OidFileCount));

  if (logmask) {
    utlogInit(o_progname, "stderr");
    sscanf(logmask, "%llx", &eyedblib::log_mask);
  }

  eyedbsm::init();
  eyedbsm::backend = eyedbsm::True;
  o_creating = (type == o_Create) ? eyedbsm::True : eyedbsm::False;

  for (i = 1; i < argc; i++) {
    char *s = argv[i];
    if (*s == '-') {
      if (!strcmp(s, "-trans")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!strcmp(s, "on"))
	  o_params.trsmode = eyedbsm::TransactionOn;
	else if (!strcmp(s, "off"))
	  o_params.trsmode = eyedbsm::TransactionOff;
	else
	  return usage();
      }
      else if (!strcmp(s, "-trans_recov")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!strcmp(s, "partial"))
	  o_params.recovmode = eyedbsm::RecoveryPartial;
	else if (!strcmp(s, "full"))
	  o_params.recovmode = eyedbsm::RecoveryFull;
	else if (!strcmp(s, "off"))
	  o_params.recovmode = eyedbsm::RecoveryOff;
	else
	  return usage();
      }
      else if (!strcmp(s, "-open_hints")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!strcmp(s, "whole"))
	  o_open_hints.maph = eyedbsm::WholeMap;
	else if (!strcmp(s, "segment")) {
	  o_open_hints.maph = eyedbsm::SegmentMap;
	  if (i == argc - 1)
	    return usage();
	  s = argv[++i];
	  if (!eyedblib::is_number(s))
	    return usage();
	  o_open_hints.mapwide = atoi(s);
	}		
	else
	  return usage();
      }
      else if (!strcmp(s, "-threads")) {
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_thread_cnt = atoi(s);
      }
      else if (!strcmp(s, "-performers")) {
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_performer_cnt = atoi(s);
      }
      else if (!strcmp(s, "-ntimes")) {
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_ntimes = atoi(s);
      }
      else if (!strcmp(s, "-trans_lock")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!strcmp(s, "R_S_W_S"))
	  o_params.lockmode = eyedbsm::ReadSWriteS;
	else if (!strcmp(s, "R_S_W_SX"))
	  o_params.lockmode = eyedbsm::ReadSWriteSX;
	else if (!strcmp(s, "R_S_W_X"))
	  o_params.lockmode = eyedbsm::ReadSWriteX;

	else if (!strcmp(s, "R_SX_W_SX"))
	  o_params.lockmode = eyedbsm::ReadSXWriteSX;
	else if (!strcmp(s, "R_SX_W_X"))
	  o_params.lockmode = eyedbsm::ReadSXWriteX;

	else if (!strcmp(s, "R_X_W_X"))
	  o_params.lockmode = eyedbsm::ReadXWriteX;

	else if (!strcmp(s, "R_N_W_S"))
	  o_params.lockmode = eyedbsm::ReadNWriteS;
	else if (!strcmp(s, "R_N_W_SX"))
	  o_params.lockmode = eyedbsm::ReadNWriteSX;
	else if (!strcmp(s, "R_N_W_X"))
	  o_params.lockmode = eyedbsm::ReadNWriteX;
	else if (!strcmp(s, "R_N_W_N"))
	  o_params.lockmode = eyedbsm::ReadNWriteN;

	else if (!strcmp(s, "DB_X"))
	  o_params.lockmode = eyedbsm::DatabaseRW;
	else
	  return usage();
      }
      else if (!strcmp(s, "-trans_magorder")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_params.magorder = atoi(s);
      }
      else if (!strcmp(s, "-trans_timeout")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_params.wait_timeout = atoi(s);
      }
      else if (!strcmp(s, "-trans_ratioalrt")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_params.ratioalrt = atoi(s);
      }
      else if (!strcmp(s, "-read_lock") && !o_creating) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!strcmp(s, "S"))
	  o_read_lock = eyedbsm::LockS;
	else if (!strcmp(s, "X"))
	  o_read_lock = eyedbsm::LockX;
	else if (!strcmp(s, "SX"))
	  o_read_lock = eyedbsm::LockSX;
	else if (!strcmp(s, "N"))
	  o_read_lock = eyedbsm::LockN;
	else
	  return usage();
      }
      else if (!strcmp(s, "-commit"))
	o_trans_epilogue = o_Commit;
      else if (!strcmp(s, "-abort"))
	o_trans_epilogue = o_Abort;
      else if (!strcmp(s, "-forget"))
	o_trans_epilogue = o_Forget;
      else if (!strcmp(s, "-dspid") && o_creating) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_dspid = atoi(s);
      }
      else if (!strcmp(s, "-reverse") && !o_creating)
	o_reverse = eyedbsm::True;
      else if (!strcmp(s, "-from") && !o_creating) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_from = atoi(s);
      }
      else if (!strcmp(s, "-incr") && !o_creating) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_incr = atoi(s);
      }
      else if (!strcmp(s, "-verbose"))
	o_verbose = eyedbsm::True;
      else if (!strcmp(s, "-location"))
	o_location = eyedbsm::True;
      else if (!strcmp(s, "-register"))
	o_register = eyedbsm::True;
      else if (!strcmp(s, "-wait_trans"))
	o_wait_trans = eyedbsm::True;
      else if (!strcmp(s, "-wait_start"))
	o_wait_start = eyedbsm::True;
      else if (!strcmp(s, "-wait_op")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_wait_op = atoi(s);
      }
      else if (!strcmp(s, "-wait_timeout")) {
	if (i == argc - 1)
	  return usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return usage();
	o_wait_timeout = atoi(s);
      }
      else
	return usage();
    }
    else
      break;
  }

  int incoff;
  if (o_default_count == o_NeedCount) {
    if (i > argc - 3)
      return usage();
    incoff = 3;
  }
  else if (o_need_oidfile) {
    if (i > argc - 2)
      return usage();
    incoff = 2;
  }
  else {
    if (i > argc - 1)
      return usage();
    incoff = 1;
  }

  o_dbfile = argv[i];
  o_oidfile = (type != o_Skip) ? argv[i+1] : 0;
  o_count = (o_default_count == o_NeedCount) ? atoi(argv[i+2]) : default_count;

  if (o_dbopen()) return 1;
  if (o_fileopen(type)) return 1;

  int offset = i+incoff;
  argc -= offset;
  for (int j = 0; j < argc; j++)
    argv[j] = argv[j+offset];

  argv[argc] = 0;

  printf(o_FMT " %s\n", "Dbfile", o_dbfile);
  if (o_need_oidfile)
    printf(o_FMT " %s\n", "Oidfile", o_oidfile);
  if (o_default_count == o_NeedCount || o_default_count == o_OidFileCount)
    printf(o_FMT " %u\n", "Count", o_count);
  printf(o_FMT " %u\n", "NTimes", o_ntimes);
  printf(o_FMT " %u\n", "NPerformer", o_performer_cnt);
  printf(o_FMT " %u\n", "NThread", o_thread_cnt);
  o_trace_params();

  o_pid = getpid();
  time(&o_stime);
  if (o_performer_cnt || o_thread_cnt) {
    if (!o_performer_cnt)
      o_performer_cnt = o_thread_cnt;
    o_perf_pool = new eyedblib::ThreadPool(o_thread_cnt);
  }
  return 0;
}

int
o_release()
{
  close(o_oidfd);
  if (o_trans_epilogue != o_Forget &&
      eyedbsm::statusPrint(eyedbsm::dbClose(o_dbh), "closing database"))
    return 1;
  return 0;
}

int
o_trsbegin()
{
  printf("Beginning transaction\n");
  if (eyedbsm::statusPrint(eyedbsm::transactionBegin(o_dbh, &o_params), "begin transaction"))
    return 1;
  if (o_register)
    eyedbsm::registerStart(o_dbh, eyedbsm::AllOP);

  return 0;
}

int
o_trsend()
{
  if (o_register) {
    eyedbsm::Register *reg;
    eyedbsm::registerGet(o_dbh, &reg);
    eyedbsm::registerTrace(stdout, reg);
  }

  if (o_trans_epilogue == o_Commit) {
    if (o_wait_trans)
      o_wait("Committing", -1);
    else
      printf("Committing\n");
    if (eyedbsm::statusPrint(eyedbsm::transactionCommit(o_dbh), "commit transaction"))
      return 1;
    printf("Done.\n");
    return 0;
  }

  if (o_trans_epilogue != o_Abort)
    return 0;

  if (o_wait_trans)
    o_wait("Aborting", -1);
  else
    printf("Aborting\n");

  if (eyedbsm::statusPrint(eyedbsm::transactionAbort(o_dbh), "abort transaction"))
    return 1;
  printf("Done.\n");
  return 0;
}

static char o_sdata[4096];

//#define MTSAFE_DATA(X) (o_thread_cnt ? strdup(X) : (X))
#define RETURN_MTSAFE_DATA(X) \
  char *xdata = (char *)malloc(sizeof(o_sdata)); \
  memcpy(xdata, o_sdata, sizeof(o_sdata)); \
  return xdata

static eyedblib::Mutex mut;

char *
o_make_data_0(int &len, int count, int n)
{
  int s, i;

  eyedblib::MutexLocker ml(mut);
  sprintf(o_sdata, "----%d*%d*%d*%d-", 7*n+3, count, o_stime+100,  o_pid);
  s = strlen(o_sdata);

  if (len < s)
    o_sdata[len] = 0;
  else if (len >= sizeof(o_sdata))
    len = sizeof(o_sdata)-1;

  for (i = s; i < len; i++)
    o_sdata[i] = (char)((i % 110) + 'c' + o_pid);

  o_sdata[i] = 0;
  RETURN_MTSAFE_DATA(o_sdata);
}

char *
o_make_data_1(int &len, int count, int n)
{
  int s, i;

  eyedblib::MutexLocker ml(mut);
  sprintf(o_sdata, "----%d+%d!pid=%d*time=%d*%d-", 8*n+5, count, o_pid, o_stime, o_pid);
  s = strlen(o_sdata);

  if (len >= sizeof(o_sdata))
    len = sizeof(o_sdata)-1;

  if (getenv("ALLSZ"))
    for (i = s; i < len; i++)
      o_sdata[i] = 'c';
  else
    for (i = s; i < len; i++)
      o_sdata[i] = (char)((i % 110) + 'c' + o_pid);

  o_sdata[i] = 0;
  RETURN_MTSAFE_DATA(o_sdata);
}

char *
o_make_data_2(int &len, int count, int n)
{
  int s, i;

  eyedblib::MutexLocker ml(mut);
  sprintf(o_sdata, "++++%d+%d^%d+%d+%d+", 12*n+3, count, o_pid*31, o_stime+110, o_pid);

  s = strlen(o_sdata);

  if (len >= sizeof(o_sdata))
    len = sizeof(o_sdata)-1;

  for (i = s; i < len; i++)
    o_sdata[i] = (char)((i % 110) + 'c' + o_pid);

  o_sdata[i] = 0;
  RETURN_MTSAFE_DATA(o_sdata);
}

char *
o_make_varstring(int n, int &len)
{
  len = 3 * n + 12;
  return o_make_data_0(len, 1, n);
}

#define TRACE_DATA(fmt, v, x2h, xdr) \
  char *d = data; \
  for (int i = 0; i < kt.count; i++) { \
     memcpy(&v, d, sizeof(v)); \
     if (xdr) v = x2h(v); \
     printf(fmt " ", v); \
     d += sizeof(v); \
  }
 
void
o_trace_data(const eyedbsm::Idx::KeyType &kt, char *data, eyedbsm::Boolean xdr)
{
  eyedblib::MutexLocker ml(mut);
  switch (kt.type)
    {
    case eyedbsm::Idx::tInt16:
    case eyedbsm::Idx::tUnsignedInt16:
      {
	unsigned short v;
	TRACE_DATA("%d", v, x2h_16, xdr);
	break;
      }

    case eyedbsm::Idx::tInt32:
    case eyedbsm::Idx::tUnsignedInt32:
      {
	unsigned int v;
	TRACE_DATA("%d", v, x2h_32, xdr);
	break;
      }
    case eyedbsm::Idx::tInt64:
    case eyedbsm::Idx::tUnsignedInt64:
      {
	unsigned long long v;
	TRACE_DATA("%lld", v, x2h_64, xdr);
	break;
      }
    case eyedbsm::Idx::tFloat32:
      {
	float v;
	TRACE_DATA("%f", v, x2h_f32, xdr);
	break;
      }

    case eyedbsm::Idx::tFloat64:
      {
	double v;
	TRACE_DATA("%f", v, x2h_f64, xdr);
	break;
      }

    case eyedbsm::Idx::tChar:
    case eyedbsm::Idx::tUnsignedChar:
    case eyedbsm::Idx::tSignedChar:
    case eyedbsm::Idx::tString:
      printf("%s", data);
      break;

    default:
      fprintf(stderr, "unsupported index type %d\n", kt.type);
      exit(1);
    }
}

#define RETURN_DATA(v) \
  char *d = o_sdata; \
  for (int i = 0; i < kt.count; i++, v++) { \
    memcpy(d , &v, sizeof(v)); \
    d += sizeof(v); \
  } \
  len = kt.count * sizeof(v); \
  RETURN_MTSAFE_DATA(o_sdata)

unsigned int
randcount()
{
  struct timeval tp;
  gettimeofday(&tp, 0);
  return tp.tv_usec % 512;
}

char *
o_make_data(const eyedbsm::Idx::KeyType &kt, int count, int n, int &len,
	    eyedbsm::Boolean xdr)
{
  switch (kt.type)
    {
    case eyedbsm::Idx::tInt16:
    case eyedbsm::Idx::tUnsignedInt16:
      {
	unsigned short v = count + n * 10;
	if (xdr) v = h2x_16(v);
	RETURN_DATA(v);
      }

    case eyedbsm::Idx::tInt32:
    case eyedbsm::Idx::tUnsignedInt32:
      {
	unsigned int v = count + n * 10;
	if (xdr) v = h2x_32(v);
	RETURN_DATA(v);
      }
    case eyedbsm::Idx::tInt64:
    case eyedbsm::Idx::tUnsignedInt64:
      {
	unsigned long long v = count + n * 10;
	if (xdr) v = h2x_64(v);
	RETURN_DATA(v);
      }
    case eyedbsm::Idx::tFloat32:
      {
	float v = count + n * 10;
	if (xdr) v = h2x_f32(v);
	RETURN_DATA(v);
      }

    case eyedbsm::Idx::tFloat64:
      {
	double v = count + n * 10;
	if (xdr) v = h2x_f64(v);
	RETURN_DATA(v);
      }

    case eyedbsm::Idx::tChar:
    case eyedbsm::Idx::tUnsignedChar:
    case eyedbsm::Idx::tSignedChar:
    case eyedbsm::Idx::tString:
      len = ((int)kt.count > 0 ? kt.count : randcount());
      return o_make_data_1(len, count, n);

    default:
      fprintf(stderr, "unsupported index type %d\n", kt.type);
      exit(1);
    }
}

void
o_dump_data(char *data, int sz)
{
  printf("data length %d:\n\t", sz);
  for (int i = 0; i < sz; i++)
    printf("%02x", data[i]);
  printf("\n");
}

struct ThreadWrapperArg {
  void (*f)(void *);
  void *arg;
};

eyedblib::ThreadPerformerArg
o_performer_wrapper(eyedblib::ThreadPerformerArg xarg)
{
  ThreadWrapperArg *arg = (ThreadWrapperArg *)xarg.data;
  arg->f(arg->arg);
  return eyedblib::ThreadPerformerArg((void *)0);
}

#define O_THREAD() (o_performer_cnt ? o_performer_cnt : 1)

void
o_bench(void (*f)(void *), void *arg)
{
  int ms;
  struct timeval tp0, tp1;

  if (o_wait_start)
    o_wait("go", -1);

  gettimeofday(&tp0, 0);

  for (int i = 0; i < o_ntimes; i++) {
    if (o_perf_pool) {
      ThreadWrapperArg parg;
      parg.f = f;
      parg.arg = arg;
      for (int i = 0; i < o_performer_cnt; i++)
	o_perf_pool->start(o_performer_wrapper, &parg);
      o_perf_pool->waitAll();
    }
    else
      f(arg);
  }

  gettimeofday(&tp1, 0);
  ms = (tp1.tv_sec - tp0.tv_sec)*1000 + (tp1.tv_usec - tp0.tv_usec)/1000;
  unsigned long long us = ms * 1000;
  printf(o_FMT " %.2fs %dms\n", "Total", (float)ms/1000, ms);
  if (o_count)
    printf(o_FMT " %.2fus/object\n", "Average",
	   (float)us/((float)o_count*o_ntimes*O_THREAD()));
  printf(o_FMT " %.2fus/times for %d objects\n", "Average2",
	 (float)us/((float)o_ntimes*O_THREAD()), o_count);
}

void
o_wait(const char *msg, int n)
{
  if (!o_wait_timeout && n < 0)
    printf("%s\n", msg);
  else if ((o_wait_op >= 0 &&
	    ((!o_reverse && n >= o_wait_op) || (o_reverse && n <= o_wait_op)))
	   || n < 0) {
    static char end = '.';
    char c = end;
    fd_set rdfds;
    struct timeval tv;
    const char *soid;

    tv.tv_sec = o_wait_timeout;
    tv.tv_usec = 0;
    FD_ZERO(&rdfds);
    FD_SET(0, &rdfds);

    if (n >= 0) {
      soid = (o_oids[n].getNX() ? o_getOidString(&o_oids[n]) : "");
      printf("%s #%d %s> ", msg, n, soid);
    }
    else
      printf("%s> ", msg);

    fflush(stdout);
    if (select(1, &rdfds, 0, 0, (o_wait_timeout ? &tv : 0)) > 0)
      read(0, &c, 1) <= 0;
    else
      printf("[TIMEOUT=%d]\n", o_wait_timeout);

    if (c == end) {
      printf("Continuing\n");
      o_wait_timeout = 0;
      /*if (n >= 0)*/ o_wait_op = -1;
    }
  }
}

static void
o_idxKeyType_usage(const char *s)
{
  fprintf(stderr, "invalid keytype format: %s\n");
  fprintf(stderr, "expected formats:\n\t<type>\t<type>:<count>:"
	  "\t<type>:<count>:<offset>\n");
  fprintf(stderr, "where <type> is one of those:\n");
  fprintf(stderr, "\tchar\n\tuchar\n\tsignedchar\n\tint16\n\tuint16\n"
	  "\tint32\n\tuint32\n\tint64\n\tuint64\n\tfloat32\n"
	  "\tfloat64\n\tstring\n\toid\n");
  exit(1);
}

eyedbsm::Idx::KeyType
o_get_idxKeyType(const char *_s)
{
  char *stype = strdup(_s);
  char *p = strchr(stype, ':');
  eyedbsm::Idx::KeyType ktype;

  ktype.offset = 0;
  ktype.count = 1;

  if (p) {
    *p++ = 0;
    char *q = strchr(p, ':');
    if (q)
      *q = 0;
    ktype.count = atoi(p);
    if (ktype.count < 0)
      ktype.count = eyedbsm::HIdx::VarSize;
    if (q)
      ktype.offset = atoi(q+1);
  }

  if (!strcasecmp(stype, "char"))
    ktype.type = eyedbsm::Idx::tChar;
  else if (!strcasecmp(stype, "uchar"))
    ktype.type = eyedbsm::Idx::tUnsignedChar;
  else if (!strcasecmp(stype, "signedchar"))
    ktype.type = eyedbsm::Idx::tSignedChar;
  else if (!strcasecmp(stype, "int16"))
    ktype.type = eyedbsm::Idx::tInt16;
  else if (!strcasecmp(stype, "uint16"))
    ktype.type = eyedbsm::Idx::tUnsignedInt16;
  else if (!strcasecmp(stype, "int32"))
    ktype.type = eyedbsm::Idx::tInt32;
  else if (!strcasecmp(stype, "uint32"))
    ktype.type = eyedbsm::Idx::tUnsignedInt32;
  else if (!strcasecmp(stype, "int64"))
    ktype.type = eyedbsm::Idx::tInt64;
  else if (!strcasecmp(stype, "uint64"))
    ktype.type = eyedbsm::Idx::tUnsignedInt64;
  else if (!strcasecmp(stype, "float32"))
    ktype.type = eyedbsm::Idx::tFloat32;
  else if (!strcasecmp(stype, "float64"))
    ktype.type = eyedbsm::Idx::tFloat64;
  else if (!strcasecmp(stype, "string"))
    ktype.type = eyedbsm::Idx::tString;
  else if (!strcasecmp(stype, "oid"))
    ktype.type = eyedbsm::Idx::tOid;
  else
    o_idxKeyType_usage(_s);

  printf("ktype.type = %d\n", ktype.type);
  printf("ktype.count = %d\n", ktype.count);
  printf("ktype.offset = %d\n", ktype.offset);
  return ktype;
}

void
o_idxsearch_realize(eyedbsm::Idx &idx, eyedbsm::IdxCursor &c, const eyedbsm::Idx::KeyType &kt,
		    unsigned int &count, eyedbsm::Boolean rmv)
{
  eyedbsm::Status s;
  struct KD {
    eyedbsm::Oid oid;
    eyedbsm::Idx::Key key;
  } *kd = 0;

  unsigned int kd_alloc = 0;

  for (count = 0; ; count++) {
    if (count >= kd_alloc) {
      int okd_alloc = kd_alloc;
      kd_alloc = count + 32;
      KD *nkd = new KD[kd_alloc];
      if (kd) {
	memcpy(nkd, kd, sizeof(KD) * okd_alloc);
	//delete [] kd;
      }
      kd = nkd;
    }
    eyedbsm::Boolean found;
    s = c.next(&found, &kd[count].oid, &kd[count].key);
    if (!found)
      break;

    if (o_verbose) {
      printf("keydata\n\t");
      o_trace_data(kt, (char *)kd[count].key.getKey(), eyedbsm::True);
      printf("\tdata: %s\n", eyedbsm::getOidString(&kd[count].oid));
    }
  }

  if (rmv) {
    printf("removing...\n");
    for (int i = 0; i < count; i++) {
      eyedbsm::Boolean found;
      if (o_verbose) {
	printf("keydata\n\t");
	o_trace_data(kt, (char *)kd[i].key.getKey(), eyedbsm::True);
	printf("\tdata: %s\n", eyedbsm::getOidString(&kd[i].oid));
      }
      s = idx.remove(kd[i].key.getKey(), &kd[i].oid, &found);
      if (s) {
	eyedbsm::statusPrint(s, "removing key #%d", i);
	delete [] kd;
	return;
      }
      if (!found) {
	fprintf(stderr, "key/data not found\n");
	assert(0);
	delete [] kd;
	return;
      }
    }
  }

  delete [] kd;
}

const char *
o_getOidString(const eyedbsm::Oid *oid)
{
  if (!o_location)
    return eyedbsm::getOidString(oid);
  static std::string s;
  s = eyedbsm::getOidString(oid);
  eyedbsm::ObjectLocation objloc;
  if (!eyedbsm::objectLocationGet(o_dbh, oid, &objloc)) {
    char buf[128];
    sprintf(buf, " [%s oid ns=#%d datid=#%d]",
	    (eyedbsm::isPhysicalOid(o_dbh, oid) ? "physical" : "logical"),
	    objloc.slot_start_num, objloc.datid);
    s += buf;
  }

  return s.c_str();
}


void dummy()
{
  eyedbsm::statusMake(eyedbsm::ERROR, "");
}

static int
o_index_usage()
{
  o_usage(eyedbsm::False);
  fprintf(stderr, "[-magorder <magorder>] [-keycount <keycount>] [-keytype <keytype>] [-inisize_hints <inisize>] [-iniobjcnt_hints <iniobjcnt>] [-xcoef_hints <xcoef>] [-szmax_hints <szmax>] [-data_grouped_by_key 0|1|2|4] [-degree <degree>] [-reimplement_H|-reimplement_B|-simulate] [-fullstats]\n");
  return 1;
}

unsigned int o_magorder = 20000;
unsigned int o_keycount = 0;
int o_degree = 0;
const char *o_keytype = "string:-1";
int o_impl_hints[eyedbsm::HIdxImplHintsCount];
eyedbsm::Boolean o_fullstats = eyedbsm::False;
eyedbsm::Boolean o_reimplement_H = eyedbsm::False;
eyedbsm::Boolean o_reimplement_B = eyedbsm::False;
eyedbsm::Boolean o_simulate = eyedbsm::False;

int
o_index_manage(int argc, char *argv[], o_FileType &ftype,
	       int default_count)
{
  ftype = o_Create;

  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "-reimplement_H") ||
	!strcmp(argv[i], "-reimplement_B")) {
      ftype = o_Write;
      break;
    }
    if (!strcmp(argv[i], "-simulate")) {
      ftype = o_Read;
      break;
    }
  }

  if (o_init(argc, argv, ftype, o_index_usage, default_count))
    return 1;

  for (int i = 0; i < argc; i++) {
    char *s = argv[i];
    if (*s == '-') {
      if (!strcmp(s, "-magorder")) {
	if (i == argc - 1)
	  return o_index_usage();
	o_magorder = atoi(argv[++i]);
      }
      else if (!strcmp(s, "-keycount")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_keycount = atoi(s);
      }
      else if (!strcmp(s, "-degree")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_degree = atoi(s);
      }
      else if (!strcmp(s, "-reimplement_H"))
	o_reimplement_H = eyedbsm::True;
      else if (!strcmp(s, "-reimplement_B"))
	o_reimplement_B = eyedbsm::True;
      else if (!strcmp(s, "-simulate"))
	o_simulate = eyedbsm::True;
      else if (!strcmp(s, "-degree"))
	o_degree = eyedbsm::True;
      else if (!strcmp(s, "-fullstats"))
	o_fullstats = eyedbsm::True;
      else if (!strcmp(s, "-keytype")) {
	if (i == argc - 1)
	  return o_index_usage();
	o_keytype = argv[++i];
      }
      else if (!strcmp(s, "-inisize_hints")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_impl_hints[eyedbsm::HIdx::IniSize_Hints] = atoi(s);
      }
      else if (!strcmp(s, "-iniobjcnt_hints")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_impl_hints[eyedbsm::HIdx::IniObjCnt_Hints] = atoi(s);
      }
      else if (!strcmp(s, "-xcoef_hints")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_impl_hints[eyedbsm::HIdx::XCoef_Hints] = atoi(s);
      }
      else if (!strcmp(s, "-szmax_hints")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	o_impl_hints[eyedbsm::HIdx::SzMax_Hints] = atoi(s);
      }
      else if (!strcmp(s, "-data_grouped_by_key")) {
	if (i == argc - 1)
	  return o_index_usage();
	s = argv[++i];
	if (!eyedblib::is_number(s))
	  return o_index_usage();
	int grouped = atoi(s);
	if (grouped != 0 && grouped != 1 && grouped != 2 && grouped != 4)
	  return o_index_usage();
	o_impl_hints[eyedbsm::HIdx::DataGroupedByKey_Hints] = grouped;
      }
      else
	return o_index_usage();
    }
    else
      return o_index_usage();
  }

  if (o_trsbegin())
    return 1;

  if ((o_reimplement_H && o_reimplement_B) ||
      (o_reimplement_H && o_simulate) ||
      (o_reimplement_B && o_simulate))
    return o_index_usage();

  return 0;
}
