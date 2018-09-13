
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


#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <eyedblib/performer.h>
#include <eyedbsm/eyedbsm.h>
#include <eyedblib/butils.h>

extern int o_release(void);
extern int o_usage(eyedbsm::Boolean complete);
extern int o_stdusage();
enum o_FileType {
  o_Create,
  o_Read,
  o_Write,
  o_Skip
};

enum {
  o_NeedCount = -1,
  o_OidFileCount = -2
};

extern int o_init(int &argc, char *argv[],
		  o_FileType type,
		  int (*usage)() = o_stdusage,
		  int default_count = o_NeedCount);

extern int o_dbopen();
extern int o_trsbegin();
extern int o_trsend();
extern void o_bench(void (*f)(void *), void *arg);
extern void o_write_oids(const eyedbsm::Oid *oids, unsigned int count);
extern int o_fileopen(o_FileType type);

extern char *o_make_data_0(int &len, int count, int n);
extern char *o_make_data_1(int &len, int count, int n);
extern char *o_make_data_2(int &len, int count, int n);
extern char *o_make_data(const eyedbsm::Idx::KeyType &, int count, int n, int &len,
			 eyedbsm::Boolean xdr);
extern char *o_make_varstring(int n, int &len);
extern void o_trace_data(const eyedbsm::Idx::KeyType &kt, char *,
			 eyedbsm::Boolean xdr);
extern void o_idxsearch_realize(eyedbsm::Idx &idx, eyedbsm::IdxCursor &c,
				const eyedbsm::Idx::KeyType &kt,
				unsigned int &count, eyedbsm::Boolean rmv);
extern void o_wait(const char *msg, int n);
extern void o_dump_data(char *data, int sz);
extern const char *o_getOidString(const eyedbsm::Oid *);

extern eyedbsm::Idx::KeyType o_get_idxKeyType(const char *);
extern int o_index_manage(int argc, char *argv[], o_FileType &ftype,
			  int default_count = o_NeedCount);


/* database */
extern char *o_dbfile;
extern eyedbsm::DbHandle *o_dbh;

/* transaction parameters */
extern eyedbsm::TransactionParams o_params;
extern eyedbsm::LockMode o_read_lock;
extern eyedbsm::Boolean o_commit;

/* oids */
extern char *o_oidfile;
extern int o_oidfd;
extern eyedbsm::Oid *o_oids;
extern unsigned int o_count;

/* oid control */
extern eyedbsm::Boolean o_reverse;
extern int o_from;
extern int o_incr;

/* wait hints */
extern eyedbsm::Boolean o_wait_trans;
extern int o_wait_op;
extern int o_wait_timeout;

/* miscelleanous */
extern const char *o_progname;
extern eyedbsm::Boolean o_verbose;
extern int o_dspid;
extern int o_pid;
extern time_t o_stime;
extern unsigned int o_thread_cnt;
extern unsigned int o_performer_cnt;
extern eyedblib::ThreadPool *o_perf_pool;
extern unsigned int o_ntimes;
extern unsigned int o_magorder;
extern unsigned int o_keycount;
extern int o_degree;
extern const char *o_keytype;
extern int o_impl_hints[eyedbsm::HIdxImplHintsCount];
extern eyedbsm::Boolean o_fullstats;
extern eyedbsm::Boolean o_reimplement_H;
extern eyedbsm::Boolean o_reimplement_B;
extern eyedbsm::Boolean o_simulate;

typedef enum {
  o_Commit = 1,
  o_Abort,
  o_Forget
} o_TransEpilogue;
extern o_TransEpilogue o_trans_epilogue;

#define o_GETN( N) (o_reverse ? (o_count - (N) - 1) : (N))

