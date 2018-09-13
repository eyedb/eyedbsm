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

#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

#include <eyedblib/machtypes.h>
#include <eyedblib/filelib.h>
#include <eyedblib/butils.h>
#include <transaction.h>
#include <eyedbsm_p.h>
#include <hashtable.h>
#include <lock.h>
#include <eyedblib/iassert.h>
#include <kern.h>
#include <kern_p.h>

using namespace eyedbsm;

#define PROG "eyedbsmtool"

static const TransactionParams params_X = {
  TransactionOn,
  DatabaseW,
  RecoveryFull,
  0,
  0,
  1
};

static const TransactionParams params_X_notrans = {
  TransactionOff,
  DatabaseW,
  RecoveryOff,
  0,
  0,
  1
};

#define sm_CHECK(S, MSG) (statusPrint(S, MSG) ? 1 : 0)

#define BEGIN(s) \
   s = transactionBegin(dbh, (const TransactionParams *)0); \
   if (s) return sm_CHECK(s, "transaction begin")

#define BEGIN_X(s) \
  s = transactionBegin(dbh, &params_X);					\
  if (s) {if (s->err == LOCK_TIMEOUT) {fprintf(stderr, "cannot acquire exclusive access on database %s\n", argv[0]);} return sm_CHECK(s, "transaction begin"); }

#define BEGIN_X_NOTRANS(s) \
  s = transactionBegin(dbh, &params_X_notrans);				\
  if (s) {if (s->err == LOCK_TIMEOUT) {fprintf(stderr, "cannot acquire exclusive access on database %s\n", argv[0]);} return sm_CHECK(s, "transaction begin"); }

#define END(s, msg) \
   if (getenv("_ABORT_") || s) transactionAbort(dbh); \
   else transactionCommit(dbh); \
   return sm_CHECK(s, msg)

static const char* abs_dbfile(const char* dbfile)
{
  if (*dbfile == '/') {
    return dbfile;
  }
  static std::string dbfile_str;
  static std::string topdir;
  if (topdir.length() == 0) {
    char buf[2048]; 
    getcwd(buf, sizeof buf);
    topdir = buf;
  }
  dbfile_str = topdir + "/" + dbfile;
  return dbfile_str.c_str();
}

#define OPEN(DBFILE, MODE) \
  if (sm_CHECK(dbOpen(abs_dbfile(DBFILE), MODE, 0, 0, 0, &dbh),	\
       "database open")) \
    return 1

#define sm_OPEN(DBFILE, MODE) \
  if (sm_CHECK(ESM_dbOpen(abs_dbfile(DBFILE), MODE, 0, 0, 0, 0, 0, 0, &sm_dbh), \
       "database open")) \
    return 1; \
  DbHeader _dbh_(DBSADDR(sm_dbh)); \
  sm_h = &_dbh_

#define sm_SHMH_INIT(DBFILE, WRITE) \
  if (shmh_init(DBFILE, WRITE)) { \
     fprintf(stderr,"cannot open database file '%s'\n", DBFILE); \
     return 1; \
   }

#define sm_XL(x) (((x) == LockX) ? "X" : ((x) == LockS ? "S" : "SX"))
#define sm_LOCK()   sm_locked = 1; MUTEX_LOCK_VOID(sm_mutex, MAXCLS)
#define sm_UNLOCK() MUTEX_UNLOCK(sm_mutex, MAXCLS); sm_locked = 0

static DbHandle *sm_dbh;
static DbHandle *dbh;
static DbShmHeader *sm_shmh;
static DbHeader *sm_h;
static XMHandle *sm_xmh;
static int sm_fdshm;
static int unsigned sm_shmsize;
static const char *sm_shmfile;
static Mutex *sm_mutex;
static int sm_locked;

static unsigned int
shmsize_get(int shmfd)
{
  struct stat stat;

  if (fstat(shmfd, &stat) < 0)
    return 0;

  return stat.st_size;
}

static int
shmh_init(const char *dbfile, Boolean write)
{
  int fddb;
  caddr_t shm_addr;
  Status status;

  if ((fddb = open(dbfile, write ? O_RDWR : O_RDONLY)) < 0)
    return 1;

  close(fddb);

  sm_shmfile = shmfileGet(dbfile);

  if ((sm_fdshm = open(shmfileGet(dbfile), write ? O_RDWR : O_RDONLY)) < 0)
    return 1;

  sm_shmsize = shmsize_get(sm_fdshm);

  shm_addr = (caddr_t)mmap(0, sm_shmsize, PROT_READ|(write ? PROT_WRITE : 0),
			   MMAP_MMAP_FLAGS, sm_fdshm, 0);

  if (shm_addr == MAP_FAILED)
    {
      fprintf(stderr, PROG ": cannot map file '%s' for %s.\n", sm_shmfile,
	      (write ? "reading" : "writing"));
      return 1;
    }

  sm_shmh = (DbShmHeader *)shm_addr;
  sm_xmh = XMOpen(shm_addr + SHM_HEADSIZE, 0);
  //sm_mutex = &sm_shmh->mtx.mp[TRS];

  return 0;
}

#define M_DATABASE    0x01000
#define M_DATAFILE    0x02000
#define M_DATASPACE   0x04000
#define M_SHMEM       0x08000
#define M_MUTEX       0x10000
#define M_TRANSACTION 0x20000
#define M_OID         0x40000

enum mAction {
  mDatabaseCreate = 1,
  mDatabaseDelete,
  mDatabaseMove,
  mDatabaseCopy,
  mDatabaseSetobjmax,
  mDatabaseDisplay,
  mDatafileCreate,
  mDatafileMove,
  mDatafileResize,
  mDatafileDelete,
  mDatafileDefragment,
  mDatafileDisplay,
  mDatafileRename,
  mDataspaceCreate,
  mDataspaceUpdate,
  mDataspaceDelete,
  mDataspaceRename,
  mDataspaceDisplay,
  mDataspaceSetDefault,
  mDataspaceGetDefault,
  mDataspaceGetCurDat,
  mDataspaceSetCurDat,
  mShmemResize,
  mShmemDspmap,
  mShmemDspsize,
  mShmemCheck,
  mShmemCleanup,
  mMutexUnlock,
  mMutexReset,
  mMutexDisplay,
  mTransactionDisplay,
  mTransactionDspoidlock,
  mTransactionDsphead,
  mTransactionAbrtInact,
  mOidMoveDat,
  mOidMoveDsp,
  mOidDspList,
  mOidDspCount,
  mOidGetCurLastNx,
  mOidSetLastNx,
  mOidSetCurNx,
  mOidSyncCurLastNx,
  mOidDspLoca,
  mOidDspLocaStats
};

static const char *prog;

static int
usage(unsigned int mode = 0)
{
  if (!mode || mode == mDatabaseCreate || (mode & M_DATABASE))
    fprintf(stderr, "%s database create DBFILE DBID OBJMAX {DATAFILE NAME MAXSIZE (suffix by KB, MB or GB) linkmap|SIZESLOT phy|log}...\n", prog);

  if (!mode || mode == mDatabaseDelete || (mode & M_DATABASE))
    fprintf(stderr, "%s database delete DBFILE\n", prog);

  if (!mode || mode == mDatabaseMove || (mode & M_DATABASE))
    fprintf(stderr, "%s database move DBFILE NEW_DBFILE NEW_DATAFILES...\n", prog);

  if (!mode || mode == mDatabaseCopy || (mode & M_DATABASE))
    fprintf(stderr, "%s database copy DBFILE NEW_DBFILE NEW_DATAFILES...\n", prog);

  if (!mode || mode == mDatabaseSetobjmax || (mode & M_DATABASE))
    fprintf(stderr, "%s database set:objmax DBFILE NEW_OBJMAX\n", prog);

  if (!mode || mode == mDatabaseDisplay || (mode & M_DATABASE))
    fprintf(stderr, "%s database display DBFILE\n", prog);
 
  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mDatafileCreate || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile create DBFILE FILE NAME MAXSIZE (suffix by KB, MB or GB) linkmap|SIZESLOT log|phy\n", prog);

  if (!mode || mode == mDatafileMove || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile move DBFILE DATAFILE NEW_DATAFILE\n", prog);

  if (!mode || mode == mDatafileResize || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile resize DBFILE DATAFILE NEW_MAXSIZE (suffix by KB, MB or GB)\n", prog);

  if (!mode || mode == mDatafileDelete || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile delete DBFILE DATAFILE\n", prog);

  if (!mode || mode == mDatafileDefragment || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile defragment DBFILE DATAFILE\n", prog);

  if (!mode || mode == mDatafileDisplay || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile display DBFILE [DATAFILES...]\n", prog);

  if (!mode || mode == mDatafileRename || (mode & M_DATAFILE))
    fprintf(stderr, "%s datafile rename DBFILE DATAFILE NAME\n", prog);

  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mDataspaceCreate || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace create DBFILE DATASPACE DATAFILES...\n", prog);

  if (!mode || mode == mDataspaceUpdate || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace update DBFILE DATASPACE DATAFILES...\n", prog);

  if (!mode || mode == mDataspaceDelete || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace delete DBFILE DATASPACE\n", prog);

  if (!mode || mode == mDataspaceRename || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace rename DBFILE DATASPACE NEW_DATASPACE\n", prog);

  if (!mode || mode == mDataspaceDisplay || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace display DBFILE [DATASPACES...]\n", prog);

  if (!mode || mode == mDataspaceSetDefault || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace set:default DBFILE DATASPACE\n", prog);

  if (!mode || mode == mDataspaceGetDefault || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace get:default DBFILE\n", prog);

  if (!mode || mode == mDataspaceSetCurDat || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace set:curdat DBFILE DATASPACE CURDAT\n", prog);

  if (!mode || mode == mDataspaceGetCurDat || (mode & M_DATASPACE))
    fprintf(stderr, "%s dataspace get:curdat DBFILE DATASPACE\n", prog);

  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mShmemResize || (mode & M_SHMEM))
    fprintf(stderr, "%s shmem resize DBFILE NEW_MAXSIZE (in KB)\n", prog);

  if (!mode || mode == mShmemDspmap || (mode & M_SHMEM))
    fprintf(stderr, "%s shmem display:map DBFILE\n", prog);

  if (!mode || mode == mShmemDspsize || (mode & M_SHMEM))
    fprintf(stderr, "%s shmem display:size DBFILE\n", prog);

  if (!mode || mode == mShmemCheck || (mode & M_SHMEM))
    fprintf(stderr, "%s shmem check DBFILE\n", prog);

  if (!mode || mode == mShmemCleanup || (mode & M_SHMEM))
    fprintf(stderr, "%s shmem cleanup DBFILE\n", prog);

  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mMutexUnlock || (mode & M_MUTEX))
    fprintf(stderr, "%s mutex unlock DBFILE\n", prog);

  if (!mode || mode == mMutexReset || (mode & M_MUTEX))
    fprintf(stderr, "%s mutex reset DBFILE\n", prog);

  if (!mode || mode == mMutexDisplay || (mode & M_MUTEX))
    fprintf(stderr, "%s mutex display DBFILE\n", prog);

  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mTransactionDisplay || (mode & M_TRANSACTION))
    fprintf(stderr, "%s transaction display [SERVER_PID] DBFILE\n", prog);

  if (!mode || mode == mTransactionDspoidlock || (mode & M_TRANSACTION))
    fprintf(stderr, "%s transaction display:lockedoids DBFILE\n", prog);

  if (!mode || mode == mTransactionDsphead || (mode & M_TRANSACTION))
    fprintf(stderr, "%s transaction display:header [SERVER_PID] DBFILE\n", prog);

  if (!mode || mode == mTransactionAbrtInact || (mode & M_TRANSACTION))
    fprintf(stderr, "%s transaction abort:inactive DBFILE\n", prog);

  if (!mode)
    fprintf(stderr, "\n");

  if (!mode || mode == mOidMoveDat || (mode & M_OID))
    fprintf(stderr, "%s oid move:datafile DBFILE FROM_DATAFILE TO_DATAFILE\n", prog);

  if (!mode || mode == mOidMoveDsp || (mode & M_OID))
    fprintf(stderr, "%s oid move:dataspace DBFILE FROM_DATASPACE TO_DATASPACE\n", prog);

  if (!mode || mode == mOidDspList || (mode & M_OID))
    fprintf(stderr, "%s oid display:list DBFILE [DATAFILE]\n", prog);

  if (!mode || mode == mOidDspCount || (mode & M_OID))
    fprintf(stderr, "%s oid display:count DBFILE [DATAFILE]\n", prog);

  if (!mode || mode == mOidGetCurLastNx || (mode & M_OID))
    fprintf(stderr, "%s oid get:curlastnx DBFILE\n", prog);

  if (!mode || mode == mOidSetLastNx || (mode & M_OID))
    fprintf(stderr, "%s oid set:lastnx DBFILE LASTNX\n", prog);

  if (!mode || mode == mOidSetCurNx || (mode & M_OID))
    fprintf(stderr, "%s oid set:curnx DBFILE CURNX\n", prog);

  if (!mode || mode == mOidSyncCurLastNx || (mode & M_OID))
    fprintf(stderr, "%s oid sync:curlastnx DBFILE\n", prog);

  if (!mode || mode == mOidDspLoca || (mode & M_OID))
    fprintf(stderr, "%s oid display:loca DBFILE [DATAFILE]\n", prog);

  if (!mode || mode == mOidDspLoca || (mode & M_OID))
    fprintf(stderr, "%s oid display:locastats DBFILE [DATAFILE]\n", prog);

  return 1;
}

static bool is_integer(const char* v)
{
  while (char c = *v++) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  return true;
}

static unsigned int get_datafile_size(mAction action, const char* str) {
  char* maxsize_str = strdup(str);
  size_t len = strlen(maxsize_str);
  size_t coef = 1;
  if (len > 3) {
    if (!strcmp(&maxsize_str[len-2], "KB")) {
      maxsize_str[len-2] = 0;
      coef = 1;
    } else if (!strcmp(&maxsize_str[len-2], "MB")) {
      maxsize_str[len-2] = 0;
      coef = ONE_K;
    } else if (!strcmp(&maxsize_str[len-2], "GB")) {
      maxsize_str[len-2] = 0;
      coef = ONE_K*ONE_K;
    }
  }
  
  if (!is_integer(maxsize_str)) {
    fprintf(stderr, "invalid datafile size [%s]\n", str);
    usage(action);
    exit(1);
  }
  return atoll(maxsize_str) * coef;
}

static int
databacreate_realize(int argc, char *argv[])
{
  if (argc < 4 || ((argc - 3) % 5))
    return usage(mDatabaseCreate);

  DbCreateDescription dbc;

  char *dbfile = argv[0];
  dbc.ndat = 0;
  dbc.dbid = atoi(argv[1]);
  dbc.nbobjs = atoi(argv[2]);

  for (int i = 3; i < argc; i += 5) {
    strcpy(dbc.dat[dbc.ndat].file, argv[i]);
    strcpy(dbc.dat[dbc.ndat].name, argv[i+1]);

    dbc.dat[dbc.ndat].maxsize = get_datafile_size(mDatabaseCreate, argv[i+2]);
    if (!strcmp(argv[i+3], "linkmap")) {
      dbc.dat[dbc.ndat].mtype = LinkmapType;
    } else {
      dbc.dat[dbc.ndat].mtype = BitmapType;
      dbc.dat[dbc.ndat].sizeslot = atoi(argv[i+3]);
    }
    if (!strcmp(argv[i+4], "log")) {
      dbc.dat[dbc.ndat].dtype = LogicalOidType;
    } else if (!strcmp(argv[i+4], "phy")) {
      dbc.dat[dbc.ndat].dtype = PhysicalOidType;
    } else {
      return usage(mDatabaseCreate);
    }
    dbc.ndat++;
  }	  
  
  return sm_CHECK(dbCreate(dbfile, V3_VERSION, &dbc, 0, 0), "database create");
}

static int
databadelete_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mDatabaseDelete);
  return sm_CHECK(dbDelete(argv[0]), "database delete");
}

static int
databamove_copy_realize(int argc, char *argv[], Boolean move)
{
  if (argc < 2) {
    return usage(move ? mDatabaseMove : mDatabaseCopy);
  }

  DbMoveDescription dbc;
  char *dbfile = argv[0];
  strcpy(dbc.dbfile, argv[1]);
  DbCreateDescription *dcr = &dbc.dcr;
  if (argc == 2) {
    DbInfoDescription info;
    dbInfo(dbfile, &info);
    *dcr = info;
  } else {
    dcr->ndat = 0;
    
    for (int i = 2; i < argc; i++) {
      strcpy(dcr->dat[dcr->ndat].file, argv[i]);
      dcr->ndat++;
    }	  
  }
  
  return sm_CHECK((move ? dbMove(dbfile, &dbc) : dbCopy(dbfile, &dbc)),
	       (move ? "database move" : "database copy"));
}

static int
databasetobjmax_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDatabaseSetobjmax);

  sm_OPEN(argv[0], VOLRW);
  return sm_CHECK(objectNumberSet(sm_dbh, atoi(argv[1])), "database setobjmax");
}

static int
sm_get_refcount()
{
  return sm_shmh->trs_hdr.tr_cnt;
}

static int
shmem_check_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mShmemCheck);

  sm_SHMH_INIT(argv[0], True);

  if (!mutexLock(sm_mutex, 0))
    {
      printf("Database shmem %s is in a coherent state\n", argv[0]);
      mutexUnlock(sm_mutex, 0);
      return 0;
    }
    
  printf("Database shmem %s is in an incoherent state. You must perform:\n"
	 "eyedbsmtool shmem cleanup %s\n", argv[0], argv[0]);
  return 1;
}

static int
shmem_cleanup_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mShmemCleanup);

  int cnt = 0;

  printf("\nDo you really want to cleanup the shmem for the "
	  "database '%s'? ", argv[0]);

  for (;;)
    {
      char s[128];
      fgets(s, sizeof s, stdin);
      s[strlen(s)-1] = 0;
      if (!strcasecmp(s, "y") || !strcasecmp(s, "yes"))
	{
	  Status status = dbCleanup(argv[0]);
	  if (status){
	    statusPrint(status, "");
	    return 1;
	  }
	  break;
	}
      else if (!strcasecmp(s, "n") || !strcasecmp(s, "no"))
	{
	  printf("\nOperation aborted by user request.\n");
	  break;
	}
      else
	printf("Please, answer `y[es]' or `n[o]'? ");
    }

  return 0;
}

#define OFFSET(T, X) (unsigned long)(&((T *)0)->X)
//#define DSPSIZEOF(T) printf("sizeof " #T ": %d\n", sizeof(T))
//#define DSPOFFSET(T, X) printf("offset of " #T "::" #X ": %d\n", OFFSET(T, X))
#define DSPSIZEOF(T) printf("#define " #T "_SIZE %d\n", sizeof(T))
#define DSPOFFSET(T, X) printf("#define " #T "_" #X "_OFF %d\n", OFFSET(T, X))

static void
display_structs()
{
#if 0
  DSPSIZEOF(DatafileDesc);
  DSPSIZEOF(DataspaceDesc);
  DSPSIZEOF(DbHeader);
  DSPSIZEOF(MapHeader);
  DSPSIZEOF(BitmapHeader);
  DSPSIZEOF(LinkmapHeader);
  DSPSIZEOF(MapStat);

  DSPOFFSET(MapStat, u);
#endif

#if 0
  DSPSIZEOF(MapHeader);
  DSPSIZEOF(DatafileDesc);
  DSPSIZEOF(DataspaceDesc);
  DSPSIZEOF(DbHeader);
  DSPSIZEOF(DbRootEntry);
  //DSPSIZEOF(DbRootEntries);
  printf("\n");

  DSPOFFSET(MapHeader, mtype);
  DSPOFFSET(MapHeader, sizeslot);
  DSPOFFSET(MapHeader, pow2);
  DSPOFFSET(MapHeader, nslots);

  DSPOFFSET(MapHeader, nbobjs);
  DSPOFFSET(MapHeader, mstat);
  DSPOFFSET(MapHeader, mstat.mtype);

  DSPOFFSET(MapHeader, u.bmh);

  DSPOFFSET(MapHeader, u.bmh.slot_cur);
  DSPOFFSET(MapHeader, u.bmh.slot_lastbusy);
  DSPOFFSET(MapHeader, u.bmh.retry);

  DSPOFFSET(MapHeader, mstat.u.bmstat);
  DSPOFFSET(MapHeader, mstat.u.bmstat.obj_count);
  DSPOFFSET(MapHeader, mstat.u.bmstat.busy_slots);
  DSPOFFSET(MapHeader, mstat.u.bmstat.busy_size);
  DSPOFFSET(MapHeader, mstat.u.bmstat.hole_size);

  DSPOFFSET(MapHeader, mstat.u.lmstat);
  DSPOFFSET(MapHeader, mstat.u.lmstat.nfreecells);

  DSPOFFSET(MapHeader, u.lmh);
  DSPOFFSET(MapHeader, u.lmh.firstcell);

  printf("\n");

  DSPOFFSET(DatafileDesc, file);
  DSPOFFSET(DatafileDesc, name);
  DSPOFFSET(DatafileDesc, __maxsize);
  DSPOFFSET(DatafileDesc, mp);
  DSPOFFSET(DatafileDesc, __lastslot);
  DSPOFFSET(DatafileDesc, __dspid);

  printf("\n");

  DSPOFFSET(DataspaceDesc, name);
  DSPOFFSET(DataspaceDesc, __cur);
  DSPOFFSET(DataspaceDesc, __ndat);
  DSPOFFSET(DataspaceDesc, __datid);

  printf("\n");

  DSPOFFSET(DbRootEntry, key);
  DSPOFFSET(DbRootEntry, data);

  printf("\n");

  DSPOFFSET(DbHeader, __magic);
  DSPOFFSET(DbHeader, __dbid);
  DSPOFFSET(DbHeader, state);
  DSPOFFSET(DbHeader, __guest_uid);
  DSPOFFSET(DbHeader, __prot_uid_oid);
  DSPOFFSET(DbHeader, __prot_list_oid);
  DSPOFFSET(DbHeader, __prot_lock_oid);
  DSPOFFSET(DbHeader, shmfile);
  DSPOFFSET(DbHeader, __nbobjs);
  DSPOFFSET(DbHeader, __ndat);
  DSPOFFSET(DbHeader, dat);
  DSPOFFSET(DbHeader, __ndsp);
  DSPOFFSET(DbHeader, dsp);
  DSPOFFSET(DbHeader, __def_dspid);
  DSPOFFSET(DbHeader, vre);
  DSPOFFSET(DbHeader, __lastidxbusy);
  DSPOFFSET(DbHeader, __curidxbusy);
  DSPOFFSET(DbHeader, __lastidxblkalloc);
  DSPOFFSET(DbHeader, __lastnsblkalloc);
#endif

#if 0
  DSPSIZEOF(HIdx::_Idx);
  DSPOFFSET(HIdx::_Idx, key_count);
  DSPOFFSET(HIdx::_Idx, dspid);
  DSPOFFSET(HIdx::_Idx, keytype);
  DSPOFFSET(HIdx::_Idx, keysz);
  DSPOFFSET(HIdx::_Idx, datasz);
  
  DSPSIZEOF(MutexP);

  DSPOFFSET(MutexP, u.key);
  DSPOFFSET(MutexP, xid);
  DSPOFFSET(MutexP, wait_cnt);
  DSPOFFSET(MutexP, pcond);

  DSPSIZEOF(DbShmHeader);
  DSPOFFSET(DbShmHeader, version);
  DSPOFFSET(DbShmHeader, xid);
  DSPOFFSET(DbShmHeader, hostid);
  DSPOFFSET(DbShmHeader, arch);
  DSPOFFSET(DbShmHeader, lock);
  DSPOFFSET(DbShmHeader, trs_hdr);
  DSPOFFSET(DbShmHeader, mtx);
  DSPOFFSET(DbShmHeader, stat);
#endif
}

static int
databadisplay_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mDatabaseDisplay);

  sm_OPEN(argv[0], VOLREAD);
  sm_SHMH_INIT(argv[0], False);

  printf(" Database ID #%d\n", sm_dbh->vd->dbid);
  printf(" Version %d\n", x2h_u32(sm_shmh->version));
  printf(" Max Object Count %u\n", x2h_u32(sm_h->__nbobjs()));
  printf(" Datafile Count %u\n", x2h_u32(sm_h->__ndat()));
  printf(" Reference Count %u\n", sm_get_refcount());
  if (sm_shmh->hostid || *sm_shmh->hostname)
    printf(" Host Owner \"%s\", Host ID %p\n", 
	    sm_shmh->hostname, x2h_u32(sm_shmh->hostid));
  
  printf("\n");
  printf(" Total Access Number   %d\n", x2h_u32(sm_shmh->stat.total_db_access_cnt));
  printf(" Current Access Number %d\n", x2h_u32(sm_shmh->stat.current_db_access_cnt));
  printf(" Transaction Started   %d\n", x2h_u32(sm_shmh->stat.tr_begin_cnt));
  printf(" Transaction Committed %d\n", x2h_u32(sm_shmh->stat.tr_commit_cnt));
  printf(" Transaction Aborted   %d\n", x2h_u32(sm_shmh->stat.tr_abort_cnt));

  return 0;
}

static int
databarealize(int argc, char *argv[])
{
  const char *action = argv[0];
  
  if (!action)
    return usage(M_DATABASE);

  if (!strcmp(action, "create"))
    return databacreate_realize(argc-1, &argv[1]);

  if (!strcmp(action, "delete"))
    return databadelete_realize(argc-1, &argv[1]);

  if (!strcmp(action, "move"))
    return databamove_copy_realize(argc-1, &argv[1], True);

  if (!strcmp(action, "copy"))
    return databamove_copy_realize(argc-1, &argv[1], False);

  if (!strcmp(action, "set:objmax"))
    return databasetobjmax_realize(argc-1, &argv[1]);

  if (!strcmp(action, "display"))
    return databadisplay_realize(argc-1, &argv[1]);

  return usage(M_DATABASE);
}

static int
datafile_create_realize(int argc, char *argv[])
{
  if (argc != 6)
    return usage(mDatafileCreate);

  DatType dtype;

  if (!strcmp(argv[5], "log"))
    dtype = LogicalOidType;
  else if (!strcmp(argv[5], "phy"))
    dtype = PhysicalOidType;
  else
    return usage(mDatafileCreate);
    
  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  MapType mtype;
  unsigned int sizeslot;
  if (!strcmp(argv[4], "linkmap")) {
    mtype = LinkmapType;
  } else {
    mtype = BitmapType;
    sizeslot = atoi(argv[4]);
  }

  s = datCreate(dbh, argv[1], argv[2], get_datafile_size(mDatafileCreate, argv[3]), mtype, sizeslot, dtype, 0, 0);
  END(s, "datafile create");
}

static int
datafile_resize_realize(int argc, char *argv[])
{
  if (argc != 3)
    return usage(mDatafileResize);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);
  s = datResize(dbh, argv[1], get_datafile_size(mDatafileResize, argv[2]));
  END(s, "datafile resize");
}

static int
datafile_move_realize(int argc, char *argv[])
{
  if (argc != 3)
    return usage(mDatafileMove);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = datMove(dbh, argv[1], argv[2]);
  END(s, "datafile move");
}

static int
datafile_delete_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDatafileDelete);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  Boolean force = getenv("DATDELFORCE") != NULL ? True : False;
  s = datDelete(dbh, argv[1], force);
  END(s, "datafile delete");
}

static int
datafile_defragment_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDatafileDefragment);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X_NOTRANS(s);
  s = datDefragment(dbh, argv[1], 0, 0);
  END(s, "datafile defragment");
}

static int
datafile_rename_realize(int argc, char *argv[])
{
  if (argc != 3)
    return usage(mDatafileRename);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = datRename(dbh, argv[1], argv[2]);
  END(s, "datafile rename");
}

static short
datafile_get(const char *dat)
{
  int ndat = x2h_u32(sm_h->__ndat());
  for (int i = 0; i < ndat; i++)
    if (!strcmp(dat, sm_h->dat(i).file()))
      return i;

  return -1;
}

static void
datafile_display_fragmentation(short datid)
{
  DatafileDesc dat = sm_h->dat(datid);
  MapHeader *xmp = dat.mp();
  x2h_prologue(xmp, mp);
  char *mapaddr = sm_dbh->vd->dmp_addr[datid];
  char *s, *start, *end;
  int nfrags, nbusy, ns;

  start = mapaddr;
  end = mapaddr + (mp->u_bmh_slot_lastbusy() / 8);
  nfrags = 0;
  ns = 0;

  for (s = start; s <= end; s++)
    {
      char v = *s;
      int b;

      for (b = 7; b >= 0; b--, ns++)
	{
	  if (!(v & (1 << b)))
	    nfrags++;

	  if (ns >= mp->u_bmh_slot_lastbusy())
	    break;
	}
    }

  if (nfrags > mp->u_bmh_slot_lastbusy())
    nfrags = mp->u_bmh_slot_lastbusy();

  printf("   Fragmentation        %u/%u slots [%2.2f%%]\n",
	 nfrags, mp->u_bmh_slot_lastbusy(),
	 (mp->u_bmh_slot_lastbusy() ?
	  (double)(100.*nfrags)/mp->u_bmh_slot_lastbusy() : 0));
}	

static void
display_size(unsigned long long sz)
{
  printf("%lldB", sz);
  sz /= ONE_K;
  if (sz)
    {
      printf(", %lldKB", sz);
      sz /= ONE_K;
      if (sz)
	{
	  printf(", ~%lldMB", sz);
	  sz /= ONE_K;
	  if (sz)
	    printf(", ~%lldGB", sz);
	}
    }
  printf("\n");
}

static void
datafile_display_info(short datid, DatafileDesc *dfd)
{
  MapHeader *xmp = dfd->mp();
  x2h_prologue(xmp, mp);
  
  printf(" Datafile #%d\n", datid);
  if (!*dfd->file())
    {
      printf("   <empty slot>\n");
      return;
    }

  unsigned long Ksz;
  printf("   File                 %s\n", dfd->file());
  printf("   Name                 %s\n",
	 (*dfd->name() ? dfd->name() : "<unnamed>"));
  if (getDatType(sm_h, datid) == LogicalOidType)
    printf("   Oid Type             Logical\n");
  else
    printf("   Oid Type             Physical\n");

  short dspid = getDataspace(sm_h, datid);
  if (dspid != DefaultDspid)
    printf("   Dataspace            %s\n", sm_h->dsp(dspid).name());
  printf("   Maximum Size         ");
  display_size((unsigned long long)x2h_u32(dfd->__maxsize())*ONE_K);
  if (mp->mtype() == BitmapType)
    {
      printf("   Bitmap Allocator\n");
      printf("     Max Slots          %u\n", mp->nslots());
      printf("     Slot Size          %u\n\n", mp->sizeslot());
    }
  else
    printf("   Linkmap Allocator\n\n");

  printf("   Object Number        %u\n", mp->mstat_u_bmstat_obj_count());
  printf("   Total Object Size    ");
  display_size(mp->mstat_u_bmstat_busy_size());
      
  printf("   Average Object Size  ");
  display_size(mp->mstat_u_bmstat_obj_count() ?
	       mp->mstat_u_bmstat_busy_size()/mp->mstat_u_bmstat_obj_count() : 0);

  printf("\n");
  printf("   Busy Slots           %u\n", mp->mstat_u_bmstat_busy_slots());
  printf("   Last Busy Slot       %u\n", mp->u_bmh_slot_lastbusy());
  printf("   Last Volume Slot     %u\n", x2h_u32(dfd->__lastslot()));
  printf("   Busy Slot Size       ");
  display_size((unsigned long long)mp->mstat_u_bmstat_busy_slots() * mp->sizeslot());

  printf("   Total File Size      ");
  display_size((unsigned long long)mp->u_bmh_slot_lastbusy() * mp->sizeslot());
	 
  printf("   Current Slot Pointer %u\n", mp->u_bmh_slot_cur());
  printf("   Defragmentable Size  ");
  display_size((unsigned long long)(mp->u_bmh_slot_lastbusy()+1 - mp->mstat_u_bmstat_busy_slots()) * mp->sizeslot());
  //datafile_display_fragmentation(datid);
  printf("   DMP Up Slot          %u\n", x2h_u32(sm_h->__lastnsblkalloc(datid)*BITS_PER_BYTE));
  printf("   DMP Allocated Size   ");
  display_size(x2h_u32(sm_h->__lastnsblkalloc(datid)));
  printf("   Used                 %2.2f%%\n",
	 ((double)mp->mstat_u_bmstat_busy_slots()/(double)mp->nslots())*100.);
}

static int
datafile_display_realize(int argc, char *argv[])
{
  if (argc < 1)
    return usage(mDatabaseDisplay);

  sm_OPEN(argv[0], VOLREAD);
  sm_SHMH_INIT(argv[0], False);

  int datid_cnt = argc-1;
  int i;
  char **dats;
  short *datids;
  dats = (datid_cnt ? new char*[datid_cnt] : 0);
  datids = (datid_cnt ? new short[datid_cnt] : 0);

  for (i = 0; i < datid_cnt; i++)
    dats[i] = argv[i+1];

  if (!datid_cnt) {
    unsigned int ndat = x2h_u32(sm_h->__ndat());
    printf(" Database %s contains %d Data File%s\n\n", sm_dbh->dbfile, ndat, (ndat > 1 ? "s" : ""));
  }

  for (i = 0; i < datid_cnt; i++)
    if (sm_CHECK(ESM_datCheck(sm_dbh, dats[i], &datids[i], 0),
		 "unknown datafile"))
      return 1;

  if (!datid_cnt)
    {
      unsigned int ndat = x2h_u32(sm_h->__ndat());
      for (i = 0; i < ndat; i++)
	{
	  if (i) printf("\n");
	  DatafileDesc d = sm_h->dat(i);
	  datafile_display_info(i, &d);
	}
      return 0;
    }

  for (i = 0; i < datid_cnt; i++)
    {
      if (i) printf("\n");
      DatafileDesc d = sm_h->dat(datids[i]);
      datafile_display_info(datids[i], &d);
    }

  return 0;
}

static int
datafile_realize(int argc, char *argv[])
{
  const char *action = argv[0];
  
  if (!action)
    return usage(M_DATAFILE);

  if (!strcmp(action, "create"))
    return datafile_create_realize(argc-1, &argv[1]);

  if (!strcmp(action, "resize"))
    return datafile_resize_realize(argc-1, &argv[1]);

  if (!strcmp(action, "move"))
    return datafile_move_realize(argc-1, &argv[1]);

  if (!strcmp(action, "delete"))
    return datafile_delete_realize(argc-1, &argv[1]);

  if (!strcmp(action, "defragment"))
    return datafile_defragment_realize(argc-1, &argv[1]);

  if (!strcmp(action, "display"))
    return datafile_display_realize(argc-1, &argv[1]);

  if (!strcmp(action, "rename"))
    return datafile_rename_realize(argc-1, &argv[1]);

  return usage(M_DATAFILE);
}

static int
dataspace_create_realize(int argc, char *argv[])
{
  if (argc < 3)
    return usage(mDataspaceCreate);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);
  s = dspCreate(dbh, argv[1], (const char **)&argv[2], argc-2);
  END(s, "dataspace create");
}

static int
dataspace_update_realize(int argc, char *argv[])
{
  if (argc < 3)
    return usage(mDataspaceUpdate);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = dspUpdate(dbh, argv[1], (const char **)&argv[2], argc-2, 0, DefaultDspid);
  END(s, "dataspace update");
}

static int
dataspace_delete_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDataspaceDelete);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = dspDelete(dbh, argv[1]);
  END(s, "dataspace delete");
}

static int
dataspace_rename_realize(int argc, char *argv[])
{
  if (argc != 3)
    return usage(mDataspaceRename);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);
  s = dspRename(dbh, argv[1], argv[2]);
  END(s, "dataspace rename");
}

static int
dataspace_display_info(short dspid, DataspaceDesc *dsp)
{
  if (!*dsp->name())
    return 0;

  printf(" Dataspace #%d\n", dspid);
  printf(" Name %s\n", dsp->name());
  printf(" Current datafile #%d\n", x2h_16(dsp->__datid(x2h_32(dsp->__cur()))));
  unsigned int ndat = x2h_u32(dsp->__ndat());
  for (int i = 0; i < ndat; i++) {
    printf("    Datafile #%d\n", x2h_16(dsp->__datid(i)));
    DatafileDesc _dat = sm_h->dat(x2h_16(dsp->__datid(i)));
    DatafileDesc *dat = &_dat;
    MapHeader *xmp = dat->mp();
    x2h_prologue(xmp, mp);
    if (*dat->name())
      printf("      Name     %s\n", dat->name());
    printf("      File     %s\n", dat->file());
    if (getDatType(sm_h, x2h_16(dsp->__datid(i))) == LogicalOidType)
      printf("      Oid Type Logical\n");
    else
      printf("      Oid Type Physical\n");
    printf("      Maxsize  %u\n", x2h_u32(dat->__maxsize()));
    printf("      Used     %2.2f%%\n",
	   ((double)mp->mstat_u_bmstat_busy_slots()/(double)mp->nslots())*100.);
  }

  return 1;
}

static int
dataspace_display_realize(int argc, char *argv[])
{
  if (argc < 1)
    return usage(mDataspaceDisplay);

  sm_OPEN(argv[0], VOLREAD);
  sm_SHMH_INIT(argv[0], False);

  int dspid_cnt = argc-1;
  int i;
  char **dsps;
  short *dspids;
  dsps = (dspid_cnt ? new char*[dspid_cnt] : 0);
  dspids = (dspid_cnt ? new short[dspid_cnt] : 0);

  for (i = 0; i < dspid_cnt; i++)
    dsps[i] = argv[i+1];

  if (!dspid_cnt) {
    unsigned int ndsp = x2h_u32(sm_h->__ndsp());
    printf(" Database %s contains %d Dataspace%s\n\n", sm_dbh->dbfile, ndsp, (ndsp > 1 ? "s" : ""));
  }

  for (i = 0; i < dspid_cnt; i++)
    if (sm_CHECK(ESM_dspGet(sm_dbh, dsps[i], &dspids[i]),
		 "unknown dataspace"))
      return 1;

  int n = 0;
  if (!dspid_cnt)
    {
      unsigned int ndsp = x2h_u32(sm_h->__ndsp());
      for (i = 0, n = 0; i < ndsp; i++)
	{
	  if (n) printf("\n");
	  DataspaceDesc d = sm_h->dsp(i);
	  n = dataspace_display_info(i, &d);
	}
      return 0;
    }

  for (i = 0; i < dspid_cnt; i++)
    {
      if (n) printf("\n");
      DataspaceDesc d = sm_h->dsp(dspids[i]);
      n = dataspace_display_info(dspids[i], &d);
    }

  return 0;
}

static int
dataspace_setdefault_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDataspaceSetDefault);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = dspSetDefault(dbh, argv[1]);
  END(s, "dataspace setdefault");
}

static int
dataspace_getdefault_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mDataspaceGetDefault);

  OPEN(argv[0], VOLREAD);

  short dspid;
  int r = sm_CHECK(dspGetDefault(dbh, &dspid), "dataspace getdefault");
  if (r) return r;

  printf("Dataspace default:\n");
  printf("  Dspid #%d\n", dspid);

  return 0;
}

static int
dataspace_setcurdat_realize(int argc, char *argv[])
{
  if (argc != 3)
    return usage(mDataspaceSetCurDat);

  Status s;
  OPEN(argv[0], VOLRW);
  BEGIN_X(s);

  s = dspSetCurDat(dbh, argv[1], argv[2]);
  END(s, "dataspace setcurdat");
}

static int
dataspace_getcurdat_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mDataspaceGetCurDat);

  OPEN(argv[0], VOLREAD);

  short cur;
  int r = sm_CHECK(dspGetCurDat(dbh, argv[1], &cur),
		   "dataspace getcurdat");
  if (r) return r;

  printf("Current Datafile is #%d\n", cur);

  return 0;
}

static int
dataspace_realize(int argc, char *argv[])
{
  const char *action = argv[0];
  
  if (!action)
    return usage(M_DATASPACE);

  if (!strcmp(action, "create"))
    return dataspace_create_realize(argc-1, &argv[1]);

  if (!strcmp(action, "update"))
    return dataspace_update_realize(argc-1, &argv[1]);

  if (!strcmp(action, "delete"))
    return dataspace_delete_realize(argc-1, &argv[1]);

  if (!strcmp(action, "rename"))
    return dataspace_rename_realize(argc-1, &argv[1]);

  if (!strcmp(action, "display"))
    return dataspace_display_realize(argc-1, &argv[1]);

  if (!strcmp(action, "set:default"))
    return dataspace_setdefault_realize(argc-1, &argv[1]);

  if (!strcmp(action, "get:default"))
    return dataspace_getdefault_realize(argc-1, &argv[1]);

  if (!strcmp(action, "set:curdat"))
    return dataspace_setcurdat_realize(argc-1, &argv[1]);

  if (!strcmp(action, "get:curdat"))
    return dataspace_getcurdat_realize(argc-1, &argv[1]);

  return usage(M_DATASPACE);
}

#define MINSHMSIZE   0x400000U

// 1. must be detected by configure
// 2. the amount of memory may be detected by configure also
//#define HAVE_WIDE_MEMORY_MAPPED
#undef HAVE_WIDE_MEMORY_MAPPED

#ifdef HAVE_WIDE_MEMORY_MAPPED
#define MAXSHMSIZE 0x120000000U
#else
#define MAXSHMSIZE 0x40000000U
#endif

static int
activetrans_get()
{
  TransHeader *trshd = &sm_shmh->trs_hdr;
  Transaction *trs = (Transaction *)XM_ADDR(sm_xmh, trshd->first_trs);
  int cnt = 0;

  while (trs)
    {
      if (ESM_isTransactionActive(trs))
	cnt++;
      trs = (Transaction *)XM_ADDR(sm_xmh, trs->next);
    }

  return cnt;
}

static int
shmem_resize_realize(int argc, char *argv[])
{
  if (argc != 2)
    return usage(mShmemResize);

  sm_OPEN(argv[0], VOLRW);
  sm_SHMH_INIT(argv[0], True);

  unsigned int newshmsize = (unsigned int)atoi(argv[1])*ONE_K;

  DbShmHeader dbhshm;
  int r = 1;

#ifndef NO_FILE_LOCK
  if (!filelockX(sm_dbh->vd->shmfd))
    {
      fprintf(stderr, "shmem file '%s' is in use\n", sm_shmfile);
      return 1;
    }
#endif

  if (newshmsize < MINSHMSIZE)
    fprintf(stderr, "size %u is too small (minimum is %u bytes)\n",
	   newshmsize, MINSHMSIZE);
  else if (newshmsize > MAXSHMSIZE)
    fprintf(stderr, "size %u too large (maximum is %u bytes)\n",
	    newshmsize, MAXSHMSIZE);
  else if (read(sm_fdshm, &dbhshm, sizeof(dbhshm)) < 0)
    fprintf(stderr, "cannot read shmfile '%s'\n", sm_shmfile);
  else if (dbhshm.magic != MAGIC)
    fprintf(stderr, "shmfile '%s' is not a valid EyeDB shmfile\n",
	    sm_shmfile);
  else if (sm_get_refcount()) {
    /* seems to be in used: must check for active transactions */
    int cnt = activetrans_get();
    printf("shmfile '%s' is currenly in use: "
	   "ref. count %u", sm_shmfile, sm_get_refcount());
    if (cnt)
      printf(", %d active transaction%s",
	     cnt, (cnt > 1 ? "s" : ""));
    printf("\n");
  } else if (ftruncate(sm_fdshm, newshmsize))
    fprintf(stderr, "ftruncate(\"%s\", %u) returns: '%s'\n",
	    sm_shmfile, newshmsize, strerror(errno));
  else {
    r = 0;
  }

  if (!r) {
    msync((caddr_t)sm_shmh, sm_shmsize, MMAP_SYNC_FLAGS);
    munmap((caddr_t)sm_shmh, sm_shmsize);
    sm_shmsize = newshmsize;
    sm_SHMH_INIT(argv[0], True);
    ESM_transInit(sm_dbh->vd, (char *)sm_shmh, newshmsize);
  }

  ut_file_unlock(sm_fdshm);
  return r;
}

static int
shm_dspmap_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mShmemDspmap);

  sm_SHMH_INIT(argv[0], True);
  XMCheckMemory(sm_xmh);
  return 0;
}

static int
shm_dspsize_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mShmemDspsize);

  sm_SHMH_INIT(argv[0], False);
  //  printf("Shm Size %u bytes [~ %uM]\n", sm_shmsize, sm_shmsize/(1024*1024));
  printf("%uB %uKB %uMB\n", sm_shmsize, sm_shmsize/1024, sm_shmsize/(1024*1024));

  return 0;
}

static int
shmem_realize(int argc, char *argv[])
{
  const char *action = argv[0];

  if (!action)
    return usage(M_SHMEM);

  if (!strcmp(action, "resize"))
    return shmem_resize_realize(argc-1, &argv[1]);

  if (!strcmp(action, "display:map"))
    return shm_dspmap_realize(argc-1, &argv[1]);

  if (!strcmp(action, "display:size"))
    return shm_dspsize_realize(argc-1, &argv[1]);

  if (!strcmp(action, "check"))
    return shmem_check_realize(argc-1, &argv[1]);

  if (!strcmp(action, "cleanup"))
    return shmem_cleanup_realize(argc-1, &argv[1]);

  return usage(M_SHMEM);
}

static int
mutex_display_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mMutexDisplay);

  sm_SHMH_INIT(argv[0], True);

  int lockX;

  DbLock *dblocks[] = {&sm_shmh->dblock_W, &sm_shmh->dblock_RW,
		       &sm_shmh->dblock_Wtrans};
  for (unsigned int i = 0; i < sizeof(dblocks)/sizeof(dblocks[0]); i++) {
    DbLock *dblock = dblocks[i];
    printf("  Mutex %s ", dblock->mp.mtname);
    if (dblock->mp.xid || dblock->S || dblock->X) {
      printf("Locked ");
      if (dblock->mp.xid)
	printf("by Server Pid %d ", dblock->mp.xid);
      printf("[S=%d, X=%d]\n", dblock->S, dblock->X);
    }
    else
      printf("not Locked\n");
  }

  MutexP *mt = sm_shmh->mtx.mp;
  for (unsigned i = 0; i < MTX_CNT; i++, mt++)
    {
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
      printf("  Mutex %-4s ", mt->mtname);
#else
      int r = pthread_mutex_trylock(&mt->u.mp);

      printf("  Mutex %-4s [POSIX mutex ", mt->mtname);
      if (!r)
	{
	  printf("not locked] ");
	  pthread_mutex_unlock(&mt->u.mp);
	}
      else
	printf("LOCKED] ");
#endif
      printf("[eyedbsm mutex ");
      if (mt->locked)
	printf("LOCKED");
      else
	printf("not locked");
      if (mt->xid)
	printf(" by Server Pid = %d", mt->xid);
      printf("]\n");
    }

  return 0;
}

static void
unlock_mutex_realize(int which, const char *mtname)
{
  /*
#ifdef HAVE_SEMAPHORE_POLICY_POSIX
  Status se;
  se = mutexLock(&sm_shmh->mtx.mp[which], 0);
  if (se && se->err == LOCK_TIMEOUT)
    {
      printf("unlocking mutex %s...\n", mtname);
      mutexInit(sm_dbh->vd, &sm_shmh->mtx.mp[which], mtname);
    }
  else
    mutexUnlock(&sm_shmh->mtx.mp[which], 0);
#endif
*/
}

static int
mutex_unlock_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mMutexUnlock);

  sm_SHMH_INIT(argv[0], True);

  unlock_mutex_realize(MAP, "map");
  unlock_mutex_realize(TRS, "trs");
  unlock_mutex_realize(NX,  "nx");
  unlock_mutex_realize(SLT, "slt");
  unlock_mutex_realize(LSL, "lsl");

  return 0;
}

static int
mutex_reset_realize(int argc, char *argv[])
{
  if (argc != 1)
    return usage(mMutexReset);

  sm_SHMH_INIT(argv[0], True);

  DbMutexesInit(0, sm_shmh);

  return 0;
}

static int
mutex_realize(int argc, char *argv[])
{
  const char *action = argv[0];
  
  if (!action)
    return usage(M_MUTEX);

  if (!strcmp(action, "display"))
    return mutex_display_realize(argc-1, &argv[1]);

  if (!strcmp(action, "unlock"))
    return mutex_unlock_realize(argc-1, &argv[1]);

  if (!strcmp(action, "reset"))
    return mutex_reset_realize(argc-1, &argv[1]);

  return usage(M_MUTEX);
}

static int
transowner_display(XMHandle *xmh, PObject *po)
{
  TransOwner *trs_own;
  printf("{owners=#%u [%s]", po->trs_own.trs_off, sm_XL(po->trs_own.trs_lock));

  trs_own = (TransOwner *)XM_ADDR(xmh, po->trs_own.next);

  while (trs_own)
    {
      printf(", %u [%s]", trs_own->trs_off, sm_XL(trs_own->trs_lock));
      trs_own = (TransOwner *)XM_ADDR(xmh, trs_own->next);
    }

  printf("}\n");
  return 0;
}

static void
one_transaction_display(XMHandle *xmh, TransHeader *trshd,
			Transaction *trs, Boolean all)
{
  HashTable *obj_ht;
  HashTable *trs_ht;
  int i, count;
  XMOffset *tro_poff;
  int cnt = 0;

  if (trs->trs_state == TransCOMMITING)
    {
      printf("    COMMITING...\n");
      return;
    }

  if (trs->trs_state == TransABORTING)
    {
      printf("    ABORTING...\n");
      return;
    }

  if (trs->trs_state != TransACTIVE)
    {
      printf("    STATE %d...\n", trs->trs_state);
      return;
    }

  obj_ht = (HashTable *)XM_ADDR(xmh, trshd->obj_ht);

  trs_ht = (HashTable *)XM_ADDR(xmh, trs->ht_off);

  count = trs_ht->mask + 1;

  if (!all)
    {
      printf("\n");
      return;
    }

  printf(" <<<\n");
  for (i = 0, tro_poff = &trs_ht->offs[0]; i < count; i++, tro_poff++)
    if (*tro_poff)
      {
	TRObject *tro = (TRObject *)XM_ADDR(xmh, *tro_poff);
	while (tro)
	  {
	    PObject *po = (PObject *)XM_ADDR(xmh, tro->po_off);
	      printf("    %-20s ", getOidString(&po->oid));

	    if (trs->trobj_wait == *tro_poff)
	      {
		printf("WAITING for lock %s ", sm_XL(trs->lock_wait));
		cnt--;
	      }
	    else if (tro->lockX)
	      printf("lock X ");
	    else if (tro->lockS)
	      printf("lock S ");
	    else if (tro->lockP)
	      printf("lock P ");

	    printf("[X=%d, S=%d, P=%d] ", tro->lockX, tro->lockS,
		   tro->lockP);
#ifndef EYEDBSM_USE_DATA_VMEM
	    if (tro->data) {
	      void *data = XM_ADDR(xmh, tro->data);
	      printf("[datasz=%d, mapped=%s] ", objDataSize(data),
		     objDataAll(data) ? "whole" : "partial");
		     
	    }
#endif
	    transowner_display(xmh, po);
	    tro = (TRObject *)XM_ADDR(xmh, tro->next);
	    cnt++;
	  }
      }

  if (cnt != trs->obj_cnt)
    printf("    incoherency locked objects count %d vs. %d\n",
	   cnt, trs->obj_cnt);
  printf(" >>>\n\n");
}

static void
transaction_display_realize(int server_pid, Boolean all)
{
  TransHeader *trshd;
  Transaction *trs;
  XMOffset trs_x[256];
  int cnt;

  trshd = &sm_shmh->trs_hdr;

  trs = (Transaction *)XM_ADDR(sm_xmh, trshd->first_trs);

  cnt = 0;

  /*
  if (!force)
    {
      LOCK();
    }
    */

#define SEC_PER_MIN 60
#define MIN_PER_HOUR 60
#define SEC_PER_HOUR (SEC_PER_MIN * MIN_PER_HOUR)
#define USEC_PER_SECOND 1000000
#define USEC_PER_MS        1000
  while (trs)
    {
      if (!server_pid || trs->xid == server_pid)
	{
	  printf(" Transaction #%d\n", cnt);
	  printf(" Server Pid %d\n", trs->xid);
	  printf(" Object Count %u\n", trs->obj_cnt);
	  printf(" Deleted Object Count %u\n", trs->del_obj_cnt);
	  printf(" Hash Table Entries %u\n", ((HashTable *)XM_ADDR(sm_xmh, trs->ht_off))->mask+1);
	  printf(" Created on %s\n", eyedblib::setbuftime(trs->create_time));
	  printf(" Last Access on %s\n", eyedblib::setbuftime(trs->access_time));
	  unsigned long duration = trs->access_time - trs->create_time;
	  unsigned int h = duration / (SEC_PER_HOUR * USEC_PER_SECOND);

	  unsigned int m = (duration - h * SEC_PER_HOUR * USEC_PER_SECOND) / (long)(SEC_PER_MIN * USEC_PER_SECOND);
	  unsigned int s = (duration - h * SEC_PER_HOUR * USEC_PER_SECOND - m * SEC_PER_MIN * USEC_PER_SECOND) / USEC_PER_SECOND;
	  unsigned int ms = (duration - h * SEC_PER_HOUR * USEC_PER_SECOND - m * SEC_PER_MIN * USEC_PER_SECOND - s * USEC_PER_SECOND) / USEC_PER_MS;
	  unsigned int us = (duration - h * SEC_PER_HOUR * USEC_PER_SECOND - m * SEC_PER_MIN * USEC_PER_SECOND - s * USEC_PER_SECOND - ms * USEC_PER_MS);
	  
	  printf(" Duration %02u:%02u:%02u %03u.%03ums\n", h, m, s, ms, us);
	  printf(" State %s\n",
		  (ESM_isTransactionActive(trs) ? "ACTIVE" : "INACTIVE"));
	  one_transaction_display(sm_xmh, trshd, trs, all);
	  cnt++;
	}
      trs = (Transaction *)XM_ADDR(sm_xmh, trs->next);
    }

  /*
  if (!force)
    {
      UNLOCK();
    }
    */

  if (!cnt)
    {
      if (server_pid)
	printf("No Current Transaction for Server Pid %d.\n",
		server_pid);
      else
	printf("No Current Transactions.\n");
    }
}

static int
transaction_abrtinact_realize(int argc, char *argv[], Boolean all)
{
  if (argc != 1)
    return usage(mTransactionAbrtInact);

  trace_garb_trs = True;
  OPEN(argv[0], VOLRW);
  return 0;
}

static int
transaction_display_realize(int argc, char *argv[], Boolean all)
{
  if (argc != 1 && argc != 2)
    return usage(all ? mTransactionDisplay : mTransactionDsphead);

  sm_SHMH_INIT(argv[0], True);
  transaction_display_realize((argc == 2 ? atoi(argv[1]) : 0), all);
  return 0;
}

static void
item_print(TransOwner *trs_own)
{
  Transaction *trs = (Transaction *)XM_ADDR(sm_xmh, trs_own->trs_off);
  printf("[xid=%d, lock=%s]", trs->xid, sm_XL(trs_own->trs_lock));
}

static int
transaction_dspoidlock_realize(int argc, char *argv[])
{
  int i, n;
  HashTable *obj_ht;
  TransOwner *trs_own;

  sm_SHMH_INIT(argv[0], True);

  obj_ht = (HashTable *)XM_ADDR(sm_xmh, sm_shmh->trs_hdr.obj_ht);

  for (i = 0, n = 0; i < obj_ht->mask+1; i++)
    {
      XMOffset po_off = obj_ht->offs[i];

      while (po_off)
	{
	  PObject *po = (PObject *)XM_ADDR(sm_xmh, po_off);
	  
	  printf("#%d %s, ", n, getOidString(&po->oid));
	  n++;
	  printf("lockS=%d, lockX=%d, lockSX=%d, ", po->lockS, po->lockX,
		 po->lockSX);
	  printf("state=");
	  if (po->state = Active)
	    printf("Active");
	  else if (po->state = Deleted)
	    printf("Deleted");
	  else if (po->state = Zombie)
	    printf("Zombie");
	  if (po->wait_cnt)
	    printf(", wait count=%d", po->wait_cnt);
	  printf(", transaction count=%d {", po->trs_cnt);

	  item_print(&po->trs_own);
	  trs_own = (TransOwner *)XM_ADDR(sm_xmh, po->trs_own.next);

	  while (trs_own)
	    {
	      printf(", ");
	      item_print(trs_own);
	      trs_own = (TransOwner *)XM_ADDR(sm_xmh, trs_own->next);
	    }
	  
	  printf("}\n");
	  po_off = po->next;
	}
    }

  return 0;
}

static int
transaction_realize(int argc, char *argv[])
{
  const char *action = argv[0];

  if (!action)
    return usage(M_TRANSACTION);

  if (!strcmp(action, "display"))
    return transaction_display_realize(argc-1, &argv[1], True);

  if (!strcmp(action, "display:header"))
    return transaction_display_realize(argc-1, &argv[1], False);

  if (!strcmp(action, "display:lockedoids"))
    return transaction_dspoidlock_realize(argc-1, &argv[1]);

  if (!strcmp(action, "abort:inactive"))
    return transaction_abrtinact_realize(argc-1, &argv[1], False);

  return usage(M_TRANSACTION);
}

struct PageStats {
  unsigned long long totalsize;
  unsigned long long totalsize_align;
  unsigned int totaldatpages_max; // for check
  unsigned int totalomppages_max; // for check
  unsigned int totaldmppages_max; // for check

  unsigned int totaldatpages_cnt;
  char *totaldatpages;

  unsigned int totaldmppages_cnt;
  char *totaldmppages;

  unsigned int totalomppages_cnt;
  char *totalomppages;

  unsigned int oid_cnt;
  unsigned short datid;

  PageStats() {
    totalsize = 0;
    totalsize_align = 0;

    totaldatpages_max = 0;
    totalomppages_max = 0;
    totaldmppages_max = 0;

    totaldatpages = (char *)0;
    totalomppages = (char *)0;
    totaldmppages = (char *)0;

    totaldatpages_cnt = 0;
    totalomppages_cnt = 0;
    totaldmppages_cnt = 0;

    oid_cnt = 0;
    datid = (unsigned short)-1;
  }
  
  void setDatid(short _datid) {
    this->datid = _datid;
    DatafileDesc _dfd = sm_h->dat(datid); 
    DatafileDesc *dfd = &_dfd;
    MapHeader *xmp = dfd->mp();
    x2h_prologue(xmp, mp);

    totaldatpages_max = (x2h_u32(dfd->__maxsize())*ONE_K>>pgsize_pow2)+1;
    totaldatpages = (char *)m_calloc(totaldatpages_max, 1);

    totalomppages_max = (x2h_u32(sm_h->__nbobjs())*OIDLOCSIZE>>pgsize_pow2)+1;
    totalomppages = (char *)m_calloc(totalomppages_max, 1);

    totaldmppages_max = (((x2h_u32(dfd->__maxsize())*ONE_K)/(mp->sizeslot()*8))>>pgsize_pow2)+1;
    totaldmppages = (char *)m_calloc(totaldmppages_max, 1);
  }

  void set(const ObjectLocation &objloc) {
    if (!objloc.is_valid)
      return;
    unsigned int size = objloc.size + sizeof(ObjectHeader);
    NS ns = SZ2NS(size, sm_h->dat(datid).mp());
    totalsize += size;
    totalsize_align += ns * sm_h->dat(datid).mp()->sizeslot();

    assert(objloc.dat_start_pagenum < totaldatpages_max);
    if (!totaldatpages[objloc.dat_start_pagenum])
      {
	totaldatpages[objloc.dat_start_pagenum] = 1;
	totaldatpages_cnt++;
      }

    assert(objloc.dat_end_pagenum < totaldatpages_max);
    if (!totaldatpages[objloc.dat_end_pagenum])
      {
	totaldatpages[objloc.dat_end_pagenum] = 1;
	totaldatpages_cnt++;
      }

    assert(objloc.omp_start_pagenum < totalomppages_max);
    if (!totalomppages[objloc.omp_start_pagenum])
      {
	totalomppages[objloc.omp_start_pagenum] = 1;
	totalomppages_cnt++;
      }

    assert(objloc.omp_end_pagenum < totalomppages_max);
    if (!totalomppages[objloc.omp_end_pagenum])
      {
	totalomppages[objloc.omp_end_pagenum] = 1;
	totalomppages_cnt++;
      }

    assert(objloc.dmp_start_pagenum < totaldmppages_max);
    if (!totaldmppages[objloc.dmp_start_pagenum])
      {
	totaldmppages[objloc.dmp_start_pagenum] = 1;
	totaldmppages_cnt++;
      }

    assert(objloc.dmp_end_pagenum < totaldmppages_max);
    if (!totaldmppages[objloc.dmp_end_pagenum])
      {
	totaldmppages[objloc.dmp_end_pagenum] = 1;
	totaldmppages_cnt++;
      }
    oid_cnt++;
  }
};

static int
lastnx_action_realize(int argc, char *argv[], mAction action)
{
  if ((action == mOidSetLastNx && argc != 2) ||
      (action == mOidSetCurNx && argc != 2) ||
      (action == mOidSyncCurLastNx && argc != 1) ||
      (action == mOidGetCurLastNx && argc != 1))
    return usage(action);

  sm_OPEN(argv[0], (action == mOidGetCurLastNx ? VOLREAD : VOLRW));
  sm_SHMH_INIT(argv[0], True);

  if (action == mOidGetCurLastNx) {
    printf("current nx: %u\n", x2h_u32(sm_h->__curidxbusy()));
    printf("last nx: %u\n", x2h_u32(sm_h->__lastidxbusy()));
    printf("last nx blkalloc: %u\n", x2h_u32(sm_h->__lastidxblkalloc()));
    return 0;
  }

  if (action == mOidSyncCurLastNx) {
    sm_h->__curidxbusy() = sm_h->__lastidxbusy();
    return 0;
  }

  unsigned int idxbusy = atoi(argv[1]);
  if (idxbusy <= 0)
    return usage(action);

  if (action == mOidSetCurNx) {
    sm_h->__curidxbusy() = h2x_u32(idxbusy);
    return 0;
  }

  if (x2h_u32(sm_h->__lastidxbusy()) != idxbusy) {
    if (x2h_u32(sm_h->__lastidxbusy()) > idxbusy)
      printf("\n** YOU ASK TO DECREASE lastnx PARAMETER: OPERATION STRICTLY NOT RECOMMENDED **\n");
    printf("\nDo you really want to change lastnx from %u to %u in "
	   "database '%s'? ", x2h_u32(sm_h->__lastidxbusy()), idxbusy, argv[0]);
    for (;;)
      {
	char s[128];
	fgets(s, sizeof s, stdin);
	s[strlen(s)-1] = 0;
	if (!strcasecmp(s, "y") || !strcasecmp(s, "yes"))
	  {
	    sm_h->__lastidxbusy() = h2x_u32(idxbusy);
	    break;
	  }
	else if (!strcasecmp(s, "n") || !strcasecmp(s, "no"))
	  {
	    printf("\nOperation aborted by user request.\n");
	    break;
	  }
	else
	  printf("Please, answer `y[es]' or `n[o]'? ");
      }
  }

  return 0;
}

Boolean
is_in_dsp(short datid, short datids[], int ndatids)
{
  for (int i = 0; i < ndatids; i++)
    if (datids[i] == datid)
      return True;

  return False;
}

static int
oid_move_realize(int argc, char *argv[], mAction action)
{
  if (argc != 3)
    return usage(action);

  OPEN(argv[0], VOLRW);
  short from_datid, to_datid;
  short from_dspid, to_dspid;
  short datids[MAX_DAT_PER_DSP];
  unsigned int ndatids;
  if (action == mOidMoveDat) {
    if (sm_CHECK(datCheck(dbh, argv[1], &from_datid, 0), "datafile"))
      return 1;

    if (sm_CHECK(datCheck(dbh, argv[2], &to_datid, 0), "datafile"))
      return 1;
    from_dspid = to_dspid = -1;
  }
  else {
    if (sm_CHECK(dspCheck(dbh, argv[1], &from_dspid, datids, &ndatids), "dataspace"))
      return 1;

    if (sm_CHECK(dspCheck(dbh, argv[2], &to_dspid, 0, 0), "dataspace"))
      return 1;
    from_datid = to_datid = -1;
  }

  Boolean found;
  Oid oid;
  int oid_cnt = 0;
  int oid_moved = 0;
  int oid_invalid = 0;

  Status s;
  BEGIN(s);

  if (sm_CHECK(firstOidDatGet(dbh, from_datid, &oid, &found), "first oid get"))
    return 1;

  while (found) {
    ObjectLocation objloc;
    if (sm_CHECK(objectLocationGet(dbh, &oid, &objloc),
		 "object location"))
      return 1;

    if (from_datid >= 0) {
      assert(objloc.datid == from_datid);
      if (objloc.datid == from_datid) {
	if (sm_CHECK(objectMoveDat(dbh, &oid, to_datid),
		     "moving oid"))
	  return 1;
	oid_moved++;
      }
    }
    else if (is_in_dsp(objloc.datid, datids, ndatids)) {
      if (sm_CHECK(objectMoveDsp(dbh, &oid, to_dspid),
		   "moving oid"))
	return 1;
      oid_moved++;
    }

    oid_cnt++;

    Oid newoid;
    if (sm_CHECK(nextOidDatGet(dbh, from_datid, &oid, &newoid, &found), "next oid get"))
      return 1;
    oid = newoid;
  }

  printf("%d/%d oid%s moved\n", oid_moved, oid_cnt, (oid_moved != 1 ? "s" : ""));

  END(s, "oid move");
  return 0;
}

static int
get_def_rawdata_hash_key(const void *key, unsigned int len)
{
  int x = 0;
  unsigned char *k = (unsigned char *)(key)+len-1;

  for (int i = 0; i < len; i++)
    x += *k-- << (i*8);

  return x;
}

static int test_hash = getenv("ESM_TEST_HASH") ? atoi(getenv("ESM_TEST_HASH")) : 0;
static int *hash_keys;

#define IDEAL(SZ) ((SZ) ? ((((SZ)-1)>>pgsize_pow2)+1) :  0)

static int
oid_action_realize(int argc, char *argv[], mAction action)
{
  if (action == mOidMoveDat || action == mOidMoveDsp)
    return oid_move_realize(argc, argv, action);

  if (argc != 1 && argc != 2)
    return usage(action);

  if (test_hash) {
    hash_keys = new int[test_hash+1];
    memset(hash_keys, 0, sizeof(int)*(test_hash+1));
  }

  sm_OPEN(argv[0], (action == mOidMoveDat ? VOLRW : VOLREAD));
  sm_SHMH_INIT(argv[0], True);

  Boolean found;
  Oid oid;
  short from_datid, to_datid;
  if (action == mOidMoveDat) {
    if (sm_CHECK(ESM_datCheck(sm_dbh, argv[1], &from_datid, 0), "datafile"))
      return 1;
    if (sm_CHECK(ESM_datCheck(sm_dbh, argv[2], &to_datid, 0), "datafile"))
      return 1;
  }
  else if (argc == 2) {
    if (sm_CHECK(ESM_datCheck(sm_dbh, argv[1], &from_datid, 0), "datafile"))
      return 1;
  }
  else
    from_datid = -1;

  unsigned int oid_cnt = 0;
  unsigned int oid_log_cnt = 0;
  unsigned int oid_phy_cnt = 0;
  unsigned int oid_moved = 0;
  unsigned int oid_invalid = 0;

  PageStats *page_stats;

  if (action == mOidDspLocaStats)
    {
      unsigned int ndat = x2h_u32(sm_h->__ndat());
      page_stats = new PageStats[ndat];
      for (int i = 0; i < ndat; i++)
	page_stats[i].setDatid(i);
    }

  short s_datid, e_datid;
  if (from_datid >= 0) {
    s_datid = from_datid;
    e_datid = from_datid+1;
  }
  else {
    s_datid = 0;
    e_datid = x2h_u32(sm_h->__ndat());
  }

  for (int datid = s_datid; datid < e_datid; datid++) {
    if (!isDatValid(sm_dbh, datid))
      continue;

    if (sm_CHECK(ESM_firstOidDatGet(sm_dbh, datid, &oid, &found), "first oid get"))
      return 1;

    while (found)
      {
	/*
	if (isPhy(sm_dbh, &oid))
	  printf("#%d %s %s\n", datid, getOidString(&oid), isPhy(sm_dbh, &oid)
		 ? "phy" : "log");
	*/

	ObjectLocation objloc = {0};
	if (action != mOidDspCount) {
	  if (sm_CHECK(ESM_objectLocationGet(sm_dbh, &oid, &objloc),
		       "object location"))
	    return 1;
	}

	if (action == mOidMoveDat)
	  {
	    if (objloc.datid == from_datid) {
	      if (sm_CHECK(ESM_objectMoveDatDsp(sm_dbh, &oid, to_datid, -1,
					       False, OPDefault),
			   "moving oid"))
		return 1;
	      oid_moved++;
	    }
	    oid_cnt++;
	  }
	else if (from_datid < 0 || objloc.datid == from_datid)
	  {
	    if (action == mOidDspLoca) {
	      printf("%s: %s%s datid #%d, slots [%u, %u], size %u, "
		     "dat pages [%u. %u], omp pages [%u, %u], "
		     "dmp pages [%u, %u]\n",
		     getOidString(&oid),
		     (objloc.is_valid ? "" : "*invalid* "),
		     (isPhy(sm_dbh, &oid) ? "physical" : "logical"),
		     objloc.datid,
		     objloc.slot_start_num, objloc.slot_end_num, objloc.size,
		     objloc.dat_start_pagenum, objloc.dat_end_pagenum,
		     objloc.omp_start_pagenum,
		     objloc.omp_end_pagenum,
		     objloc.dmp_start_pagenum,
		     objloc.dmp_end_pagenum);
	      oid_cnt++;
	    }
	    else if (action == mOidDspLocaStats)
	      page_stats[objloc.datid].set(objloc);
	    else if (action == mOidDspList)
	      {
		if (test_hash) {
		  hash_keys[get_def_rawdata_hash_key(&oid, sizeof(oid)) & test_hash]++;
		}
		else {
		  size_t size; // V3_API_size_t
		  if (sm_CHECK(ESM_objectSizeGet(sm_dbh, &size, DefaultLock,
						&oid, OPDefault),
			       "size get"))
		    return 1;
		  printf("%s [size=%llu]\n", getOidString(&oid), size);
		}
		oid_cnt++;
	      }
	    else if (action == mOidDspCount) {
	      oid_cnt++;
	      if (isPhy(sm_dbh, &oid))
		oid_phy_cnt++;
	      else
		oid_log_cnt++;
	    }
	  }

	Oid newoid;
	if (sm_CHECK(ESM_nextOidDatGet(sm_dbh, datid, &oid, &newoid, &found), "next oid get"))
	  return 1;
	oid = newoid;
      }
  }

  if (action == mOidDspLocaStats) {
    unsigned int ndat = x2h_u32(sm_h->__ndat());
    for (int i = 0; i < ndat; i++)
      if (from_datid < 0 || i == from_datid)
	{
	  printf("Datafile #%d\n", i);
	  printf("  Object Count   %u\n", page_stats[i].oid_cnt);
	  printf("  Size           ");
	  display_size(page_stats[i].totalsize);
	  printf("  Slot Size      ");
	  display_size(page_stats[i].totalsize_align);
	  printf("  DAT Page Count %u",
		 page_stats[i].totaldatpages_cnt);
	  printf(" (Ideal Page Count %lld, ",
		 IDEAL(page_stats[i].totalsize));
	  printf("Ideal Slot Based Page Count %lld)\n",
		 IDEAL(page_stats[i].totalsize_align));
	  //((page_stats[i].totalsize_align-1)>>pgsize_pow2)+1);
	  printf("  OMP Page Count %u",
		 page_stats[i].totalomppages_cnt);
	  printf(" (Ideal Page Count %u)\n",
		 page_stats[i].oid_cnt ?
		 ((page_stats[i].oid_cnt*OIDLOCSIZE)>>pgsize_pow2)+1 : 0);
	  /*
	    (page_stats[i].totalomppages_cnt ?
	    (((page_stats[i].totalomppages_cnt*OIDLOCSIZE)>>pgsize_pow2)+1)) : 0);
	  */
	  printf("  DMP Page Count %u",
		 page_stats[i].totaldmppages_cnt);
	  printf(" (Ideal Page Count %lld)\n",
		 (page_stats[i].totalsize_align ?
		  ((((page_stats[i].totalsize_align-1)/(sm_h->dat(i).mp()->sizeslot()*8))>>pgsize_pow2)+1) : 0));
	  printf("\n");
	}
  }
  else if (action == mOidMoveDat)
    printf("%u oid%s moved\n", oid_moved, (oid_moved != 1 ? "s" : ""));
  else if (test_hash) {
    //printf("HASH MIN %d HASH MAX %d TOTAL %d AVG %f\n", hash_min, hash_max,
    //hash_total, (float)hash_total/(oid_cnt*sizeof(Oid)));
    for (int i = 0; i <= test_hash; i++)
      printf("%d %d\n", i, hash_keys[i]);
  }
  else
    printf("%u OID%s found [%u log/%u phy]\n", oid_cnt,
	   (oid_cnt != 1 ? "s" : ""), oid_log_cnt, oid_phy_cnt);
  return 0;
}

static int
oid_realize(int argc, char *argv[])
{
  const char *action = argv[0];

  if (!action)
    return usage(M_OID);

  if (!strcmp(action, "move:datafile"))
    return oid_action_realize(argc-1, &argv[1], mOidMoveDat);

  if (!strcmp(action, "move:dataspace"))
    return oid_action_realize(argc-1, &argv[1], mOidMoveDsp);

  if (!strcmp(action, "display:list"))
    return oid_action_realize(argc-1, &argv[1], mOidDspList);

  if (!strcmp(action, "display:count"))
    return oid_action_realize(argc-1, &argv[1], mOidDspCount);

  if (!strcmp(action, "get:curlastnx"))
    return lastnx_action_realize(argc-1, &argv[1], mOidGetCurLastNx);

  if (!strcmp(action, "set:lastnx"))
    return lastnx_action_realize(argc-1, &argv[1], mOidSetLastNx);

  if (!strcmp(action, "set:curnx"))
    return lastnx_action_realize(argc-1, &argv[1], mOidSetCurNx);

  if (!strcmp(action, "sync:curlastnx"))
    return lastnx_action_realize(argc-1, &argv[1], mOidSyncCurLastNx);

  if (!strcmp(action, "display:loca"))
    return oid_action_realize(argc-1, &argv[1], mOidDspLoca);

  if (!strcmp(action, "display:locastats"))
    return oid_action_realize(argc-1, &argv[1], mOidDspLocaStats);

  return usage(M_OID);
}

int
main(int argc, char *argv[])
{
  if (sm_CHECK(init(), "se init"))
    return 1;

  // for debug
  if (getenv("EYEDBSM_DISPLAY_STRUCTS")) {
    display_structs();
    return 0;
  }

  prog = argv[0];

  const char *major = argv[1];

  if (!major)
    return usage();

  if (!strcmp(major, "database"))
    return databarealize(argc-2, &argv[2]);

  if (!strcmp(major, "datafile"))
    return datafile_realize(argc-2, &argv[2]);

  if (!strcmp(major, "dataspace"))
    return dataspace_realize(argc-2, &argv[2]);

  if (!strcmp(major, "shmem"))
    return shmem_realize(argc-2, &argv[2]);

  if (!strcmp(major, "mutex"))
    return mutex_realize(argc-2, &argv[2]);

  if (!strcmp(major, "transaction"))
    return transaction_realize(argc-2, &argv[2]);

  if (!strcmp(major, "oid"))
    return oid_realize(argc-2, &argv[2]);

  return usage();
}


