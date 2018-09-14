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


#ifndef _EYEDBSM_EYEDBSM_H
#define _EYEDBSM_EYEDBSM_H

#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

namespace eyedbsm {

  /**
     @addtogroup eyedbsm
     @{
  */

  static const unsigned int MAX_ROOT_KEY = 16;
  static const unsigned int MAX_ROOT_DATA = 64;
  static const unsigned int MAX_DATAFILES = 512;
  static const unsigned int MAX_DATASPACES = 512;
  static const unsigned int MAX_DAT_PER_DSP = 32;
  //static const unsigned int MAXOBJSIZE = 0x7FFFFF00UL;
  // V3_storage_size_t
  static const size_t MAXOBJSIZE = 0x7FFFFFFFFFFFFF00ULL;

  static const unsigned int Oid_DBID = 10;
  static const unsigned int Oid_UNIQUE = 22;

  static const unsigned int L_NAME = 31;

  static const unsigned int L_FILENAME = 256;

  static const unsigned int MIN_SIZE_SLOT = 8;
  static const unsigned int MAX_SIZE_SLOT = 4096;

  static const unsigned int VOLREAD = 0x100;
  static const unsigned int VOLRW = 0x200;
  static const unsigned int LOCAL = 0x004; 
  static const unsigned int NO_SHM_ACCESS = 0x008;
  static const unsigned int MAX_DBID = ((1 << (Oid_DBID))-1);
  static const unsigned int PROT_NAME = 32;

  static const unsigned long INVALID_UID = ~0UL;

  static const short DefaultDspid = (short)0x7fff;

  typedef unsigned int NS;
  //typedef size_t NS;

  class Oid {

  public:
    typedef unsigned int NX;
    typedef unsigned int DbID;
    typedef unsigned int Unique;

    static const size_t SIZE;
    static const Oid::NX INVALID_NX;
    static const Oid nullOid;

    void setNX(Oid::NX _nx) {nx = _nx;}
    Oid::NX getNX() const {return nx;}

    void setDbID(Oid::DbID _dbid) {dbid = _dbid;}
    Oid::DbID getDbID() const {return dbid;}

    void setUnique(Oid::Unique _unique) {unique = _unique;}
    Oid::Unique getUnique() const {return unique;}

  private:
    Oid::NX nx;
    unsigned int dbid:Oid_DBID, unique:Oid_UNIQUE;

  public:
    static Oid makeNullOid();
  };

  struct ObjectHeaderV2 { // V3_storage_size_t
    unsigned int unique;
    unsigned int size;
    Oid prot_oid;
  };

  struct ObjectHeaderV3 { // V3_storage_size_t
    unsigned int unique;
    size_t size;
  };

  union ObjectHeader { // V3_storage_size_t
    ObjectHeaderV2 objh_v2;
    ObjectHeaderV3 objh_v3;
  };

  enum Boolean {
    False = 0,
    True  = 1
  };

  enum MapHints {
    WholeMap = 0x111,
    SegmentMap = 0x222
  };

  struct OpenHints {
    eyedbsm::MapHints maph;
    unsigned int mapwide; /* in page; 0 if default */
    unsigned int m_mmap_flags;

    OpenHints(eyedbsm::MapHints maph = SegmentMap, unsigned int mapwide = 0) : maph(maph), mapwide(mapwide), m_mmap_flags(0U) {
    }
  };

  struct ObjectLocation {
    short datid;
    short dspid;
    eyedbsm::Boolean is_valid;
    size_t size;
    NS slot_start_num;
    NS slot_end_num;
    size_t dat_start_pagenum;
    size_t dat_end_pagenum;
    size_t omp_start_pagenum;
    size_t omp_end_pagenum;
    size_t dmp_start_pagenum;
    size_t dmp_end_pagenum;
  };
  
  enum MapType {
    BitmapType,
    LinkmapType,
    DefaultMapType = eyedbsm::BitmapType
  };

  enum DatType {
    LogicalOidType = 0x100,
    PhysicalOidType
  };

  struct Datafile {
    char file[L_FILENAME];
    char name[L_NAME+1];
    unsigned long long maxsize; /* in Kbytes */
    short mtype; /* was eyedbsm::MapType */
    unsigned int sizeslot;
    short dspid;
    int extflags;
    short dtype; /* eyedbsm::DatType */
  };

  struct DatafileInfo {
    unsigned short datid;
    eyedbsm::Datafile datafile;
    Oid::NX objcnt;
    NS slotcnt;
    NS busyslotcnt;
    unsigned long long totalsize;
    unsigned int avgsize;
    NS lastbusyslot;
    NS lastslot;
    unsigned long long busyslotsize;
    unsigned long long datfilesize;
    unsigned long long datfileblksize;
    unsigned long long dmpfilesize;
    unsigned long long dmpfileblksize;
    NS curslot;
    unsigned long long defragmentablesize;
    NS slotfragcnt;
    double used;
  };

  struct Dataspace {
    char name[L_NAME+1];
    unsigned int ndat;
    short datid[MAX_DAT_PER_DSP];
  };

  struct DbCreateDescription {
    Oid::NX nbobjs;
    unsigned int dbid;
    unsigned int ndat;
    eyedbsm::Datafile dat[MAX_DATAFILES];
    unsigned int ndsp;
    eyedbsm::Dataspace dsp[MAX_DATASPACES];
    unsigned long long dbsfilesize;    /* used with DbInfo only */
    unsigned long long dbsfileblksize; /* used with DbInfo only */
    unsigned long long ompfilesize;    /* used with DbInfo only */
    unsigned long long ompfileblksize; /* used with DbInfo only */
    unsigned long long shmfilesize;    /* used with DbInfo only */
    unsigned long long shmfileblksize; /* used with DbInfo only */
  };

  typedef DbCreateDescription DbInfoDescription;

  struct DbRelocateDescription {
    unsigned int ndat;
    char file[MAX_DATAFILES][L_FILENAME];
  };

  struct DbMoveDescription {
    char dbfile[L_FILENAME];
    eyedbsm::DbCreateDescription dcr;
  };

  typedef DbMoveDescription DbCopyDescription;

  struct Protection {
    unsigned short r, w;
  };

  struct ProtectionAtom {
    unsigned int uid;
    eyedbsm::Protection prot;
  };

  struct ProtectionDescription {
    char name[PROT_NAME];
    unsigned int nprot;
    eyedbsm::ProtectionAtom desc[1];
  };

  struct DbProtectionDescription {
    unsigned int uid;
    Protection prot;
  };

  struct DbHandle;
  struct IndexId;
  struct Cursor;
  struct DbLock;

  enum LockMode {
    DefaultLock,
    LockN,  /* no lock */
    LockX,  /* exclusive */
    LockSX, /* shared/exclusive */
    LockS,  /* shared */
    LockP,  /* private */
    LockE   /* lock error */
  };

  enum TransactionMode {
    TransactionOff = 1,  /* no rollback is possible */
    TransactionOn  = 2
  };

  /* lockmode: S means shared, X means exclusive, SX means shared/exclusive */
  enum ObjectLockMode {
    ReadSWriteS = 1, /* read shared; write shared */
    ReadSWriteSX,    /* read shared; write shared/exclusive */  
    ReadSWriteX,     /* read shared; write exclusive */  
    ReadSXWriteSX,   /* read shared/exclusive; write shared/exclusive */
    ReadSXWriteX,    /* read shared/exclusive; write exclusive */
    ReadXWriteX,     /* read exclusive; write exclusive */
    ReadNWriteS,     /* read no lock; write shared */
    ReadNWriteSX,    /* read no lock; write shared/exclusive */
    ReadNWriteX,     /* read no lock; write exclusive */
    ReadNWriteN,     /* read no lock; write no lock */
    DatabaseW,       /* database exclusive for writing */
    DatabaseRW,      /* database exclusive for reading and writing */
    DatabaseWtrans   /* database exclusive for writing transaction */
  };

  enum RecoveryMode {
    RecoveryOff = 3, /* prevents from remote client failure */
    RecoveryPartial, /* plus prevents from local client and server failure */
    RecoveryFull     /* plus prevents from OS failure */
  };

  struct TransactionParams {
    TransactionMode trsmode;
    ObjectLockMode lockmode;
    RecoveryMode recovmode;
    unsigned int magorder;     /* estimated object cardinality in trans */
    unsigned int ratioalrt;    /* error returned if ratio != 0 &&
				  trans object number > ratioalrt * magorder  */
    unsigned int wait_timeout; /* in seconds */
  };

  static const TransactionParams DEFAULT_TRANSACTION_PARAMS = {
    eyedbsm::TransactionOn,
    eyedbsm::ReadNWriteSX,
    eyedbsm::RecoveryFull,
    0,
    0,
    30
  };

  enum Error {
    SUCCESS = 0,
    ERROR,
    SYS_ERROR,
    CONNECTION_FAILURE,
    SERVER_FAILURE,
    CANNOT_LOCK_SHMFILE,
    DB_ALREADY_LOCK_BY_A_SERVER,
    INVALID_DBID,
    INVALID_SIZESLOT,
    INVALID_NBSLOTS,
    INVALID_NBOBJS,
    INVALID_MAXSIZE,
    INVALID_MAPTYPE,
    DATABASE_CREATION_ERROR,
    DATABASE_ACCESS_DENIED,
    DATABASE_OPEN_FAILED,
    INVALID_DATAFILE_CNT,
    INVALID_DATASPACE_CNT,
    INVALID_DATAFILE_CNT_IN_DATASPACE,
    INVALID_DATASPACE,
    INVALID_DBFILE,
    INVALID_DBFILE_ACCESS,
    INVALID_SHMFILE,
    INVALID_SHMFILE_ACCESS,
    INVALID_OBJMAP_ACCESS,
    INVALID_DATAFILE,
    INVALID_DMPFILE,
    INVALID_DATAFILEMAXSIZE,
    INVALID_FILES_COPY,
    INVALID_DBFILES_COPY,
    INVALID_DATAFILES_COPY,
    INVALID_SHMFILES_COPY,
    INVALID_OBJMAPFILES_COPY,
    DBFILES_IDENTICAL,
    DATAFILES_IDENTICAL,
    DBFILE_ALREADY_EXISTS,
    SHMFILE_ALREADY_EXISTS,
    OBJMAPFILE_ALREADY_EXISTS,
    DATAFILE_ALREADY_EXISTS,
    SIZE_TOO_LARGE,
    WRITE_FORBIDDEN,
    CONN_RESET_BY_PEER,
    LOCK_TIMEOUT,
    FATAL_MUTEX_LOCK_TIMEOUT,
    BACKEND_INTERRUPTED,
    INVALID_TRANSACTION_MODE,
    RW_TRANSACTION_NEEDED,
    TRANSACTION_NEEDED,
    TRANSACTION_LOCKING_FAILED,
    TRANSACTION_UNLOCKING_FAILED,
    TOO_MANY_TRANSACTIONS,
    TRANSACTION_TOO_MANY_NESTED,
    DEADLOCK_DETECTED,
    INVALID_FLAG,
    INVALID_DB_HANDLE,
    MAP_ERROR,
    TOO_MANY_OBJECTS,
    INVALID_OBJECT_SIZE,
    NO_DATAFILESPACE_LEFT,
    NO_SHMSPACE_LEFT,
    INVALID_SIZE,
    INVALID_OFFSET,
    INVALID_OID,
    INVALID_ROOT_ENTRY_SIZE,
    INVALID_ROOT_ENTRY_KEY,
    INVALID_READ_ACCESS,
    INVALID_WRITE_ACCESS,
    OBJECT_PROTECTED,
    PROTECTION_INVALID_UID,
    PROTECTION_DUPLICATE_UID,
    PROTECTION_DUPLICATE_NAME,
    PROTECTION_NOT_FOUND,
    ROOT_ENTRY_EXISTS,
    TOO_MANY_ROOT_ENTRIES,
    ROOT_ENTRY_NOT_FOUND,
    PROT_NAME_TOO_LONG,
    NOTIMPLEMENTED,
    NO_SETUID_PRIVILEGE,
    NOT_YET_IMPLEMENTED,
    COMPATIBILITY_ERROR,
    INTERNAL_ERROR,
    FATAL_ERROR,
    COLLAPSING_LIMIT,
    N_ERROR
  };

  struct StatusRec {
    Error err;
    char *err_msg;
  };

  enum OP {
    CreateOP  = 0x1,
    ReadOP    = 0x2,
    WriteOP   = 0x4,
    SizeModOP = 0x8,
    DeleteOP  = 0x10,
    SizeGetOP = 0x20,
    LockNOP   = 0x40,
    LockSOP   = 0x80,
    LockXOP   = 0x100,
    LockSXOP  = 0x200,
    LockPOP   = 0x400,
    AllOP     = ~0
  };

  struct RegisterEntry {
    Oid oid;
    OP op;
    size_t create_size;
    size_t start_rw, length_rw;
    size_t sizemod_size;
  };

  struct Register {
    size_t oid_cnt;
    RegisterEntry *entries;
  };

  typedef const StatusRec *Status;

  /* function declarations */

  extern Status
  init(),
    release(),

    // functional API : should disapear
    dbCreate(const char *dbfile, unsigned int version,
	     const DbCreateDescription *dbc, mode_t file_mask, const char *file_group),
    dbDelete(const char *dbfile),
    dbMove(const char *dbfile, const DbMoveDescription *dmv),
    dbCopy(const char *dbfile, const DbCopyDescription *dcp),

    dbOpen(const char *dbfile, int flags,
	   const OpenHints *hints, int uid, unsigned int *pversion,
	   DbHandle **dbh),
    dbClose(const DbHandle *dbh),

    dbInfo(const char *dbfile, DbInfoDescription *info),

    transactionBegin(DbHandle *dbh, 
		     const TransactionParams *params),
    transactionCommit(DbHandle *dbh),
    transactionAbort(DbHandle *dbh),

    transactionParamsSet(DbHandle const *dbh,
			 const TransactionParams *params),

    transactionParamsGet(DbHandle const *dbh,
			 TransactionParams *params),

    dbRelocate(const char *dbfile, const DbRelocateDescription *rel),

    rootEntrySet(DbHandle const *dbh, char const *const key,
		 void const *const data, unsigned int size, Boolean create),
    rootEntryGet(DbHandle const *dbh, char const *const key,
		 void *data, unsigned int maxsize),
    rootEntryDelete(DbHandle const *dbh, char const *const key),

    objectCreate(DbHandle const *dbh, void const *const object,
		 size_t size, short dspid, Oid *oid), // V3_API_size_t
    objectDelete(DbHandle const *dbh, Oid const *const oid),
    objectWrite(DbHandle const *dbh, size_t start, size_t length,
		void const *const object, Oid const *const oid),
    objectWriteCache(DbHandle const *dbh, size_t start,
		     void const *const object, Oid const *const oid),
    objectRead(DbHandle const *dbh, size_t start, size_t length, void *object,
	       LockMode lockmode, short *pdatid, size_t *psize, // V3_API_size_t
	       Oid const *const oid),
    objectReadNoCopy(DbHandle const *dbh, size_t start, size_t length,
		     void *object,
		     LockMode lockmode, short *pdatid, size_t *psize, // V3_API_size_t
		     Oid const *const oid),
    objectReadCache(DbHandle const *dbh, size_t start, void **object,
		    LockMode lockmode, Oid const *const oid),
    objectSizeGet(DbHandle const *dbh, size_t *size, // V3_API_size_t
		  LockMode lockmode, Oid const *const oid),

    objectCheckAccess(DbHandle const *dbh, Boolean write,
		      Oid const *const oid, Boolean *access),

    objectLocationGet(DbHandle const *dbh, const Oid *oid,
		      ObjectLocation *objloc),

    objectsLocationGet(DbHandle const *dbh, const Oid *oid,
		       ObjectLocation *objloc, unsigned int oid_cnt),

    objectMoveDat(DbHandle const *dbh, Oid const *const oid,
		  short datid),

    objectsMoveDat(DbHandle const *dbh, Oid const *const oid,
		   unsigned int oid_cnt, short datid),

    objectMoveDsp(DbHandle const *dbh, Oid const *const oid,
		  short dspid),

    objectsMoveDsp(DbHandle const *dbh, Oid const *const oid,
		   unsigned int oid_cnt, short dspid),

    objectSizeModify(DbHandle const *dbh, size_t size, Boolean copy, // V3_API_size_t
		     Oid const *const oid),

    objectLock(DbHandle const *dbh, Oid const *const oid,
	       LockMode mode, LockMode *rmode),

    objectGetLock(DbHandle const *dbh, Oid const *const oid,
		  LockMode *rmode),

    objectDownLock(DbHandle const *dbh, Oid const *const oid),

    registerStart(DbHandle const *dbh, unsigned reg_mask),
    registerClear(DbHandle const *dbh),
    registerEnd(DbHandle const *dbh),
    registerGet(DbHandle const *dbh, Register **),

    firstOidDatGet(DbHandle const *dbh, short datid, Oid *oid,
		   Boolean *found),
    nextOidDatGet(DbHandle const *dbh, short datid,
		  Oid const *const baseoid, Oid *nextoid,
		  Boolean *found),

    privilegeInit(void),
    privilegeAcquire(void),
    privilegeRelease(void),
    suserUnset(DbHandle *dbh),

    statusPrint(Status status, const char *fmt, ...),

    statusMake(Error, const char *, ...),
    statusMake_s(Error),

    datCreate(DbHandle const *dbh, const char *file, const char *name,
	      unsigned long long maxsize, MapType mtype, unsigned int sizeslot,
	      DatType type, mode_t file_mask, const char *file_group),

    datMove(DbHandle const *dbh, const char *datfile,
	    const char *newdatfile),

    datDelete(DbHandle const *dbh, const char *datfile, Boolean force = False),

    datResize(DbHandle const *dbh, const char *datfile,
	      unsigned long long newmaxsize),

    datMoveObjects(DbHandle const *dbh, const char *dat_src,
		   const char *dat_dest),
		    
    datCheck(DbHandle const *dbh, const char *datfile,
	     short *datid, short *dspid),
		    
    datResetCurSlot(DbHandle const *dbh, const char *datfile),

    datDefragment(DbHandle const *dbh, const char *datfile, mode_t file_mask, const char *file_group),

    datRename(DbHandle const *dbh, const char *datfile, const char *name),

    datGetInfo(DbHandle const *dbh, const char *datfile, DatafileInfo *info),

    datGetDspid(DbHandle const *dbh, short datid, short *dspid),

    dspSetDefault(DbHandle const *dbh, const char *dataspace),

    dspGetDefault(DbHandle const *dbh, short *dspid),

    dspCreate(DbHandle const *dbh, const char *dataspace,
	      const char **datfiles, unsigned int datfile_cnt),

    dspUpdate(DbHandle const *dbh, const char *dataspace,
	      const char **datfiles, unsigned int datfile_cnt,
	      short flags, short orphan_dspid),

    dspDelete(DbHandle const *dbh, const char *dataspace),
    dspRename(DbHandle const *dbh, const char *dataspace,
	      const char *dataspace_new),

    dspCheck(DbHandle const *dbh, const char *dataspace, short *dspid,
	     short datid[], unsigned int *ndat),
		    
    dspSetCurDat(DbHandle const *dbh, const char *dataspace,
		 const char *datfile),
    dspGetCurDat(DbHandle const *dbh, const char *dataspace, short *datid),

    objectNumberGet(DbHandle const *dbh, Oid::NX *maxobjs),
    objectNumberSet(DbHandle const *dbh, Oid::NX maxobjs),

    shmSizeGet(DbHandle const *dbh, int *shmsize),
    shmSizeSet(DbHandle const *dbh, int shmsize),

    protectionCreate(DbHandle const *dbh,
		     ProtectionDescription const *desc,
		     Oid *oid),

    protectionDelete(DbHandle const *dbh, Oid const *const oid),

    protectionModify(DbHandle const *dbh,
		     ProtectionDescription const *desc,
		     Oid const *oid),

    protectionGetByName(DbHandle const *dbh,
			char const *name,
			ProtectionDescription **desc,
			Oid *oid),

    protectionGetByOid(DbHandle const *dbh,
		       Oid const *oid,
		       ProtectionDescription **desc),

    protectionListGet(DbHandle const *dbh,
		      Oid **oid, ProtectionDescription ***desc,
		      unsigned int *nprot),

    dbProtectionAdd(DbHandle const *dbh,
		    DbProtectionDescription const *desc, int nprot),

    dbProtectionGet(DbHandle const *dbh,
		    DbProtectionDescription **desc, unsigned int *nprot),

    objectProtectionSet(DbHandle const *dbh, Oid const *const oid,
			Oid const *const protoid),
    objectProtectionGet(DbHandle const *dbh, Oid const *const oid,
			Oid *protoid);

  extern int
  getOpenFlags(DbHandle const *dbh);

  extern Boolean
  isPhysicalOid(DbHandle const *dbh, const Oid *oid);

  extern Status
  transactionLockSet(DbHandle const *dbh, ObjectLockMode lockmode,
		     ObjectLockMode *olockmode);

  extern int
  getTransactionCount(DbHandle const *dbh);

  extern int
  getXID(DbHandle const *dbh);

  extern const char *
  getOPString(OP op);

  extern void
  registerEntryTrace(FILE *, const RegisterEntry *);

  extern void
  registerTrace(FILE *, const Register *);

  extern Status
  backendInterrupt(),
    backendInterruptReset();

  extern const char *
  statusGet(Status status);

  extern const char *
  statusGet_err(int err);

  extern const char *
  getOidString(const Oid *);

  enum {
    ReadNone   = 0,
    WriteNone  = 0,
    ReadAll    = (unsigned short)0xffff,
    WriteAll   = (unsigned short)0xffff
  };

  extern const void *ObjectZero, *ObjectNone;
  extern int dbidGet(const Oid *oid);
  extern void dbidSet(Oid *oid, int dbid);

  static const Status Success = (Status)0;

  static inline int protectionDescriptionSize(int n) {
    return sizeof(eyedbsm::ProtectionDescription) +
      ((n - 1) * sizeof(eyedbsm::ProtectionAtom));
  }

  // object API

  /**
     Not yet documented.
  */
  class Database {

    public :
      /**
	 Not yet documented.
	 @param dbfile
	 @param version
	 @param dbc
	 @param file_mask
	 @param file_group
	 @return
      */
    static Status dbCreate(const char *dbfile, unsigned int version,
			   const DbCreateDescription &dbc,
			   mode_t file_mask, const char *file_group);
    
    /**
       Not yet documented
       @param dbfile
       @return
    */
    static Status dbDelete(const char *dbfile);

    /**
       Not yet documented
       @param dbfile
       @param dmv
       @return
    */
    static Status dbMove(const char *dbfile, const DbMoveDescription &dmv);

    /**
       Not yet documented
       @param dbfile
       @param dcp
       @return
    */
    static Status dbCopy(const char *dbfile, const DbCopyDescription &dcp);

    /**
       Not yet documented
       @param dbfile
       @param info
       @return
    */
    static Status dbInfo(const char *dbfile, DbInfoDescription &info);

    /**
       Not yet documented
       @param dbfile
       @param rel
       @return
    */
    static Status dbRelocate(const char *dbfile, const DbRelocateDescription &rel);

    Database();

    /**
       Not yet documented
       @param dbfile
       @param flags
       @param hints
       @param uid
       @return
    */
    Status open(const char *dbfile, int flags,
		const OpenHints &hints, int uid);

    /**
       Not yet documented
       @return
    */
    int getOpenFlags() const;

    /**
       Not yet documented
       @return
    */
    unsigned int getVersion() const;

    /**
       Not yet documented
       @return
    */
    const char *getDBFile() const;

    /**
       Not yet documented
       @return
    */
    const OpenHints &getOpenHints() const;

    /**
       Not yet documented
       @return
    */
    Status close();

    // transaction management
    /**
       Not yet documented
       @param params
       @return
    */
    Status transactionBegin(const TransactionParams &params);

    /**
       Not yet documented
       @return
    */
    Status transactionCommit();

    /**
       Not yet documented
       @return
    */
    Status transactionAbort();

    /**
       Not yet documented
       @param params
       @return
    */
    Status transactionParamsSet(const TransactionParams &params);

    /**
       Not yet documented
       @param params
       @return
    */
    Status transactionParamsGet(TransactionParams &params);

    /**
       Not yet documented
       @param lockmode
       @param olockmode
       @return
    */
    Status transactionLockSet(ObjectLockMode lockmode,
			      ObjectLockMode &olockmode);

    // object management
    /**
       Not yet documented
       @param object
       @param size
       @param dspid
       @param oid
       @return
    */
    Status objectCreate(const void *object,
			size_t size, short dspid, Oid &oid); // V3_API_size_t

    /**
       Not yet documented
       @param oid
       @return
    */
    Status objectDelete(const Oid &oid);

    /**
       Not yet documented
       @param start
       @param length
       @param object
       @param oid
       @return
    */
    Status objectWrite(size_t start, size_t length,
		       const void *object, const Oid &oid);

    /**
       Not yet documented
       @param start
       @param object
       @param oid
       @return
    */
    Status objectWriteCache(size_t start,
			    const void *object, const Oid & oid);

    /**
       Not yet documented
       @param start
       @param length
       @param object
       @param lockmode
       @param pdatid
       @param psize
       @param oid
       @return
    */
    Status objectRead(size_t start, size_t length, void *object,
		      LockMode lockmode, short &pdatid, size_t &psize, // V3_API_size_t
		      const Oid & oid);

    /**
       Not yet documented
       @param start
       @param length
       @param object
       @param lockmode
       @param pdatid
       @param psize
       @param oid
       @return
    */
    Status objectReadNoCopy(size_t start, size_t length,
			    void *object, LockMode lockmode,
			    short &pdatid, size_t &psize, // V3_API_size_t
			    const Oid & oid);

    /**
       Not yet documented
       @param start
       @param object
       @param lockmode
       @param oid
       @return
    */
    Status objectReadCache(size_t start, void **object,
			   LockMode lockmode, const Oid & oid);

    /**
       Not yet documented
       @param size
       @param lockmode
       @param oid
       @return
    */
    Status objectSizeGet(size_t &size, LockMode lockmode, const Oid & oid); // V3_API_size_t

    /**
       Not yet documented
       @param write
       @param oid
       @param access
       @return
    */
    Status objectCheckAccess(Boolean write,
			     const Oid & oid, Boolean &access);

    /**
       Not yet documented
       @param oid
       @param objloc
       @return
    */
    Status objectLocationGet(const Oid &oid, ObjectLocation &objloc);

    /**
       Not yet documented
       @param oid
       @param objloc
       @param oid_cnt
       @return
    */
    Status objectsLocationGet(const Oid * oid, ObjectLocation *objloc,
			      unsigned int oid_cnt);

    /**
       Not yet documented
       @param oid
       @param datid
       @return
    */
    Status objectMoveDat(const Oid & oid, short datid);

    /**
       Not yet documented
       @param oid
       @param oid_cnt
       @param datid
       @return
    */
    Status objectsMoveDat(const Oid * oid,
			  unsigned int oid_cnt, short datid);

    /**
       Not yet documented
       @param oid
       @param dspid
       @return
    */
    Status objectMoveDsp(const Oid & oid, short dspid);

    /**
       Not yet documented
       @param oid
       @param oid_cnt
       @param dspid
       @return
    */
    Status objectsMoveDsp(const Oid * oid,
			  unsigned int oid_cnt, short dspid);

    /**
       Not yet documented
       @param size
       @param copy
       @param oid
       @return
    */
    Status objectSizeModify(size_t size, Boolean copy, // V3_API_size_t
			    const Oid & oid);

    /**
       Not yet documented
       @param oid
       @param mode
       @param rmode
       @return
    */
    Status objectLock(const Oid & oid, LockMode mode, LockMode &rmode);

    /**
       Not yet documented
       @param oid
       @param rmode
       @return
    */
    Status objectGetLock(const Oid & oid, LockMode &rmode);

    /**
       Not yet documented
       @param oid
       @return
    */
    Status objectDownLock(const Oid & oid);

    /**
       Not yet documented
       @param datid
       @param oid
       @param found
       @return
    */
    Status firstOidDatGet(short datid, Oid &oid, Boolean &found);

    /**
       Not yet documented
       @param datid
       @param baseoid
       @param nextoid
       @param found
       @return
    */
    Status nextOidDatGet(short datid, const Oid & baseoid, Oid &nextoid,
			 Boolean &found);

    /**
       Not yet documented
       @param key
       @param data
       @param size
       @param create
       @return
    */
    Status rootEntrySet(const char *key,
			const void *data, unsigned int size, Boolean create);

    /**
       Not yet documented
       @param key
       @param data
       @param maxsize
       @return
    */
    Status rootEntryGet(const char *key,
			void *data, unsigned int maxsize);

    /**
       Not yet documented
       @param key
       @return
    */
    Status rootEntryDelete(const char * key);

    /**
       Not yet documented
       @return
    */
    Status suserUnset();

    // datafile management
    /**
       Not yet documented
       @param file
       @param name
       @param maxsize
       @param mtype
       @param sizeslot
       @param type
       @param file_mask
       @param file_group
       @return
    */
    Status datCreate(const char *file, const char *name,
		     unsigned long long maxsize, MapType mtype,
		     unsigned int sizeslot,
		     DatType type,
		     mode_t file_mask, const char *file_group);

    /**
       Not yet documented
       @param datfile
       @param newdatfile
       @return
    */
    Status datMove(const char *datfile, const char *newdatfile);

    /**
       Not yet documented
       @param datfile
       @return
    */
    Status datDelete(const char *datfile, Boolean force = False);

    /**
       Not yet documented
       @param datfile
       @param newmaxsize
       @return
    */
    Status datResize(const char *datfile,
		     unsigned long long newmaxsize);

    /**
       Not yet documented
       @param dat_src
       @param dat_dest
       @return
    */
    Status datMoveObjects(const char *dat_src, const char *dat_dest);
		    
    /**
       Not yet documented
       @param datfile
       @param datid
       @param dspid
       @return
    */
    Status datCheck(const char *datfile, short &datid, short &dspid);
		    
    /**
       Not yet documented
       @param datfile
       @param file_mask
       @param file_group
       @return
    */
    Status datDefragment(const char *datfile,
			 mode_t file_mask, const char *file_group);

    /**
       Not yet documented
       @param datfile
       @param name
       @return
    */
    Status datRename(const char *datfile, const char *name);

    /**
       Not yet documented
       @param datfile
       @param info
       @return
    */
    Status datGetInfo(const char *datfile, DatafileInfo &info);

    /**
       Not yet documented
       @param datid
       @param dspid
       @return
    */
    Status datGetDspid(short datid, short &dspid);

    // dataspace management
    /**
       Not yet documented
       @param dataspace
       @return
    */
    Status dspSetDefault(const char *dataspace);

    /**
       Not yet documented
       @param dspid
       @return
    */
    Status dspGetDefault(short &dspid);

    /**
       Not yet documented
       @param dataspace
       @param datfiles
       @param datfile_cnt
       @return
    */
    Status dspCreate(const char *dataspace,
		     const char **datfiles, unsigned int datfile_cnt);

    /**
       Not yet documented
       @param dataspace
       @param datfiles
       @param datfile_cnt
       @return
    */
    Status dspUpdate(const char *dataspace,
		     const char **datfiles, unsigned int datfile_cnt);

    /**
       Not yet documented
       @param dataspace
       @return
    */
    Status dspDelete(const char *dataspace);

    /**
       Not yet documented
       @param dataspace
       @param dataspace_new
       @return
    */
    Status dspRename(const char *dataspace,
		     const char *dataspace_new);

    /**
       Not yet documented
       @param dataspace
       @param dspid
       @param datid
       @param ndat
       @return
    */
    Status dspCheck(const char *dataspace, short &dspid,
		    short datid[], unsigned int &ndat);
		    
    /**
       Not yet documented
       @param dataspace
       @param datfile
       @return
    */
    Status dspSetCurDat(const char *dataspace,
			const char *datfile);

    /**
       Not yet documented
       @param dataspace
       @param datid
       @return
    */
    Status dspGetCurDat(const char *dataspace, short &datid);

    /**
       Not yet documented
       @param maxobjs
       @return
    */
    Status objectNumberSet(Oid::NX maxobjs);

    // protection management
    /**
       Not yet documented
       @param desc
       @param oid
       @return
    */
    Status protectionCreate(const ProtectionDescription &desc, Oid &oid);

    /**
       Not yet documented
       @param oid
       @return
    */
    Status protectionDelete(const Oid & oid);

    /**
       Not yet documented
       @param desc
       @param oid
       @return
    */
    Status protectionModify(const ProtectionDescription &desc, const Oid &oid);

    /**
       Not yet documented
       @param name
       @param desc
       @param oid
       @return
    */
    Status protectionGetByName(const char *name,
			       ProtectionDescription **desc,
			       Oid &oid);

    /**
       Not yet documented
       @param oid
       @param desc
       @return
    */
    Status protectionGetByOid(const Oid &oid,
			      ProtectionDescription **desc);

    /**
       Not yet documented
       @param oid
       @param desc
       @param nprot
       @return
    */
    Status protectionListGet(Oid **oid, ProtectionDescription ***desc,
			     unsigned int &nprot);

    /**
       Not yet documented
       @param desc
       @param nprot
       @return
    */
    Status dbProtectionAdd(const DbProtectionDescription &desc,
			   unsigned int nprot);

    /**
       Not yet documented
       @param desc
       @param nprot
       @return
    */
    Status dbProtectionGet(DbProtectionDescription **desc,
			   unsigned int &nprot);

    /**
       Not yet documented
       @param oid
       @param protoid
       @return
    */
    Status objectProtectionSet(const Oid & oid,
			       const Oid & protoid);

    /**
       Not yet documented
       @param oid
       @param protoid
       @return
    */
    Status objectProtectionGet(const Oid & oid,
			       Oid *protoid);

    /**
       Not yet documented
       @param oid
       @return
    */
    Boolean isPhysicalOid(const Oid &oid);

    /**
       Not yet documented
       @param reg_mask
       @return
    */
    Status registerStart(unsigned reg_mask);

    /**
       Not yet documented
       @return
    */
    Status registerClear();

    /**
       Not yet documented
       @return
    */
    Status registerEnd();

    /**
       Not yet documented
       @param preg
       @return
    */
    Status registerGet(Register **preg);

    ~Database();

  private:
    char *dbfile;
    unsigned int version;
    OpenHints hints;
    DbHandle *dbh;
  };

  /**
     @}
  */
}

#include <eyedbsm/BIdx.h>
#include <eyedbsm/HIdx.h>

#endif
