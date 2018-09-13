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


/*
 * Files:
 *  .dbs: database system file: contains database file header
 *  .shm: shm file (transaction information)
 *  .lck: lock file (to avoid use of eyedbsmd daemon, when it is possible)
 *  .omp: object mapping file
 *  .dat: data files
 *  .dmp: data mapping file (allocator per datafile)
 */

#include "eyedbsmconfig.h"

#include <iostream>
#include <sys/types.h>
#include <grp.h>

#include "eyedblib/filelib.h"
#include "eyedblib/rpc_lib.h"
#include "kern_p.h"
#include <eyedbsm/smd.h>
#include <map>
#include "lib/compile_builtin.h"

static const char defDsp[] = "DEFAULT";

//#define ESM_SOFT_MAX_OBJS (unsigned int)500000000, /* waiting for 64 bits */
//#define ESM_SOFT_MAX_OBJS (unsigned int)~0

namespace eyedbsm {
  unsigned long curref;
  const void *ObjectZero = 0, *ObjectNone = (void *)-1;
  Boolean backend_interrupt = False;
  Boolean backend = False;
  unsigned int import_xid;
  const int INVALID = -1;

  //#define SHM_DEFSIZE   0x8000000
  // modified the 17/11/01
#define SHM_DEFSIZE   0x4000000
  //#define DBS_DEFSIZE   (size_t)(sizeof(DbHeader))
#define DBS_DEFSIZE   (size_t)DbHeader_SIZE
#define OIDMAP_SIZE(NOBJS) \
  (((((unsigned long long)NOBJS * OIDLOCSIZE) / pgsize) + 1) * pgsize)

#define ALIGN4(x) \
x = (u_long *)(((u_long)(x)&0x3) ? ((u_long)(x) + 0x4-((u_long)(x)&0x3)) : (u_long)x)


#define ESM_DEF_NBOBJS 100000000 /* 100 Millions */
#define MAXTRIES 0

  const char ompext[] = ".omp";
  const char shmext[] = ".shm";
  const char dbsext[] = ".dbs";
  const char datext[] = ".dat";
  const char dmpext[] = ".dmp";

  int dbsext_len = 4; /* strlen(dbsext); */
  int datext_len = 4; /* strlen(datext); */

  bool isV3(const DbHandle* dbh)
  {
    /*
    if (dbh->vd->version >= V3_VERSION) {
      std::cerr << "is V3\n";
    } else {
      std::cerr << "NOT V3\n";
    }
    */
    return dbh->vd->version >= V3_VERSION;
  }

  static Status
  dbCleanupRealize(const char *shmfile, int sm_fdshm);

  static Status
  dbcreate_error(Status status, const char *dbfile,
		 const DbCreateDescription *dbc, int n, DBFD *dbfd)
  {
    char pwd[DEFAULT_PWD_SIZE];
    push_dir(dbfile, pwd, sizeof pwd);

    unlink(dbfile); 
    unlink(objmapfileGet(dbfile));
    unlink(shmfileGet(dbfile));

    close(dbfd->dbsfd);
    close(dbfd->ompfd);
    close(dbfd->shmfd);

    for (int j = 0; j < n; j++) {
      unlink(dbc->dat[j].file);
      unlink(dmpfileGet(dbc->dat[j].file));
      close(dbfd->fd_dat[j]);
      close(dbfd->fd_dmp[j]);
    }

    pop_dir(pwd);
    return status;
  }

  static int fileCreate(const char *file, mode_t file_mode, gid_t file_gid)
  {
    int fd;

    umask(0);

    if ((fd = creat(file, file_mode)) < 0)
      return -1;

    if (chmod(file, file_mode) < 0)
      return -1;

    if (file_gid != (gid_t)-1) {
      if (chown(file, (uid_t)-1, file_gid) < 0) {
	close(fd);
	unlink(file);
	return -2;
      }
    }
    return fd;
  }

  static int
  dbsfileCreate(const char *dbfile, mode_t file_mode, gid_t file_gid)
  {
    int dbsfd;

    if ((dbsfd = fileCreate(dbfile, file_mode, file_gid)) < 0)
      return dbsfd;

    IDB_LOG(IDB_LOG_MMAP, ("ftruncate %s %llu\n", dbfile, DBS_DEFSIZE));
    if (ftruncate(dbsfd, DBS_DEFSIZE) < 0) {
      return -1;
    }
    return dbsfd;
  }

  static int
  shmfileCreate(const char *dbfile, mode_t file_mode, gid_t file_gid)
  {
    int shmfd;

    if ((shmfd = fileCreate(shmfileGet(dbfile), file_mode, file_gid)) < 0)
      return shmfd;

    IDB_LOG(IDB_LOG_MMAP, ("ftruncate %s %llu\n", shmfileGet(dbfile), SHM_DEFSIZE));
    if (ftruncate(shmfd, SHM_DEFSIZE) < 0)
      return -1;
    return shmfd;
  }
    
  static Status
  check_dbCreate_1(const char *pr, int dbid, const char *dbfile,
		   Oid::NX nbobjs, int ndat)
  {
    int dbfile_len = strlen(dbfile);

    if (dbid <= 0 || dbid >= MAX_DBID)
      return statusMake(INVALID_DBID,
			"%sinvalid database identifier `%d'", pr, dbid);

    if (dbfile_len <= dbsext_len ||
	strcmp(&dbfile[dbfile_len-dbsext_len], dbsext))
      return statusMake(INVALID_DBFILE,
			"%sinvalid database file extension for `%s' "
			"(must be %s)", pr, dbfile, dbsext);

    /*
      if (nbobjs > ESM_SOFT_MAX_OBJS)
      return statusMake(INVALID_NBOBJS,
      "%stoo many objects `%d' for database, "
      "maximum allowed is `%d'",
      pr, nbobjs, ESM_SOFT_MAX_OBJS);
    */

    if (ndat <= 0)
      return statusMake(INVALID_DATAFILE_CNT,
			"%sinvalid datafile number: %d",
			pr, ndat);

    if (ndat >= MAX_DATAFILES)
      return statusMake(INVALID_DATAFILE_CNT,
			"%sdatafile number too large: %d, maximum is %u", pr, ndat, MAX_DATAFILES);
    
    return Success;
  }
    
  static Status
  check_dbCreate_2(const char *pr, const char *dbfile, DBFD *dbfd, mode_t file_mode, gid_t file_gid)
  {
    if ((dbfd->dbsfd = open(dbfile, O_RDONLY)) >= 0)
      return statusMake(INVALID_DBFILE,
			"%sdatabase file already exists: '%s'",
			pr, dbfile);

    if ((dbfd->ompfd = open(objmapfileGet(dbfile), O_RDONLY)) >= 0)
      return statusMake(INVALID_DBFILE,
			"%smap file already exists: '%s'",
			pr, objmapfileGet(dbfile));

    if ((dbfd->shmfd = open(shmfileGet(dbfile), O_RDONLY)) >= 0)
      return statusMake(INVALID_SHMFILE,
			"%sshm file already exists: '%s'",
			pr, shmfileGet(dbfile));

    if ((dbfd->dbsfd = dbsfileCreate(dbfile, file_mode, file_gid)) < 0)
      return statusMake(INVALID_DBFILE,
			"%scannot create database file: '%s' [%s]",
			pr, dbfile, strerror(errno));

    return Success;
  }

  static Status
  check_dbCreate_3(const char *pr, const char *dbfile, DBFD *dbfd, mode_t file_mode, gid_t file_gid)
  {
    if ((dbfd->ompfd = fileCreate(objmapfileGet(dbfile), file_mode, file_gid))
	< 0)
      return statusMake(INVALID_DBFILE,
			"%scannot create map file: '%s' [%s]",
			pr, objmapfileGet(dbfile), strerror(errno));

    if ((dbfd->shmfd = shmfileCreate(dbfile, file_mode, file_gid)) < 0)
      return statusMake(INVALID_SHMFILE,
			"%scannot create shm file: '%s' [%s]",
			pr, shmfileGet(dbfile), strerror(errno));

    return Success;
  }

  Status checkDatafileSize(unsigned long long nslots_l,
			   const char *datfile, unsigned int sizeslot,
			   unsigned long long newmaxsize)
  {
    //    if (nslots_l >= ~0U) {
    //    if (nslots_l > 0x100000000ULL) {
    if (nslots_l >= 0x100000000ULL) {
      size_t abs_maxsize = SLOT2KB(((unsigned long long)~0U)-1, sizeslot);
      return statusMake(SIZE_TOO_LARGE,
			"datafile %s (slotsize %u) maximum size is too large: "
			"%lluMB, maximum allowed size is %uMB (%uGB)",
			datfile,
			sizeslot,
			newmaxsize/ONE_K, abs_maxsize/ONE_K, abs_maxsize/(ONE_K*ONE_K));
    }

    return Success;
  }

  Status checkDatafile(const char *pr, const char *dbfile, DbHeader *dbh,
		       const DbCreateDescription *dbc,
		       int i, DBFD *dbfd,
		       mode_t file_mode, gid_t file_gid,
		       Boolean can_be_null,
		       Boolean *is_null, Boolean out_place)
  {
    if (!*dbc->dat[i].file) {
      if (can_be_null) {
	if (is_null)
	  *is_null = True;
	return Success;
      }
      return statusMake(INVALID_DBFILE, "%sinvalid null database", pr);
    }

    DatType dtype = (DatType)dbc->dat[i].dtype;

    if (dtype != LogicalOidType &&
	dtype != PhysicalOidType)
      return statusMake(ERROR, "datafile creation: "
			"invalid datatype %d", dtype);

    if (is_null)
      *is_null = False;
    const char *dmpfile = dmpfileGet(dbc->dat[i].file);
    short mtype; /* was MapType */
    int datfile_len = strlen(dbc->dat[i].file);
    Status status;
    unsigned int sizeslot;

    char pwd[DEFAULT_PWD_SIZE];
    status = push_dir(dbfile, pwd, sizeof pwd);
    if (status) return status;

    if (datfile_len <= datext_len ||
	strcmp(&dbc->dat[i].file[datfile_len-datext_len], datext)) {
      pop_dir(pwd);
      return statusMake(INVALID_DBFILE,
			"%sinvalid database file extension for `%s' "
			"(must be %s)", pr, dbc->dat[i].file, datext);
    }
  
    if ((status = checkVolMaxSize(dbc->dat[i].maxsize))) {
      pop_dir(pwd);
      return status;
    }

    if ((dbfd->fd_dat[i] = open(dbc->dat[i].file, O_RDONLY)) >= 0) {
      pop_dir(pwd);
      close(dbfd->fd_dat[i]);
      return statusMake(INVALID_DATAFILE,
			"%sdatafile already exists: '%s'",
			pr, dbc->dat[i].file);
    }

    if (status = checkNewDatafile(dbh, dbc->dat[i].file, dbc->dat[i].name)) {
      pop_dir(pwd);
      return status;
    }

    if ((dbfd->fd_dmp[i] = open(dmpfile, O_RDONLY)) >= 0) {
      pop_dir(pwd);
      close(dbfd->fd_dmp[i]);
      return statusMake(INVALID_DMPFILE,
			"%sdata map file already exists: '%s'",
			pr, dmpfile);
    }

  
    if ((dbfd->fd_dat[i] = fileCreate(dbc->dat[i].file, file_mode, file_gid)) <
	0) {
      pop_dir(pwd);
      return statusMake(INVALID_DATAFILE, 
			"%scannot create datafile: '%s' [%s]",
			pr, dbc->dat[i].file, strerror(errno));
    }
  
    if ((dbfd->fd_dmp[i] = fileCreate(dmpfile, file_mode, file_gid)) <
	0) {
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(INVALID_DMPFILE, 
			"%scannot create data map file: '%s' [%s]",
			pr, dmpfile, strerror(errno));
    }
  
    if (status = syscheck(pr, close(dbfd->fd_dat[i]),
			  "closing datafile: '%s'",
			  dbc->dat[i].file)) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return status;
    }
  
    strcpy(dbh->dat(i).file(), dbc->dat[i].file);
    strcpy(dbh->dat(i).name(), dbc->dat[i].name);
    dbh->dat(i).__dspid() = 0;
    if (out_place) {
      dbh->dat(i).__maxsize() = h2x_u32(dbc->dat[i].maxsize);
      setDataspace(dbh, i, DefaultDspid);
      setDatType(dbh, i, dtype);
    }
    else {
      dbh->dat(i).__maxsize() = dbc->dat[i].maxsize;
      setDataspace_inplace(dbh, i, DefaultDspid);
      setDatType_inplace(dbh, i, dtype);
    }

    dbh->dat(i).__lastslot() = 0;
    dbh->dat(i).mp()->memzero();
    //memset(&dbh->dat[i].mp, 0, sizeof(dbh->dat[i].mp));
    mtype = dbc->dat[i].mtype;

    if (mtype == LinkmapType) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(INVALID_MAPTYPE, "%slinkmap type is not supported", pr);
    }

    if (mtype != BitmapType) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(INVALID_MAPTYPE, "%smap type is invalid: '%d'", pr, mtype);
    }

    sizeslot = ((dbc->dat[i].mtype == BitmapType) ? dbc->dat[i].sizeslot :
		sizeof(eyedblib::int32));

    DatafileDesc dat = dbh->dat(i);
    MapHeader *xmp = dat.mp();

    xmp->pow2() = power2(sizeslot);
    if (xmp->pow2() < 0) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(INVALID_SIZESLOT,
			"%sslot size %d is not a power of two", pr, sizeslot);
    }

    if (mtype == BitmapType &&
	(sizeslot < MIN_SIZE_SLOT ||
	 sizeslot > MAX_SIZE_SLOT ||
	 (pgsize % sizeslot) != 0)) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(INVALID_SIZESLOT,
			"dbCreate: slot size is invalid: `%d'", sizeslot);
    }

    xmp->sizeslot() = sizeslot;
    xmp->mtype() = mtype;
    xmp->sizeslot() = dbc->dat[i].sizeslot;
    unsigned long long nslots_l;
    if (mtype == BitmapType) {
      nslots_l = KB2SLOT(dbc->dat[i].maxsize, xmp->pow2());
    } else {
      nslots_l = ((unsigned long long)(dbc->dat[i].maxsize)*ONE_K)/32;
    }

    if (status = checkDatafileSize(nslots_l, dbc->dat[i].file, xmp->sizeslot(), dbc->dat[i].maxsize)) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return status;
    }

    xmp->nslots() = (unsigned int)nslots_l;
    /*
      if (xmp->nslots >= (unsigned long long)MAX_SLOTS) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return statusMake(SIZE_TOO_LARGE, 
      "%smaximum slots `%d' exceeded", pr, MAX_SLOTS);
      }
    */

    if (status = syscheck(pr, close(dbfd->fd_dmp[i]),
			  "closing data map file: '%s'", dmpfile)) {
      unlink(dmpfile);
      unlink(dbc->dat[i].file);
      pop_dir(pwd);
      return status;
    }

    pop_dir(pwd);

    if (out_place) {
      h2x_mapHeader(dbh->dat(i).mp(), xmp);
    }

    return Success;
  }

  static char **datfilesBuild(unsigned int ndat)
  {
    char **datfiles = new char *[ndat];
    for (int n = 0; n < ndat; n++) {
      char buf[16];
      sprintf(buf, "%d", n);
      datfiles[n] = strdup(buf);
    }

    return datfiles;
  }

  static void datfilesFree(char **datfiles, unsigned int ndat)
  {
    for (int n = 0; n < ndat; n++)
      free(datfiles[n]);

    delete [] datfiles;
  }

  Status
  getFileMaskGroup(mode_t &file_mode, gid_t &file_gid, mode_t file_mask, const char *file_group)
  {
    file_mode = (file_mask | DEFAULT_CREATION_MODE);
    if (file_group && *file_group) {
      struct group *grp = getgrnam(file_group);
      if (!grp) {
	return statusMake(DATABASE_CREATION_ERROR, "invalid file group: %s", file_group);
      }
      file_gid = grp->gr_gid;
    }
    else
      file_gid = (gid_t)-1;

    return Success;
  }

  static const char *basename(const char* name)
  {
    const char* q = strrchr(name, '/');
    if (NULL == q) {
      return name;
    }
#define MAXBASENAMES 8
    static int basename_ind;
    static char* basenames[MAXBASENAMES];

    if (NULL != basenames[basename_ind]) {
      delete [] basenames[basename_ind];
    }
    basenames[basename_ind] = new char[strlen(name)+1];
    strcpy(basenames[basename_ind], q+1);
    int oind = basename_ind;
    if (++basename_ind == MAXBASENAMES) {
      basename_ind = 0;
    }
    return basenames[oind];
  }

  Status
  dbCreate(const char *dbfile, unsigned int version,
	   const DbCreateDescription *dbc, mode_t file_mask, const char *file_group)
  {
    DBFD dbfd;
    int dbid = dbc->dbid, sizeslot, i,
      ndat = dbc->ndat, szhead, rszhead;
    //unsigned int nbobjs = (dbc->nbobjs ? dbc->nbobjs : ESM_DEF_NBOBJS);
    Oid::NX nbobjs = dbc->nbobjs;
    int n;
    DbHeader dbh;

    DbHandle *pdbh;
    DbShmHeader dbhshm;
    char *p;
    Status status;
    int dbfile_len = strlen(dbfile);

#undef PR
#define PR "dbCreate: "
    mode_t file_mode;
    gid_t file_gid;
    status = getFileMaskGroup(file_mode, file_gid, file_mask, file_group);
    if (status)
      return status;

    status = check_dbCreate_1(PR, dbid, dbfile, nbobjs, ndat);
    if (status)
      return status;

    status = check_dbCreate_2(PR, dbfile, &dbfd, file_mode, file_gid);
    if (status)
      return status;

    status = check_dbCreate_3(PR, dbfile, &dbfd, file_mode, file_gid);
    if (status)
      return dbcreate_error(status, dbfile, dbc, 0, &dbfd);

    memset(&dbhshm, 0, sizeof(dbhshm));
    dbhshm.magic = MAGIC;
    dbhshm.version = h2x_u32(version);
    if ((n = write(dbfd.shmfd, (char *)&dbhshm, sizeof(dbhshm))) !=
	sizeof(dbhshm))
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "unexpected writing header in shmfile: '%s'", shmfileGet(dbfile)),
			    dbfile, dbc, 0, &dbfd);

    if (status = syscheck(PR, close(dbfd.shmfd), "closing shm file: '%s'", shmfileGet(dbfile)))
      return dbcreate_error(status, dbfile, dbc, 0, &dbfd);

    dbh.memzero();
      
    char pwd[DEFAULT_PWD_SIZE];
    status = push_dir(dbfile, pwd, sizeof pwd);
    if (status) return status;

    Boolean ok = False;
    dbh.__magic() = MAGIC;
    for (i = 0; i < ndat; i++) {
      Boolean is_null;
      status = checkDatafile(PR, dbfile, &dbh, dbc, i, &dbfd,
			     file_mode, file_gid, True, &is_null);
      if (!is_null) ok = True;
      if (status) {
	pop_dir(pwd);
	return dbcreate_error(status, dbfile, dbc, i, &dbfd);
      }
    }

    if (!ok) {
      pop_dir(pwd);
      return statusMake(DATABASE_CREATION_ERROR, PR " at least one datafile must not be null");
    }

    // EV: 2018-07-06
    //strcpy(dbh.shmfile(), shmfileGet(dbfile));
    strcpy(dbh.shmfile(), basename(shmfileGet(dbfile)));
    dbh.__ndat() = dbc->ndat;
    dbh.__lastidxbusy() = 0;
    dbh.__curidxbusy() = 0;
    dbh.__dbid() = dbid;
    dbh.__guest_uid() = (short)INVALID_UID;
    dbh.__nbobjs() = nbobjs;

    dbh.state() = OPENING_STATE;

    DbHeader xdbh;
    h2x_dbHeader(&xdbh, &dbh);

    if ((n = write(dbfd.dbsfd, xdbh._addr(), DbHeader_SIZE)) != DbHeader_SIZE) {
      pop_dir(pwd);
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "unexpected error reported by write on database file: '%s'", dbfile), dbfile, dbc, ndat, &dbfd);
    }

    if (status = syscheck(PR, close(dbfd.dbsfd), "closing database file: '%s'", dbfile)) {
      pop_dir(pwd);
      return dbcreate_error(status, dbfile, dbc, ndat, &dbfd);
    }

    if (status = syscheck(PR, close(dbfd.ompfd), "closing map oid file: '%s'",
			  objmapfileGet(dbfile))) {
      pop_dir(pwd);
      return dbcreate_error(status, dbfile, dbc, ndat, &dbfd);
    }

    if (status = ESM_dbOpen(dbfile, VOLRW, 0, 0, 0, 1, 0, 0, &pdbh)) {
      pop_dir(pwd);
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "database open error reported: '%s'", statusGet(status)), dbfile, dbc, ndat, &dbfd);
    }

    char **datfiles = datfilesBuild(ndat);

    //char *datfile[1] = { "0" };
    if (status = ESM_dspCreate(pdbh, defDsp, (const char **)datfiles, ndat, True)) {
      datfilesFree(datfiles, ndat);
      pop_dir(pwd);
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "database open error reported: '%s'", statusGet(status)), dbfile, dbc, ndat, &dbfd);
    }


    datfilesFree(datfiles, ndat);

    if (status = ESM_dspSetDefault(pdbh, defDsp, True)) {
      pop_dir(pwd);
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "database open error reported: '%s'", statusGet(status)), dbfile, dbc, ndat, &dbfd);
    }

    if (status = protectionInit(pdbh)) {
      pop_dir(pwd);
      return dbcreate_error(statusMake(DATABASE_CREATION_ERROR, PR "database protection init error reported: '%s'", statusGet(status)), dbfile, dbc, ndat, &dbfd);
    }

    pop_dir(pwd);
    DbHeader _xpdbh(pdbh->vd->dbs_addr);
    _xpdbh.state() = OPENED_STATE;

    ESM_dbClose(pdbh);

    return Success;
  }

  Status
  dbDelete(const char *dbfile)
  {
    Status s;
    DbHandle *dbh;
    int i;

#undef PR
#define PR "dbDelete: "
    if (s = ESM_dbOpen(dbfile, VOLRW, 0, 0, 0, 0, 0, 0, &dbh))
      return s;

    char pwd[DEFAULT_PWD_SIZE];
    s = push_dir(dbfile, pwd, sizeof pwd);
    if (s) return s;

    DbHeader _dbh(DBSADDR(dbh));;
    unsigned int ndat = x2h_u32(_dbh.__ndat());
    for (i = 0; i < ndat; i++) {
      if (*_dbh.dat(i).file()) {
	if (unlink(_dbh.dat(i).file()) < 0) {
	  pop_dir(pwd);
	  return fcouldnot(PR, "unlink", _dbh.dat(i).file());
	}

	if (unlink(dmpfileGet(_dbh.dat(i).file())) < 0) {
	  pop_dir(pwd);
	  return fcouldnot(PR, "unlink", dmpfileGet(_dbh.dat(i).file()));
	}
      }
    }

    ESM_dbClose(dbh);

    if (unlink(dbfile) < 0) {
      pop_dir(pwd);
      return fcouldnot(PR, "unlink", dbfile);
    }

    if (unlink(shmfileGet(dbfile)) < 0) {
      pop_dir(pwd);
      return fcouldnot(PR, "unlink", shmfileGet(dbfile));
    }

    if (unlink(objmapfileGet(dbfile)) < 0) {
      pop_dir(pwd);
      return fcouldnot(PR, "unlink", objmapfileGet(dbfile));
    }

    return pop_dir(pwd);
  }

  Status
  dbInfo(const char *dbfile, DbInfoDescription *info)
  {
    DbHeader xdbh;
    int fd;
    Status se;

#undef PR
#define PR "dbInfo: "
    if (se = checkFileAccess(DATABASE_OPEN_FAILED, "database file",
			     dbfile, R_OK))
      return se;

    if ((se = dopen(PR, dbfile, O_RDONLY, &fd, 0)) != Success)
      return se;

    if (se = syscheckn(PR, read(fd, xdbh._addr(), DbHeader_SIZE), DbHeader_SIZE,
		       "reading database file: '%s'", dbfile))
      return se;

    DbHeader dbh;
    x2h_dbHeader(&dbh, &xdbh);

    if (dbh.__magic() != MAGIC) {
      if (se = syscheck(PR, close(fd), "closing database file: '%s'",
			dbfile))
	return se;
      return statusMake(INVALID_DBFILE,
			PR "database file '%s' is not a valid eyedbsm database "
			"file", dbfile);
    }
      
    /*
      if (se = syscheck(PR, lseek(fd, 0, 0), "lseek on database file: '%s'",
      dbfile))
      return se;

      if (se = syscheckn(PR, read(fd, &dbh, sizeof(dbh)), sizeof(dbh),
      "read on database file: '%s'", dbfile))
      return se;
    */

    info->dbid = dbh.__dbid();
    info->ndat = dbh.__ndat();
    info->ndsp = dbh.__ndsp();
    info->nbobjs = dbh.__nbobjs();

    if (se = fileSizesGet(dbfile,
			  info->dbsfilesize, info->dbsfileblksize))
      return se;

    if (se = fileSizesGet(objmapfileGet(dbfile),
			  info->ompfilesize, info->ompfileblksize))
      return se;

    if (se = fileSizesGet(shmfileGet(dbfile),
			  info->shmfilesize, info->shmfileblksize))
      return se;

    if (se = syscheck(PR, close(fd), "closing database file: '%s'", dbfile))
      return se;

    for (int i = 0; i < dbh.__ndsp(); i++) {
      Dataspace *ds = &info->dsp[i];
      DataspaceDesc _dsd = dbh.dsp(i);
      DataspaceDesc *dsd = &_dsd;

      strcpy(ds->name, dsd->name());
      ds->ndat = dsd->__ndat();
      memcpy(ds->datid, dsd->__datid_ref(), sizeof(short) * dsd->__ndat());
    }

    for (int i = 0; i < dbh.__ndat(); i++) {
      Datafile *df = &info->dat[i];
      DatafileDesc _dfd = dbh.dat(i);
      DatafileDesc *dfd = &_dfd;

      strcpy(df->file, dfd->file());
      strcpy(df->name, dfd->name());
      df->dspid = getDataspace_inplace(&dbh, i); // dfd->__dspid;
      df->dtype = getDatType_inplace(&dbh, i);
      df->maxsize = dfd->__maxsize();
      df->mtype = dfd->mp()->mtype();
      df->sizeslot = dfd->mp()->sizeslot();

      if (!access(df->file, R_OK|W_OK))
	df->extflags = R_OK|W_OK;
      else if (!access(df->file, W_OK))
	df->extflags = W_OK;
      else if (!access(df->file, R_OK))
	df->extflags = R_OK;
      else
	df->extflags = 0;
    }

    return Success;
  }

  /*
   * Move/Copy operations
   */

#define XSTR(F) ((F) ? "copy" : "move")
  //#define MVCP_TRACE

  char *
  makefile(const char *dir, const char *file)
  {
    static int buf_ind;
#define NN 8
    static char *buf[NN];
    char *s;

    if (buf_ind >= NN)
      buf_ind = 0;

    free(buf[buf_ind]);

    if (!dir || !*dir || *file == '/') {
      buf[buf_ind] = strdup(file);
      return buf[buf_ind++];
    }

    s = (char *)m_malloc(strlen(dir)+strlen(file)+2);
    strcpy(s, dir);
    strcat(s, "/");
    strcat(s, file);

    buf[buf_ind] = s;
    return buf[buf_ind++];
  }

  Status
  copyfile(const char *from, const char *to,
	   const char *fromdbdir, const char *todbdir,
	   int sparsify)
  {
    int fd1, fd2;
    struct stat st;
    Status se;
    char *xfrom = makefile(fromdbdir, from);
    char *xto = makefile(todbdir, to);

#if 1
    sparsify = 0; // 27/08/03 : no more need for sparsification
#endif

    errno = 0;

#ifdef MVCP_TRACE
    printf("copying '%s' to '%s' [%s . %s]\n", xfrom, xto, fromdbdir, todbdir);
#endif

    if (!access(xto, F_OK))
      return syserror("target file '%s' already exists", xto);

    if ((fd1 = open(xfrom, O_RDONLY)) < 0)
      return syserror("opening file '%s' for reading", xfrom);

    if ((fd2 = creat(xto, DEFAULT_CREATION_MODE)) < 0) {
      close(fd1);
      return syserror("creating file '%s'", xto);
    }

    // setting same mode to the new file
    if (fstat(fd1, &st) < 0)
      return syserror("stating file '%s'", xfrom);
    fchmod(fd2, st.st_mode); // don't worry if an error occurs!

    if (!sparsify) {
      char buf[2048];
      int n;
      while ((n = read(fd1, buf, sizeof buf)) > 0)
	if (write(fd2, buf, n) != n) {
	  close(fd1); close(fd2); unlink(xto);
	  return syserror("writing to file '%s'", xto);
	}

      if (n < 0) {
	close(fd1); close(fd2); unlink(xto);
	return syserror("reading from file '%s'", xfrom);
      }
    }
    else {
      char buf[512];
      static char const zero[sizeof buf] = { 0 };
      int n;
      off_t zeros = 0;
    
      while ((n = read(fd1, buf, sizeof buf)) > 0) {
	if (memcmp(buf, zero, n) == 0)
	  zeros += n;
	else {
	  if (zeros) {
	    if (lseek(fd2, zeros, SEEK_CUR) < 0) {
	      close(fd1); close(fd2); unlink(xto);
	      return syserror("seeking file '%s'", xto);
	    }
	    zeros = 0;
	  }
	  if (write(fd2, buf, n) != n) {
	    close(fd1); close(fd2); unlink(xto);
	    return syserror("writing to file '%s'", xto);
	  }
	}
      }

      if (n < 0) {
	close(fd1); close(fd2); unlink(xto);
	return syserror("reading from file '%s'", xfrom);
      }

      if (zeros) {
	if (lseek(fd2, zeros - 1, SEEK_CUR) < 0) {
	  close(fd1); close(fd2); unlink(xto);
	  return syserror("seeking file '%s'", xto);
	}
      
	if (write(fd2, zero, 1) != 1) {
	  close(fd1); close(fd2); unlink(xto);
	  return syserror("writing to file '%s'", xto);
	}
      }
    }
  
    close(fd1);
    close(fd2);
    return Success;
  }

  Status
  renamefile(char const * from, char const * to,
	     const char *fromdbdir, const char *todbdir, int sparsify)
  {
    char *xfrom = makefile(fromdbdir, from);
    char *xto = makefile(todbdir, to);

#ifdef MVCP_TRACE
    printf("renaming '%s' to '%s' [%s . %s]\n", from, to, fromdbdir, todbdir);
#endif

    if (rename(xfrom, xto) < 0) {
      Status se;
      if (errno != EXDEV)
	return syserror("renaming file '%s' to '%s'", xfrom, xto);

#ifdef MVCP_TRACE
      printf("cannot rename file across 2 file systems\n");
#endif

      se = copyfile(from, to, fromdbdir, todbdir, sparsify);
      if (se)
	return statusMake(se->err, "renaming file '%s' to '%s': %s", xfrom, xto, se->err_msg);

      if (unlink(xfrom) < 0)
	return syserror("unlinking file '%s'", xfrom);
    }

    return Success;
  }

  static Status
  mvcp_immediate(const char *xstr, const char *from,
		 const char *to, const char *fromdbdir, const char *todbdir,
		 Status (*mvcp)(const char *, const char *,
				const char *, const char *, int))
  {
    Status s;
    if (strcmp(from, to) && (s = mvcp(from, to, fromdbdir, todbdir, 1)))
      return statusMake(INVALID_SHMFILES_COPY,
			"%s operation failed between "
			"'%s' and '%s': %s",
			xstr, from, to, s->err_msg);
    return Success;
  }

  static Status
  mvcp_datafiles(DbCreateDescription *dbc,
		 DbHandle *dbh,
		 DbHeader *db_header, int fd,
		 const char *fromdbdir, const char *todbdir,
		 const char *dbfile,
		 int flag,
		 Status (*mvcp)(const char *, const char *,
				const char *, const char *, int))
  {
    int i;
    Status s;
    for (i = 0; i < dbc->ndat; i++) {
      DbHeader _dbh(DBSADDR(dbh));
      char *from = makefile(fromdbdir, _dbh.dat(i).file());
      char *to = makefile(todbdir, dbc->dat[i].file);

      if (strcmp(from, to)) {
	if (s = mvcp(_dbh.dat(i).file(),
		     dbc->dat[i].file, fromdbdir, todbdir, 0))
	  return statusMake(INVALID_DATAFILES_COPY,
			    "%s operation failed between "
			    "'%s' and '%s': %s",
			    XSTR(flag), from, to, s->err_msg);

	if (s = mvcp(dmpfileGet(_dbh.dat(i).file()),
		     dmpfileGet(dbc->dat[i].file), fromdbdir, todbdir, 0))
	  return statusMake(INVALID_DATAFILES_COPY,
			    "%s operation failed between "
			    "'%s' and '%s': %s",
			    XSTR(flag),
			    dmpfileGet(from),
			    dmpfileGet(to),
			    s->err_msg);
      }

      strcpy(db_header->dat(i).file(), dbc->dat[i].file);

      if (lseek(fd, 0, 0) < 0)
	return syserror("rewing database file '%s'", dbfile);

      if (write(fd, db_header->_addr(), DbHeader_SIZE) != DbHeader_SIZE)
	return syserror("writing database file '%s'", dbfile);
    }

    return Success;
  }

  static Status
  mvcp_check(const char *fname, DbCreateDescription *dbc,
	     DbHandle *dbh,
	     const char *fromdbdir, const char *todbdir,
	     const char *dbfile, const char *ndbfile,
	     int flag)
  {
    int i;
    Status s;

    DbHeader _dbh(DBSADDR(dbh));
    unsigned int ndat = x2h_u32(_dbh.__ndat());
    if (dbc->ndat != ndat)
      return statusMake(INVALID_DATAFILE_CNT,
			"%s: different datafiles number: `%d' vs. `%d'",
			fname, dbc->ndat, ndat);

    for (i = 0; i < dbc->ndat; i++) {
      unsigned int maxsize = x2h_u32(_dbh.dat(i).__maxsize());
      if (!dbc->dat[i].maxsize)
	dbc->dat[i].maxsize = maxsize;
      else if (dbc->dat[i].maxsize != maxsize)
	return statusMake(INVALID_MAXSIZE,
			  "%s: different maximum size: `%d' vs. `%d' "
			  "on datafile #%d",
			  fname, dbc->dat[i].maxsize,
			  maxsize, i);
    }
  
    if (!strcmp(dbfile, ndbfile)) {
      if (flag)
	return statusMake(DBFILES_IDENTICAL,
			  "%s: identical database files: '%s'",
			  fname, dbfile);
    }

    if (flag) {
      if (!access(ndbfile, F_OK))
	return statusMake(DBFILE_ALREADY_EXISTS,
			  "%s: target database file already exists: '%s'",
			  fname, ndbfile);
      if (!access(shmfileGet(ndbfile), F_OK))
	return statusMake(SHMFILE_ALREADY_EXISTS,
			  "%s: target shm file already exists: '%s'",
			  fname, shmfileGet(ndbfile));
      if (!access(objmapfileGet(ndbfile), F_OK))
	return statusMake(OBJMAPFILE_ALREADY_EXISTS,
			  "%s: target oid map file already exists: '%s'",
			  fname, objmapfileGet(ndbfile));
    }

	    
    for (i = 0; i < dbc->ndat; i++) {
      char *to = makefile(todbdir, dbc->dat[i].file);
      char *from = makefile(fromdbdir, _dbh.dat(i).file());

      if (flag && !strcmp(from, to))
	return statusMake(DATAFILES_IDENTICAL,
			  "%s: identical data files: '%s'",
			  fname, to);
      if (strcmp(from, to) && !access(to, F_OK))
	return statusMake(DATAFILE_ALREADY_EXISTS,
			  "%s: target data file already exists: '%s'",
			  fname, to);
    }
    return Success;
  }

  static Status
  mvcp_realize(const char *fname, const char *dbfile,
	       const DbMoveDescription *xdmv, int flag)
  {
    DbMoveDescription dmv = *xdmv;
    DbHandle *dbh;
    DbHeader db_header;
    Status s;
    DbCreateDescription *dbc = &dmv.dcr;
    int i, fd;
    Status (*mvcp)(const char *, const char *, 
		   const char *, const char *, int);
    const char *fromdbdir = get_dir(dbfile);
    const char *todbdir = get_dir(dmv.dbfile);

    if (s = ESM_dbOpen(dbfile, VOLREAD, 0, 0, 0, 0, 0, 0, &dbh) )
      return s;

    if (s = mvcp_check(fname, dbc, dbh, fromdbdir, todbdir,
		       dbfile, dmv.dbfile, flag))
      return s;

    mvcp = (flag ? copyfile : renamefile);

    if (strcmp(dbfile, dmv.dbfile)) {
      if (s = mvcp(dbfile, dmv.dbfile, fromdbdir, todbdir, 1))
	return statusMake(INVALID_DBFILES_COPY,
			  "%s operation failed between "
			  "'%s' and '%s': %s",
			  XSTR(flag), dbfile, dmv.dbfile,
			  s->err_msg);
    }

    if ((fd = open(dmv.dbfile, O_RDWR)) >= 0) {
      if (read(fd, db_header._addr(), DbHeader_SIZE) != DbHeader_SIZE)
	return syserror("reading database file '%s'", dmv.dbfile);
    }
    else
      return statusMake(INVALID_DBFILE_ACCESS,
			"cannot open database file for writing: '%s'",
			dmv.dbfile);

    if (s = mvcp_immediate(XSTR(flag),
			   shmfileGet(dbfile), shmfileGet(dmv.dbfile),
			   fromdbdir, todbdir, mvcp))
      return s;

    if (s = mvcp_immediate(XSTR(flag),
			   objmapfileGet(dbfile), objmapfileGet(dmv.dbfile),
			   fromdbdir, todbdir, mvcp))
      return s;

    if (s = mvcp_datafiles(dbc, dbh, &db_header, fd, fromdbdir, todbdir,
			   dmv.dbfile, flag, mvcp))
      return s;

    close(fd);

    ESM_dbClose(dbh);

    if (s = ESM_dbOpen(dmv.dbfile, VOLREAD, 0, 0, 0, 0, 0, 0, &dbh))
      return s;

    ESM_dbClose(dbh);
    return Success;
  }

  Status
  dbMove(const char *dbfile, const DbMoveDescription *dmv)
  {
    return mvcp_realize("dbMove", dbfile, dmv, 0);
  }

  Status
  dbCopy(const char *dbfile, const DbCopyDescription *dcp)
  {
    return mvcp_realize("dbCopy", dbfile, dcp, 1);
  }

  Status
  dbRelocate(const char *dbfile, const DbRelocateDescription *rel)
  {
    DbHeader xdbh;
    int fd, i;
    Status se;

#undef PR
#define PR "dbRelocate: "
    if ( (fd = open(dbfile, O_RDWR)) < 0)
      return statusMake(INVALID_DBFILE_ACCESS, PR "cannot open database file for writing: '%s'", dbfile);

    if (se = syscheckn(PR, read(fd, xdbh._addr(), DbHeader_SIZE), DbHeader_SIZE, ""))
      return se;

    DbHeader dbh;
    x2h_dbHeader(&dbh, &xdbh);
    if (dbh.__magic() != MAGIC)
      return statusMake(INVALID_DBFILE, PR "database file '%s' is not a valid eyedbsm database file", dbfile);

    /*
      if (se = syscheck(PR, lseek(fd, 0, 0), ""))
      return se;
      if (se = syscheckn(PR, read(fd, &dbh, sizeof(dbh)), sizeof(dbh), ""))
      return se;
    */

    if (rel->ndat != dbh.__ndat()) {
      close(fd);
      return statusMake_s(INVALID_DATAFILE_CNT);
    }

    for (i = 0; i < dbh.__ndat(); i++)
      strcpy(dbh.dat(i).file(), rel->file[i]);

    if (se = syscheck(PR, lseek(fd, 0, 0), ""))
      return se;

    h2x_dbHeader(&xdbh, &dbh);
    if (se = syscheckn(PR, write(fd, xdbh._addr(), DbHeader_SIZE), DbHeader_SIZE, ""))
      return se;

    if (se = syscheck(PR, close(fd), ""))
      return se;

    return Success;
  }

  /*
   * database opening process
   */


  static Status
  shmMap(const char *dbfile, size_t size, int shmfd, bool no_shm_access,
	 void **pshm_addr, m_Map **pm_shm)
  {
#undef PR
#define PR "shmMap"
    int x;
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
    int flags = no_shm_access ? PROT_READ : PROT_READ|PROT_WRITE;
    for (x = 0; ; x++) {
      if (*pm_shm = m_mmap(0, size, flags,
			   MMAP_MMAP_FLAGS, shmfd,
			   0, (char **)pshm_addr, shmfileGet(dbfile), 0, 0)) {
	if (x)
	  IDB_LOG(IDB_LOG_MMAP, ("m_mmap successfull in shmMap after %d attemps\n",
				 x));
	break;
      }

      if (x == MAXTRIES)
	return statusMake(MAP_ERROR, PR "shmfile '%s' cannot be mapped by eyedbsm server", shmfileGet(dbfile));
      IDB_LOG(IDB_LOG_MMAP, ("m_mmap failed in shmMap, tries again\n"));
      sleep(1);
    }

    m_lock(*pm_shm);

    return Success;
  }

  static Status
  dbsUnmap(const char *dbfile, DbDescription *vd)
  {
    m_unlock(vd->m_dbs);

    if (m_munmap(vd->m_dbs, (char *)vd->dbs_addr, DBS_DEFSIZE))
      return statusMake(MAP_ERROR, PR "database system file '%s' "
			"cannot be unmapped by eyedbsm server", dbfile);

    return Success;
  }

  static Status
  shmUnmap(const char *dbfile, DbDescription *vd, unsigned int size)
  {
    m_unlock(vd->m_shm);

    if (m_munmap(vd->m_shm, (char *)vd->shm_addr_b, size))
      return statusMake(MAP_ERROR, PR "shmfile '%s' cannot be unmapped by eyedbsm server", shmfileGet(dbfile));

    return Success;
  }

  static Status
  shmMutexRelease(DbDescription *vd, DbShmHeader *shmh, unsigned int xid)
  {
    Status se;

    if (xid && (se = DbMutexesRelease(vd, shmh, xid)))
      return se;

    return Success;
  }

#define NO_BLOCK
  static void
  ESM_DbInitialize(DbDescription *vd, void *shm_addr, unsigned int shmsize)
  {
    DbMutexesInit(vd, (DbShmHeader *)shm_addr);
    ESM_transInit(vd, (char *)shm_addr, shmsize);
  }

  static Status
  ESM_dbOpenPrologue(DbDescription *vd, DbShmHeader *shmh,
		     unsigned int shmsize, const char *dbfile, int flags,
		     unsigned int *pxid)
  {
    XMHandle *xmh;
    char hostname[256+1];
    bool no_shm_access = (vd->flags & NO_SHM_ACCESS) != 0;

    IDB_LOG(IDB_LOG_MMAP, ("USE_MMAP_SYNC version -- NFS debug\n"));

#undef PR
#define PR "dbOpenPrologue: "

    if (shmh) {
      if (shmh->magic != MAGIC)
	return statusMake(INVALID_SHMFILE, PR "shm file is not a valid eyedbsm shm file: '%s'", shmfileGet(dbfile));

      gethostname(hostname, sizeof(hostname)-1);

      Mutex *mp = VD2MTX(vd, TRS);
    
      DbMutexesLightInit(vd, shmh);

      //MUTEX_LOCK(mp, 0);
      xmh = XMOpen(((char *)shmh) + SHM_HEADSIZE, vd);

      if (!xmh) {
	//MUTEX_UNLOCK(mp, 0);
	return statusMake(INVALID_SHMFILE, PR "shm file is not a valid eyedbsm shm file: '%s'", shmfileGet(dbfile));
      }

      Boolean mustUnlock = True;
      if (x2h_u32((unsigned int)shmh->hostid) != (unsigned int)gethostid() ||
	  strncmp(shmh->arch, eyedblib::CompileBuiltin::getArch(), sizeof( shmh->arch))) {
	return statusMake(DATABASE_OPEN_FAILED,
			  "cannot open database %s on "
			  "computer %s (hostid=%d) [architecture %s]: "
			  "database hold by computer %s (hostid=%d) [architecture %s]",
			  dbfile, hostname, gethostid(), eyedblib::CompileBuiltin::getArch(), shmh->hostname, x2h_u32((unsigned int)shmh->hostid),
			  shmh->arch);
      }
    }

    if (backend) {
      *pxid = rpc_getpid();

      if (!no_shm_access) {
	shmh->stat.total_db_access_cnt = h2x_u32(x2h_u32(shmh->stat.total_db_access_cnt)+1);
	shmh->stat.current_db_access_cnt = h2x_u32(x2h_u32(shmh->stat.current_db_access_cnt)+1);
      }
    }
    else {
      *pxid = import_xid;
    }

    /*
      if (mustUnlock)
      MUTEX_UNLOCK(mp, 0);
    */

    IDB_LOG(IDB_LOG_DATABASE, ("dbOpenPrologue(%s) -> xid = %d [backend %d]\n", dbfile, *pxid,
			       backend));

    return Success;
  }

  static void
  ESM_initHost(DbShmHeader *sm_shmh)
  {
    char hostname[256+1];
    gethostname(hostname, sizeof(hostname)-1);
    sm_shmh->hostid = x2h_u32(gethostid());
    strncpy(sm_shmh->hostname, hostname, sizeof(sm_shmh->hostname)-1);
    sm_shmh->hostname[sizeof(sm_shmh->hostname)-1] = 0;
    strncpy(sm_shmh->arch, eyedblib::CompileBuiltin::getArch(), sizeof( sm_shmh->arch));
  }

#define ESM_MMAP_WIDE_SEGMENT   2000

  static OpenHints *
  get_default_hints()
  {
    static OpenHints hints(SegmentMap, ESM_MMAP_WIDE_SEGMENT);
    return &hints;
  }

  static bool TRACE_CLEANUP = (getenv("EYEDBSM_TRACE_CLEANUP") != 0);
  static bool SLEEP_CLEANUP = (getenv("EYEDBSM_SLEEP_CLEANUP") != 0);
  
  static std::map<std::string, unsigned int> db_map;

  static Status db_clean_shm(const char *dbfile, int *lkfd, int shmfd)
  {
#undef PR
#define PR "dbOpenPrologue: "
    errno = 0;

    if (db_map.find(dbfile) != db_map.end()) {
      if (TRACE_CLEANUP) {
	fprintf(stderr, "eyedbsm: found database %s %d\n", dbfile, db_map[dbfile]);
      }
      db_map[dbfile]++;
      return Success;
    }

    const char *lockfile = fileGet(dbfile, ".lck");
    if ((*lkfd = open(lockfile, O_RDWR)) < 0) {
      struct stat st;
      mode_t file_mode = DEFAULT_CREATION_MODE;
      if (stat(shmfileGet(dbfile), &st) >= 0) {
	file_mode = st.st_mode;
      }

      int fd = fileCreate(lockfile, file_mode, (gid_t)-1);
      if (TRACE_CLEANUP) {
	fprintf(stderr, "eyedbsm: creating lockfile %s\n", lockfile);
      }

      if (fd < 0) {
	return statusMake(INVALID_DBFILE,
			  "%scannot create lock file: '%s' [%s]",
			  PR, lockfile, strerror(errno));
      }
      close(fd);

      if ((*lkfd = open(lockfile, O_RDWR)) < 0) {
	return statusMake(INVALID_DBFILE,
			  "%scannot open lock file: '%s' [%s]",
			  PR, lockfile, strerror(errno));
      }
    }

    if (filelockX(*lkfd)) {
      if (TRACE_CLEANUP) {
	fprintf(stderr, "eyedbsm: cleaning up database %s %d %s\n", dbfile, errno, strerror(errno));
      }

      dbCleanupRealize(shmfileGet(dbfile), shmfd);

      if (SLEEP_CLEANUP) {
	int sl = atoi(getenv("EYEDBSM_SLEEP_CLEANUP"));
	if (TRACE_CLEANUP) {
	  fprintf(stderr, "eyedbsm: waiting for %d seconds\n", sl);
	}
	sleep(sl);
      }

      if (!filelockS(*lkfd)) {
	return statusMake(ERROR, PR "cannot open database '%s': cannot lock dbfile in share mode", dbfile);
      }

      db_map[dbfile] = 1;
      return Success;
    }

    if (TRACE_CLEANUP) {
      fprintf(stderr, "eyedbsm: does not clean up database %s %d %s\n", dbfile, errno, strerror(errno));
    }

    for (int try_n = 0; !filelockS(*lkfd); try_n++) {
#define MAX_TRY_LOCK_CNT 100
      if (try_n == MAX_TRY_LOCK_CNT) {
	return statusMake(ERROR, PR "cannot open database '%s': cannot lock dbfile in share mode", dbfile);
      }
      if (TRACE_CLEANUP) {
	fprintf(stderr, "eyedbsm: waiting before continuing...\n");
      }
      usleep(10000);
    }

    if (TRACE_CLEANUP) {
      fprintf(stderr, "eyedbsm: continuing for database '%s'\n", dbfile);
    }

    db_map[dbfile] = 1;
    return Success;
  }

  Status
  ESM_dbOpen(const char *dbfile, int flags,
	     const OpenHints *hints, int *id,
	     void **pdblock, int create_mode, unsigned int xid,
	     unsigned int *pversion, DbHandle **pdbh)
  {
    int hdfd, shmfd, ompfd, va, fop, i;
    int const opf = (flags & VOLREAD) ? O_RDONLY : O_RDWR;
    int const accflags = (flags & VOLREAD ? R_OK : R_OK|W_OK);
    bool no_shm_access = (flags & NO_SHM_ACCESS) != 0;
    size_t size;
    DbDescription *vd;
    DbHeader *dbh = NULL;
    Status se;
    Boolean suser = True;
    void *shm_addr;
    int x;
    size_t shmsize;
    unsigned int version;

    //fprintf(stderr, "EV WORKING VERSION 2014-05-30\n");
    //fflush(stderr);
    // for compilation test
    /*
      unsigned int nss = MapHeader_nslots((unsigned char *)0);
      DbHeader__ dbh_(0);
      unsigned int xxx = dbh_.__magic();
    */

    if (!hints) {
      hints = get_default_hints();
    }

    if (hints->maph != WholeMap && hints->maph != SegmentMap) {
      return statusMake(DATABASE_OPEN_FAILED, "invalid open hints %d",
			hints->maph);
    }

    m_init_flags(hints->m_mmap_flags);

#undef PR
#define PR "dbOpen: "

#ifdef TRACE
    utshm("ESM_dbOpen(%s)\n", dbfile);
#endif

    if (flags == (VOLRW|NO_SHM_ACCESS)) {
      return statusMake(INVALID_FLAG, PR "flag cannot be set to VOLRW|NO_SHM_ACCESS");
    }

    if (flags != VOLREAD && flags != VOLRW && flags != (VOLREAD|NO_SHM_ACCESS)) {
      return statusMake(INVALID_FLAG, PR "flag is invalid: %u", flags);
    }

    if (se = checkFileAccess(DATABASE_OPEN_FAILED, "shm file", shmfileGet(dbfile), accflags))
      return se;

    vd = (DbDescription *)m_calloc(sizeof(DbDescription), 1);

#ifndef HAVE_EYEDBSMD
    smdcli_conn_t *conn = 0;
#else
    smdcli_conn_t *conn = smdcli_open(smd_get_port());
    if (!conn) {
      free(vd);
      return statusMake(ERROR, "cannot connect to eyedbsmd on port "
			"%s", smd_get_port());
    }
#ifdef HAVE_SEMAPHORE_POLICY_SYSV_IPC
    if (smdcli_init_getsems(conn, dbfile, vd->semkeys)) {
      free(vd);
      free(conn);
      return statusMake(ERROR, "protocol error with eyedbsmd on port "
			"%s", smd_get_port());
    }
#else
    if (smdcli_init(conn, dbfile)) {
      free(vd);
      free(conn);
      return statusMake(ERROR, "protocol error with eyedbsmd on port "
			"%s", smd_get_port());
    }
#endif
#endif

    if ((shmfd = shmfileOpen(dbfile, no_shm_access)) < 0) {
      free(vd);
      return statusMake(INVALID_SHMFILE_ACCESS, PR "shm file '%s'",
			shmfileGet(dbfile));
    }

    vd->shmfd = shmfd;
    vd->conn = conn;

    if ((ompfd = objmapfileOpen(dbfile, opf)) < 0) {
      free(vd);
      return statusMake(INVALID_OBJMAP_ACCESS, PR "objmap file '%s'",
			objmapfileGet(dbfile));
    }

    shmsize = fdSizeGet(shmfd);

    if ((se = shmMap(dbfile, shmsize, shmfd, no_shm_access, (void **)&vd->shm_addr_b,
		     &vd->m_shm)) != Success) {
      free(vd);
      return se;
    }

    vd->shm_addr = vd->shm_addr_b;

    if (se = checkFileAccess(DATABASE_OPEN_FAILED, "database file", dbfile, accflags)) {
      free(vd);
      return se;
    }

    if ((se = dopen(PR, dbfile, opf, &hdfd, &suser)) != Success) {
      free(vd);
      return se;
    }

    DbHeader xdbh;
    if (se = syscheckn(PR, read(hdfd, xdbh._addr(), DbHeader_SIZE), DbHeader_SIZE, "")) {
      free(vd);
      free(dbh);
      return se;
    }

#ifndef HAVE_EYEDBSMD
    if (!no_shm_access) {
      if (se = db_clean_shm(dbfile, &vd->lkfd, shmfd)) {
	free(vd);
	free(dbh);
	return se;
      }
    }
#endif

    dbh = new DbHeader();
    x2h_dbHeader(dbh, &xdbh);

    if (dbh->__magic() != MAGIC) {
      free(vd);
      delete dbh;
      return statusMake(INVALID_DBFILE, PR "database file '%s' is not a valid eyedbsm database file", dbfile);
    }

    shm_addr = vd->shm_addr;

    version = x2h_u32(((DbShmHeader *)shm_addr)->version);

    if (pversion && *pversion && version > *pversion) {
      char str_version[32];
      char str_pversion[32];
      strcpy(str_version, string_version(version));
      strcpy(str_pversion, string_version(*pversion));
      free(vd);
      delete dbh;
      return statusMake(ERROR, "version of database '%s' (%s) is upper "
			"than the EyeDB version (%s): cannot be opened",
			dbfile, 
			str_version, str_pversion);
    }

    vd->version = version;

    if (no_shm_access) {
      shm_addr = vd->shm_addr = 0;
    }


    fop = ((flags & VOLREAD) ? PROT_READ : PROT_READ|PROT_WRITE);
    vd->dbid = dbh->__dbid();
    vd->flags = flags;
    vd->rsuser = vd->suser = suser;
    vd->hints = *hints;

#ifdef ESM_DBG
    printf("FLAGS %d\n", flags);
#endif
    /* maps dbs file */
    if (!(vd->m_dbs = m_mmap(0, DBS_DEFSIZE, fop, MMAP_MMAP_FLAGS, hdfd, 0,
			     (char **)&vd->dbs_addr, dbfile, 0, 0))) {
      shmUnmap(dbfile, vd, shmsize);
      free(vd);
      delete dbh;
      return statusMake(MAP_ERROR, "unexpected and unrecoverable mmap error in database opening process: '%s'", dbfile);
    }

    m_lock(vd->m_dbs);

    char pwd[DEFAULT_PWD_SIZE];
    se = push_dir(dbfile, pwd, sizeof pwd);
    if (se) return se;

    /* maps header file */
    for (i = 0; i < dbh->__ndat(); i++) {
      if (!*dbh->dat(i).file()) {
	vd->m_dmp[i] = 0;
	vd->dmp_addr[i] = 0;
	continue;
      }
      const char *dmpfile = dmpfileGet(dbh->dat(i).file());
      int fd = open(dmpfile, opf);
      if (fd < 0) {
	pop_dir(pwd);
	return statusMake(DATABASE_OPEN_FAILED,
			  PR "cannot open data map file '%s' for writing",
			  dmpfile);
      }
    
      if (flags != (VOLREAD|NO_SHM_ACCESS)) { // EV vmem OPT
	if ((flags & VOLREAD) != 0) {
	  size = DMP_SIZE(dbh->dat(i).mp()->mtype(), (dbh->dat(i).__lastslot()+1));
	  
	} else {
	  size = DMP_SIZE(dbh->dat(i).mp()->mtype(), dbh->dat(i).mp()->nslots());
	}

	if (!size) {
	  size = ONE_K;
	}

	if (!(vd->m_dmp[i] = m_mmap(0, size, fop, MMAP_MMAP_FLAGS, fd, 0,
				    (char **)&vd->dmp_addr[i],
				    dmpfileGet(dbh->dat(i).file()), 0, 0))) {
	  shmUnmap(dbfile, vd, shmsize);
	  dbsUnmap(dbfile, vd);
	  /* should unmap all other dmpfiles */
	  free(vd);
	  delete dbh;
	  pop_dir(pwd);
	  perror("mmap");
	  return statusMake(MAP_ERROR,
			    "unexpected and unrecoverable mmap error in "
			    "database opening process (dbfile='%s') for data map file:  ", dbfile);
	}
    
	m_lock(vd->m_dmp[i]);
      }

      if ((m_mmap_flags & M_NFS_FIX_NO_CLOSE_FD_MODE) == 0) {
	if (se = syscheck(PR, close(fd), "")) {
	  delete dbh;
	  free(vd);
	  pop_dir(pwd);
	  return se;
	}
      }
    }

    /* la size deborde si le nombre d'objs  ~ 1G => probleme
     * il faut faire un mapping plus siouks! */

    if ((flags & VOLREAD) != 0) {
      //fprintf(stderr, "last idx busy %u nbobj=%u\n", dbh->__lastidxbusy(), dbh->__nbobjs());
      size = OIDMAP_SIZE((dbh->__lastidxbusy()+1));
    } else {
      size = OIDMAP_SIZE(dbh->__nbobjs());
    }
    if (size < ONE_K) {
      size = ONE_K;
    }

    if (!(vd->m_omp = m_mmap(0, size, fop, MMAP_MMAP_FLAGS, ompfd, 0,
			     (char **)&vd->omp_addr,
			     objmapfileGet(dbfile), 0, 0))) {
      dbsUnmap(dbfile, vd);
      shmUnmap(dbfile, vd, shmsize);
      /* should unmap all other dmpfiles */
      free(vd);
      delete dbh;
      pop_dir(pwd);
      return statusMake(MAP_ERROR, "unexpected and unrecoverable mmap error in "
			"database opening process (dbfile: '%s') for object map file %s", dbfile,
			objmapfileGet(dbfile));
    }
    m_lock(vd->m_omp);

    if ((m_mmap_flags & M_NFS_FIX_NO_CLOSE_FD_MODE) == 0) {
      if (se = syscheck(PR, close(hdfd), "")) {
	delete dbh;
	free(vd);
	pop_dir(pwd);
	return se;
      }

      if (se = syscheck(PR, close(ompfd), "")) {
	delete dbh;
	free(vd);
	pop_dir(pwd);
	return se;
      }
    }
  
    /* open all datafiles */
    for (i = 0; i < dbh->__ndat(); i++) {
      vd->dmd[i].file = strdup(dbh->dat(i).file());
      if (!*dbh->dat(i).file()) {
	vd->dmd[i].fd = -1;
	continue;
      }
    
      Status status;
      if (se = checkFileAccess(DATABASE_OPEN_FAILED, "datafile", dbh->dat(i).file(), accflags)) {
	delete dbh;
	free(vd);
	pop_dir(pwd);
	return se;
      }
    
      if ((status = dopen(PR, dbh->dat(i).file(), opf, &vd->dmd[i].fd,
			  &vd->suser)) != Success) {
	int j;
	for (j = 0; j < i; j++)
	  if (vd->dmd[j].fd >= 0 &&
	      (se = syscheck(PR, close(vd->dmd[j].fd), ""))) {
	    delete dbh;
	    free(vd);
	    pop_dir(pwd);
	    return se;
	  }
	
	delete dbh;
	free(vd);
	pop_dir(pwd);
	return status;
      }

      /*
	printf("opening datafile %s -> fd=%d, maxsize=%llu\n", dbh->dat[i].file,
	vd->dmd[i].fd, (unsigned long long)dbh->dat[i].maxsize*1024);
      */
    
      if (hints->maph == WholeMap) {
	if (!(vd->dmd[i].m_dat = m_mmap(0, (size_t)dbh->dat(i).__maxsize()*ONE_K,
					fop, MMAP_MMAP_FLAGS, vd->dmd[i].fd, 0,
					(char **)&vd->dmd[i].addr,
					dbh->dat(i).file(), 0, 0))) {
	  shmUnmap(dbfile, vd, shmsize);
	  dbsUnmap(dbfile, vd);
	  free(vd);
	  delete dbh;
	  pop_dir(pwd);
	  return statusMake(MAP_ERROR,
			    "unexpected and unrecoverable mmap error in "
			    "database opening process (dbfile='%s') for data map file:  ", dbfile,
			    dbh->dat(i).file());
	}
	//printf("MAPPING ALL DATAFILE\n");
	m_lock(vd->dmd[i].m_dat);
      }
      else {
	vd->dmd[i].m_dat = 0;
	vd->dmd[i].addr = 0;

	unsigned int mapwide = (hints->mapwide ? hints->mapwide : ESM_MMAP_WIDE_SEGMENT);
	vd->mapwide = mapwide * pgsize;
	vd->mapwide2 = vd->mapwide >> 1;
	//printf("MAPPING SEGMENT DATAFILE -> %d\n", mapwide);
      }

      if (se = syscheck(PR, fcntl(vd->dmd[i].fd, F_SETFD, 1), "")) {
	delete dbh;
	free(vd);
	pop_dir(pwd);
	return se;
      }
    }

    if (create_mode) {
      ESM_initHost((DbShmHeader *)shm_addr);
      ESM_DbInitialize(vd, shm_addr, shmsize);
    }

    se = ESM_dbOpenPrologue(vd, (DbShmHeader *)shm_addr, shmsize, dbfile, flags,
			    &xid);
  
    if (se) {
      delete dbh;
      free(vd);
      pop_dir(pwd);
      return se;
    }

    ALIGN4(vd->omp_addr);

    *pdbh = (DbHandle *)m_calloc(sizeof(DbHandle), 1);
    (*pdbh)->vd = vd;

    assert(!pdblock); // 17/09/06

    if (pdblock)
      *pdblock = &((DbShmHeader *)shm_addr)->dblock_W;

#if 1
    if (pversion)
      *pversion = version;
#else
    if (pversion)
      *pversion = x2h_u32(((DbShmHeader *)shm_addr)->version);
#endif

    (*pdbh)->vd->xid = xid;

    if (no_shm_access) {
      (*pdbh)->vd->trs_mh = 0;
    }
    else {
      (*pdbh)->vd->trs_mh = XMOpen(((char *)shm_addr) + SHM_HEADSIZE, vd);
    }

    /* 9/1/00: does not support anymore linkmap allocator for a while */
    /*
      if ((*pdbh)->vd->dbs_addr->state == ESM_OPENING_STATE &&
      (*pdbh)->vd->dbs_addr->mp.mtype == LinkmapType)
      {
      LinkmapCell cell;

      cell.size = dbh->mp.nslots;
      cell.ns = 0;
      cell.prev = cell.next = InvalidCell;
      memcpy(vd->mapaddr, &cell, sizeof(cell));
      }
    */

    delete dbh;

    (*pdbh)->dbfile = strdup(dbfile);

    if (flags == VOLRW) {
      se = ESM_transactionsGarbage(*pdbh, True);
      if (se) {
	pop_dir(pwd);
	return se;
      }
    }

    // 09/03/06: it seems to me that (*pdbh)->vd->dbs_addr->state
    // must be swapped !!
    if (DbHeader((*pdbh)->vd->dbs_addr).state() == OPENING_STATE) {
      pop_dir(pwd);
      return Success;
    }

    if (se = dbProtectionRunTimeUpdate(*pdbh)) {
      pop_dir(pwd);
      return se;
    }

    pop_dir(pwd);
    return protectionRunTimeUpdate(*pdbh);
  }

  int ESM_getOpenFlags(DbHandle const *dbh)
  {
    return dbh->vd->flags;
  }

  /*
   * database close process
   *
   */

  static Status
  ESM_dbCloseEpilogue(DbDescription *vd, DbShmHeader *shmh, unsigned int xid,
		      int flags, const char *dbfile)
  {
    Status se;
    XMHandle *xmh;
    bool no_shm_access = (vd->flags & NO_SHM_ACCESS) != 0;

    IDB_LOG(IDB_LOG_DATABASE, ("dbCloseEpilogue(%s) #2\n", dbfile));

    if (!no_shm_access) {
      xmh = XMOpen(((char *)shmh) + SHM_HEADSIZE, vd);

      if (!xmh)
	return statusMake(INVALID_SHMFILE, PR "shm file is not a valid eyedbsm shm file: '%s'", shmfileGet(dbfile));
      
      IDB_LOG(IDB_LOG_DATABASE, ("dbCloseEpilogue(%s) #1\n", dbfile));
      
      //MUTEX_LOCK(&shmh->main_mp, xid);
      shmh->stat.current_db_access_cnt--;

      if (se = ESM_transactionsRelease(vd, shmh, dbfile, xid, xmh, 0))
	return se;

      if (se = shmMutexRelease(vd, shmh, xid))
	return se;
    }

    return Success;
  }

  Status
  ESM_dbClose(const DbHandle *dbh)
  {
    Status se;
    int i;

    IDB_LOG(IDB_LOG_DATABASE, ("dbClose(%s)\n", dbh->dbfile));

    //    std::cout << "starting DB close\n";
    //m_display();

#undef PR
#define PR "dbClose: "

    if (!check_dbh(dbh))
      return statusMake(INVALID_DB_HANDLE, PR IDBH);

    DbHeader _dbh(DBSADDR(dbh));
    unsigned int ndat = x2h_u32(_dbh.__ndat());
    for (i = 0; i < ndat; i++) {
      MmapDesc *mmd, *mmend = &dbh->vd->dmd[i].mmd[MAX_MMAP_SEGMENTS];

      if (dbh->vd->m_dmp[i]) {
	int mtype = x2h_u16(_dbh.dat(i).mp()->mtype());
	int nslots = x2h_u32(_dbh.dat(i).mp()->nslots());
	unsigned int size = DMP_SIZE(mtype, nslots);
	if (m_munmap(dbh->vd->m_dmp[i], dbh->vd->dmp_addr[i], size))
	  return statusMake(MAP_ERROR, PR "cannot unmap dmp file");
      }

#if 0
      if (dbh->vd->dmd[i].fd >= 0 &&
	  (se = syscheck(PR, close(dbh->vd->dmd[i].fd), "")))
	return se;
#endif

      for (mmd = dbh->vd->dmd[i].mmd; mmd < mmend; mmd++) {
	if (mmd->ismapped)
	  SEGMENT_UNMAP(mmd);
      }

#if 1
      if (dbh->vd->dmd[i].fd >= 0 &&
	  (se = syscheck(PR, close(dbh->vd->dmd[i].fd), "")))
	return se;
#endif
    }
    unsigned int nbobjs = x2h_u32(_dbh.__nbobjs());
    m_munmap(dbh->vd->m_omp, (char *)dbh->vd->omp_addr, OIDMAP_SIZE(nbobjs));

    /*
      m_munmap(dbh->vd->m_db, (char *)dbh->vd->dbs_addr,
      DBS_SIZE(DBH2MP(dbh)->mtype, DBH2MP(dbh)->nslots));
    */
    dbsUnmap(dbh->dbfile, dbh->vd);

    if (backend)
      ESM_dbCloseEpilogue(dbh->vd, (DbShmHeader *)dbh->vd->shm_addr, dbh->vd->xid,
			  dbh->vd->flags, dbh->dbfile);

    if (se = shmUnmap(dbh->dbfile, dbh->vd, fdSizeGet(dbh->vd->shmfd))) {
      return se;
    }

    if (se = syscheck(PR, close(dbh->vd->shmfd), "")) {
      return se;
    }
#ifndef HAVE_EYEDBSMD
    if (!--db_map[dbh->dbfile]) {
      if (TRACE_CLEANUP) {
	fprintf(stderr, "eyedbsm: closing lockfile map\n");
      }

      if (se = syscheck(PR, close(dbh->vd->lkfd), "")) {
	return se;
      }

      db_map.erase(dbh->dbfile);
    }
#endif

    if (dbh->vd->conn) {
      smdcli_close(dbh->vd->conn);
    }

    //m_unmmap_all();

    XMClose(dbh->vd->trs_mh);

    free(dbh->vd);
    free(dbh->dbfile);
    memset((char *)dbh, 0, sizeof(*dbh)); // secure
    free((char *)dbh);

    //std::cout << "ending DB close\n";

    return Success;
  }

  int
  ESM_dataBaseIdGet(DbHandle const *dbh)
  {
    return dbh->vd->dbid;
  }

  int
  dbidGet(const Oid *oid)
  {
    return OIDDBIDGET(oid);
  }

  void
  dbidSet(Oid *oid, int dbid)
  {
    OIDDBIDMAKE(oid, dbid);
  }

  Oid::NX
  getTotalObjectCount(DbHandle const *dbh)
  {
    DbHeader _dbh(DBSADDR(dbh));
    Oid::NX curobj_cnt = 0;

    unsigned int ndat = x2h_u32(_dbh.__ndat());
    for (int datid = 0; datid < ndat; datid++) {
      if (isDatValid(dbh, datid)) {
	MapHeader mp = DAT2MP(dbh, datid);
	curobj_cnt += x2h_u32(mp.mstat_u_bmstat_obj_count());
      }
    }

    return curobj_cnt;
  }

#define BLKIDXALLOC_INC 10000

  Status
  nxFileSizeExtends(DbHandle const *dbh, Oid::NX cur_nx)
  {
    Oid::NX lastidxblkalloc = cur_nx + BLKIDXALLOC_INC;
    Oid::NX lastidxbusy = x2h_u32(LASTIDXBUSY(dbh));

    char pwd[DEFAULT_PWD_SIZE];
    Status status = push_dir(dbh->dbfile, pwd, sizeof pwd);
    if (status) return status;

    if (lastidxblkalloc < lastidxbusy)
      lastidxblkalloc = lastidxbusy + 1;

    const char *file = objmapfileGet(dbh->dbfile);
    size_t size = OIDMAP_SIZE(lastidxblkalloc);
    size_t cursize = fileSizeGet(file);

    if (cursize == ~0) {
      pop_dir(pwd);
      return statusMake(ERROR, "cannot stat file '%s'", file);
    }

    if (cursize < size) {
      IDB_LOG(IDB_LOG_MMAP, ("nxFileSizeExtends omp %s %llu -> %llu\n", file, cursize, size));
      if (truncate(file, size) < 0) {
	pop_dir(pwd);
	return statusMake(ERROR, "nxFileSizeExtends: "
			  "unexpected error reported by truncate "
			  "on map file '%s': %s", file, strerror(errno));
      }
    }
  
    LASTIDXBLKALLOC(dbh) = h2x_u32(lastidxblkalloc);
    return pop_dir(pwd);
  }

#define BLKNSALLOC_INC (40000/BITS_PER_BYTE)

  Status
  nsFileSizeExtends(DbHandle const *dbh, short datid, NS curb)
  {
    NS lastnsblkalloc = curb + BLKNSALLOC_INC;
    DbHeader _dbh(DBSADDR(dbh));
    const char *file = dmpfileGet(_dbh.dat(datid).file());
    size_t size = lastnsblkalloc;

    char pwd[DEFAULT_PWD_SIZE];
    Status status = push_dir(dbh->dbfile, pwd, sizeof pwd);
    if (status) return status;

    size_t cursize = fileSizeGet(file);

    if (cursize == ~0) {
      pop_dir(pwd);
      return statusMake(ERROR, "cannot stat file '%s'", file);
    }

    if (cursize < size) {
      IDB_LOG(IDB_LOG_MMAP, ("nsFileSizeExtends dmp %s %llu -> %llu\n", file, cursize, size));
      if (truncate(file, size) < 0) {
	pop_dir(pwd);
	return statusMake(ERROR, "nsFileSizeExtends: "
			  "unexpected error reported by truncate "
			  "on map file '%s': %s", file, strerror(errno));
      }
    }
  
    LASTNSBLKALLOC(dbh, datid) = h2x_u32(lastnsblkalloc);
    return pop_dir(pwd);
  }

  Status
  objectNumberSet(DbHandle const *dbh, Oid::NX maxobjs)
  {
    DbHeader _dbh(DBSADDR(dbh));
    DbShmHeader *shmh = dbh->vd->shm_addr;

    Oid::NX curobj_cnt = getTotalObjectCount(dbh);
    if (maxobjs < curobj_cnt)
      return statusMake(ERROR,
			"objectNumberSet: cannot decrease object number "
			"to %d: current object number is %d", maxobjs,
			curobj_cnt);

#ifndef NO_FILE_LOCK
#error "NO_FILE_LOCK not defined"
    if (!filelockX(dbh->vd->shmfd))
      return statusMake(ERROR,
			"objectNumberSet: cannot change object number "
			"when clients are connected.");
#endif

    _dbh.__nbobjs() = h2x_u32(maxobjs);

    return Success;
  }

  Status
  objectNumberGet(DbHandle const *dbh, Oid::NX *maxobjs)
  {
    DbHeader _dbh(DBSADDR(dbh));

    *maxobjs = x2h_u32(_dbh.__nbobjs());

    return Success;
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

  Status
  shmSizeGet(DbHandle const *dbh, int *shmsize)
  {
    struct stat stat;

    int shmfd = shmfileOpen(dbh->dbfile, true);
    if (shmfd < 0 || fstat(shmfd, &stat) < 0) {
      return statusMake(INVALID_DBFILE_ACCESS,
			"cannot open shm file for writing: '%s'",
			shmfileGet(dbh->dbfile));
    }

    *shmsize = (int)(stat.st_size/ONE_K);
    return Success;
  }

  Status
  shmSizeSet(DbHandle const *dbh, int shmsize)
  {
    shmsize *= ONE_K;

    DbShmHeader dbhshm;

    int shmfd = shmfileOpen(dbh->dbfile, false);
#ifndef NO_FILE_LOCK
    if (!filelockX(shmfd)) {
      return statusMake(ERROR,
			"shmSizeSet: cannot change shm size "
			"when clients are connected.");
    }
#endif

    if (shmsize < MINSHMSIZE) {
      return statusMake(ERROR, "logsize %d MB is too small (minimum is %d MB)",
			shmsize/ONE_M, MINSHMSIZE/ONE_M);
    }

    if (shmsize > MAXSHMSIZE) {
      return statusMake(ERROR, "logsize %d MB too large (maximum is %d MB)",
			shmsize/ONE_M, MAXSHMSIZE/ONE_M);
    }

    if (read(shmfd, &dbhshm, sizeof(dbhshm)) < 0) {
      return statusMake(ERROR, "cannot read shmfile '%s'", shmfileGet(dbh->dbfile));
    }

    if (dbhshm.magic != MAGIC)
      return statusMake(ERROR, "shmfile '%s' is not a valid eyedb shmfile\n",
			shmfileGet(dbh->dbfile));

    if (dbhshm.trs_hdr.tr_cnt) {
      /* seems to be in used: must check for active transactions */
      return statusMake(ERROR, "shmfile %s is currently in use, cannot be resized", shmfileGet(dbh->dbfile));
    }

    IDB_LOG(IDB_LOG_MMAP, ("ftruncate shmfile %s %llu\n", shmfileGet(dbh->dbfile), shmsize));
    if (ftruncate(shmfd, shmsize)) {
      return statusMake(ERROR, "ftruncate(\"%s\", %u) returns: '%s'\n",
			shmfileGet(dbh->dbfile), shmsize, strerror(errno));
    }
    
    ESM_DbInitialize(dbh->vd, dbh->vd->shm_addr_b, shmsize);
    
#ifndef NO_FILE_LOCK
    ut_file_unlock(shmfd);
#endif
    return Success;
  }

  Boolean
  isDatValid(DbHandle const *dbh, short datid)
  {
    DbHeader _dbh(DBSADDR(dbh));
    return (datid >= 0 && datid < x2h_u32(_dbh.__ndat()) &&
	    dbh->vd->dmd[datid].fd >= 0) ?
      True : False;
  }

  unsigned int
  getDbVersion(void *dbh)
  {
#if 1
    return ((DbHandle *)dbh)->vd->version;
#else
    return x2h_u32(((DbHandle *)dbh)->vd->shm_addr->version);
#endif
  }

  Boolean
  isWholeMapped(void *dbh)
  {
    return ((DbHandle *)dbh)->vd->hints.maph == WholeMap ? True : False;
  }

  static Status
  dbCleanupRealize(const char *shmfile, int sm_fdshm)
  {
    caddr_t shm_addr;
    Status status;
    DbHandle *sm_dbh;
    DbHandle *dbh;
    DbShmHeader *sm_shmh;
    DbHeader *sm_h;
    XMHandle *sm_xmh;
    size_t sm_shmsize;

    sm_shmsize = fdSizeGet(sm_fdshm);

    shm_addr = (caddr_t)mmap(0, sm_shmsize, PROT_READ|PROT_WRITE,
			     MMAP_MMAP_FLAGS, sm_fdshm, 0);

    if (shm_addr == MAP_FAILED)
      return statusMake(ERROR, 
			"cannot map file '%s' for writing\n", shmfile);

    sm_shmh = (DbShmHeader *)shm_addr;
    sm_xmh = XMOpen(shm_addr + SHM_HEADSIZE, 0);

    unsigned int version = x2h_u32(sm_shmh->version);

    DbStat stat = sm_shmh->stat;
    cleanup = True;
    memset(sm_shmh, 0, sizeof(DbShmHeader));
    sm_shmh->magic = MAGIC;
    sm_shmh->version = h2x_u32(version ? version : 20508);
    //sm_shmh->version = h2x_u32(version);
    sm_shmh->stat = stat;
    sm_shmh->stat.current_db_access_cnt = 0;
    Mutex mp;
    mutexInit(0, &mp, &sm_shmh->main_mp, "SHMMAIN");
    ESM_transInit(0, (char *)sm_shmh, sm_shmsize);
    DbMutexesInit(0, sm_shmh);

    if (sm_xmh)
      XMInit(sm_xmh);

    ESM_initHost(sm_shmh);

    msync(shm_addr, sm_shmsize, MMAP_SYNC_FLAGS);
    munmap(shm_addr, sm_shmsize);

    cleanup = False;

    return Success;
  }

  Status
  dbCleanup(const char *dbfile)
  {
    extern Boolean cleanup;
    const char *shmfile = shmfileGet(dbfile);
    int fd;

    if ((fd = open(dbfile, O_RDWR)) < 0)
      return statusMake(ERROR, "cannot open dbfile %s for writing",
			dbfile);
    
    close(fd);

    fd = open(shmfile, O_RDWR);

    if (fd < 0)
      return statusMake(ERROR, "cannot open shmfile %s for writing",
			shmfile);

#ifndef NO_FILE_LOCK
#error "NO_FILE_LOCK not defined"
    if (ut_file_lock(fd, ut_LOCKX, ut_NOBLOCK) < 0 &&
	!getenv("EYEDBFORCECLEANUP")) {
      close(fd);
      return statusMake(CANNOT_LOCK_SHMFILE,
			"cannot cleanup shmem file %s: currently used by"
			" other clients", shmfile);
    }
#endif

    Status s = dbCleanupRealize(shmfile, fd);
    close(fd);
    return s;
  }
}
