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

#include <eyedblib/filelib.h>
#include <eyedblib/rpc_lib.h>
#include <kern_p.h>

#define NEW_FILE_ACCESS

#define ACCESS_FILE_FMT \
 "eyedbsm [pid = %d] running under user %s [uid = %d] : "

namespace eyedbsm {
  const char *
  fileGet(const char *dbfile, const char ext[])
  {
#define NN 4
    static char file[NN][512];
    static int n;
    char *p, *s;

    if (n == NN)
      n = 0;
    s = file[n++];
    strcpy(s, dbfile);
    if (p = strrchr(s, '.'))
      *p = 0;
    strcat(s, ext);

    return s;
  }

  const char *
  shmfileGet(const char *dbfile)
  {
    return fileGet(dbfile, shmext);
  }

  const char *
  dmpfileGet(const char *volfile)
  {
    return fileGet(volfile, dmpext);
  }

  const char *
  objmapfileGet(const char *dbfile)
  {
    return fileGet(dbfile, ompext);
  }

  Status
  checkVolMaxSize(unsigned int maxsize)
  {
    /*
      if (maxsize <= 0)
      return statusMake(INVALID_DATAFILEMAXSIZE,
      "negative volume file maximum size: `%d'",
      maxsize);

      if ((((unsigned long long)(maxsize)) * ONE_K) >
      (unsigned long long)ESM_MAX_DATAFILE_SIZE)
      return statusMake(SIZE_TOO_LARGE,
      "volume file maximum size is too large: "
      "`%llu bytes', maximum allowed size is `%llu'.",
      ((unsigned long long)(maxsize)) * ONE_K,
      ESM_MAX_DATAFILE_SIZE);
    */

    return Success;
  }

  Boolean
  filelockS(int fd)
  {
    return ut_file_lock(fd, ut_LOCKS, ut_NOBLOCK) >= 0 ? True : False;
  }

  Boolean
  filelockX(int fd)
  {
    return ut_file_lock(fd, ut_LOCKX, ut_NOBLOCK) >= 0 ? True : False;
  }

  Boolean
  fileunlock(int fd)
  {
    return ut_file_unlock(fd) == 0 ? True : False;
  }

  int
  shmfileOpen(const char *dbfile, bool strict_read)
  {
    int fd = open(shmfileGet(dbfile), strict_read ? O_RDONLY : O_RDWR);
    // we defined NO_FILE_LOCK because of a problem (?) of lock+mmap on
    // NFS files on solaris 7+
#ifndef NO_FILE_LOCK
#error "NO_FILE_LOCK not defined"
    if (ut_file_lock(fd, ut_LOCKS, ut_NOBLOCK) < 0) {
      close(fd);
      return -1;
    }
#endif
    return fd;
  }
    
  int
  objmapfileOpen(const char *dbfile, int flag)
  {
    int fd = open(objmapfileGet(dbfile), flag);
    return fd;
  }
    
  Status
  syserror(const char *fmt, ...)
  {
    Status status;
    char buf[1024];
    int const err = errno;
    va_list ap;
    va_start(ap, fmt);

    if (!fmt)
      buf[0] = 0;
    else
      vsprintf(buf, fmt, ap);

    va_end(ap);

    if (errno)
      return statusMake(SYS_ERROR, "%s: %s", buf,
			strerror(err));

    return statusMake(SYS_ERROR, "%s", buf);
  }

  Status
  syscheck(const char *pre, long long c, const char *fmt, ...)
  {
    int const err = errno;
    va_list ap;
    va_start(ap, fmt);

    if (c < 0)
      {
	Status status;
	char buf[256];

	if (!fmt)
	  buf[0] = 0;
	else
	  vsprintf(buf, fmt, ap);

	va_end(ap);
	return statusMake(SYS_ERROR, "%s%s: errno '%s'", pre, buf,
			  strerror(err));
      }

    va_end(ap);
    return Success;
  }

  Status
  syscheckn(const char *pre, long long c, int n, const char *fmt, ...)
  {
    int const err = errno;
    va_list ap;
    va_start(ap, fmt);

    if (c != n)
      {
	Status status;
	char buf[256];

	if (!fmt)
	  buf[0] = 0;
	else
	  vsprintf(buf, fmt, ap);

	va_end(ap);
	if (c < 0)
	  return statusMake(SYS_ERROR, "%s%s: errno '%s'", pre, buf,
			    strerror(err));

	return statusMake(SYS_ERROR, "%s%s: invalid size read: %db "
			  "expected, got %db", pre, buf,
			  n, c);
      }

    va_end(ap);
    return Success;
  }

  static const char *
  user_get_from_uid(int uid)
  {
    struct passwd *p = getpwuid(uid);

    if (!p)
      return "<unknown user>";
  
    return p->pw_name;
  }

  static const char *
  getmsgaccess(unsigned int flags)
  {
    if (flags == R_OK) {
      return "read ";
    }
    if (flags == W_OK) {
      return "read/write ";
    }
    return "";
  }

  Status
  checkFileAccessFailed(Error err, const char *what, const char *file, unsigned int flags)
  {
    int uid = getuid();
    const char *user = user_get_from_uid(uid);

    int fd = open(file, O_RDONLY);
    const char* errmsg = sys_errlist[errno];
    return statusMake(err, ACCESS_FILE_FMT "no %saccess to %s '%s': %s", rpc_getpid(), user, uid, getmsgaccess(flags), what, file, errmsg);
  }

  Status
  checkFileAccess(Error err, const char *what, const char *file, unsigned int flags)
  {
#ifdef NEW_FILE_ACCESS
    if (access(file, F_OK)) {
      return checkFileAccessFailed(err, what, file, F_OK);
    }

    flags &= ~F_OK;

    int fd;

    if ((flags & W_OK) != 0) {
      fd = open(file, O_RDWR);
    } else {
      fd = open(file, O_RDONLY);
    }

    if (fd >= 0) {
      close(fd);
      return Success;
    }

    return checkFileAccessFailed(err, what, file, flags);
#else
    if (flags != F_OK) {
      /* check existence first */
      if (access(file, F_OK))
	return checkFileAccessFailed(err, what, file, F_OK);
    }

    flags &= ~F_OK;
    if (access(file, flags)) {
      printf("Access failed for %d\n", flags);
      if ((flags & W_OK)) {
	privilegeInit();
	int fd = open(file, O_RDWR);
	if (fd >= 0) {
	  close(fd);
	  printf("open OK!\n");
	}
      }
      else {
	privilegeInit();
	int fd = open(file, O_RDONLY);
	if (fd >= 0) {
	  close(fd);
	  printf("open OK!\n");
	}
      }
      return checkFileAccessFailed(err, what, file, flags);
    }
    return Success;
#endif
  }

  Status
  dopen(char const * pre, char const * file, int mode, int * const fdp,
	Boolean * const suser)
  {
#ifdef NEW_FILE_ACCESS
    if ((*fdp = open(file, mode)) >= 0)
      return Success;

    if (*fdp < 0) {
      return statusMake((errno == EACCES) ? INVALID_DBFILE_ACCESS : INVALID_DBFILE, "%sdatabase file '%s'", pre, file);
    }

    if (suser)
      *suser = False;

    return Success;
#else
    Status s;

    if ((*fdp = open(file, mode)) >= 0)
      return Success;

    if ((s = privilegeAcquire()) != Success)
      return s;

    *fdp = open(file, mode);

    if ((s = privilegeRelease()) != Success)
      return s;

    if (*fdp < 0) {
      return statusMake((errno == EACCES) ? INVALID_DBFILE_ACCESS : INVALID_DBFILE, "%sdatabase file '%s'", pre, file);
    }
    if (suser)
      *suser = False;

    return Success;
#endif
  }

  Status
  fileSizesGet(const char *file, unsigned long long &filesize,
	       unsigned long long &fileblksize)
  {
    struct stat st;
    if (stat(file, &st) < 0)
      return statusMake(ERROR, "cannot stat file `%s'", file);

    filesize = st.st_size;
    fileblksize = st.st_blocks * 512;

    return Success;
  }

  Status
  fcouldnot(char const *pre, char const *what, char const *which)
  {
    int const err = errno;
    return statusMake(SYS_ERROR, "%ssystem error reported '%s' "
		      "while performing %s(%s)",
		      pre, strerror(err), what, (which ? which : ""));
  }

#define PWDMAX 1024

#if 0
  Status
  push_dir(const char *dbfile, char **pwd)
  {
    const char *dir = get_dir(dbfile);

    if (!*dir) {
      *pwd = 0;
      return Success;
    }

    *pwd = getcwd(0, PWDMAX);
    if (chdir(dir)) {
      free(*pwd);
      return statusMake(ERROR, "cannot change to directory '%s'", dir);
    }

    return Success;
  }
#endif

  Status
  push_dir(const char *dbfile, char *pwd, unsigned int pwd_size)
  {
    const char *dir = get_dir(dbfile);

    if (!*dir) {
      *pwd = 0;
      return Success;
    }

    getcwd(pwd, pwd_size);
    if (chdir(dir)) {
      *pwd = 0;
      return statusMake(ERROR, "cannot change to directory '%s'", dir);
    }

    return Success;
  }

  Status
  pop_dir(char *pwd)
  {
    if (!pwd) {
      return Success;
    }

    if (chdir(pwd)) {
      return statusMake(ERROR, "cannot change to directory '%s'", pwd);
    }

#if 0
    free(pwd);
#endif
    return Success;
  }

  const char *
  get_dir(const char *dbfile)
  {
    //if (*dbfile == '/' && strrchr(dbfile, '/')) {
    if (*dbfile == '/' || strrchr(dbfile, '/') != NULL) {
      static char dirname[4][256];
      static int dirname_cnt;
      char *q;
    
      if (dirname_cnt == 4) {
	dirname_cnt = 0;
      }

      strcpy(dirname[dirname_cnt], dbfile);
      q = strrchr(dirname[dirname_cnt], '/');
      *q = 0;
      return dirname[dirname_cnt++];
    }

    return "";
  }

  char *
  string_version(unsigned int version)
  {
    static const char version_fmt[] = "%d.%d.%d";
    static char s_version[32];

#define MAJORCOEF 100000
#define MINORCOEF   1000
    int major     = version/MAJORCOEF;
    int minor     = (version - major*MAJORCOEF)/MINORCOEF;
    int bug_fixed = (version - major*MAJORCOEF - minor*MINORCOEF);

    sprintf(s_version, version_fmt, major, minor, bug_fixed);
    return s_version;
  }

  const char *
  get_time()
  {
    time_t t;
    char *c;
    time(&t);
    c = ctime(&t);
    c[strlen(c)-1] = 0;
    return c;
  }

  Status
  backendInterrupt()
  {
    backend_interrupt = True;
    return Success;
  }

  Status
  backendInterruptReset()
  {
    backend_interrupt = False;
    return Success;
  }

#ifdef DSP_INVALID_OID
  void display_invalid_oid(const Oid *oid, ObjectHeader *xobjh)
  {
    printf("eyedbsm: invalid oid: %s ", getOidString(oid));
    printf(", xobjh: %p", xobjh);
    if (xobjh) {
      printf(" , unique: %d, size: %u [%u]", x2h_u32(xobjh->unique),
	     x2h_u32(xobjh->size),
	     x2h_makeValid(xobjh->size));
    }
    printf("\n");
  }
#endif

#ifdef DICO_ALG
  int
  oid_cmp(Oid *a, Oid *b)
  {
    return (nsOidGet(dbh, a) - nsOidGet(dbh, b));
  }
#endif

  Boolean
  is_number(const char *s)
  {
    if (!*s)
      return False;
  
    char c;
    while (c = *s++)
      if (!(c >= '0' && c <= '9'))
	return False;

    return True;
  }

  size_t
  fdSizeGet(int fd)
  {
    struct stat st;

    if (fstat(fd, &st) < 0)
      return ~0;

    return st.st_size;
  }

  size_t
  fileSizeGet(const char *file)
  {
    struct stat st;

    if (stat(file, &st) < 0)
      return ~0;

    return st.st_size;
  }
}
