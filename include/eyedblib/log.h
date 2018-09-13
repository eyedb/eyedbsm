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


#ifndef _EYEDBLIB_LOG_H
#define _EYEDBLIB_LOG_H

#include <stdio.h>

#define IDB_LOG_MASK(X) ((unsigned long long)(1ULL << (X)))

#define IDB_LOG_LOCAL  IDB_LOG_MASK(0)
#define IDB_LOG_SERVER IDB_LOG_MASK(1)

/* general level */
#define IDB_LOG_CONN        IDB_LOG_MASK(2)
#define IDB_LOG_TRANSACTION IDB_LOG_MASK(3)
#define IDB_LOG_DATABASE    IDB_LOG_MASK(4)
#define IDB_LOG_ADMIN       IDB_LOG_MASK(5)
#define IDB_LOG_EXCEPTION   IDB_LOG_MASK(40)

/* storage manager level */
#define IDB_LOG_OID_CREATE IDB_LOG_MASK(6)
#define IDB_LOG_OID_READ   IDB_LOG_MASK(7)
#define IDB_LOG_OID_WRITE  IDB_LOG_MASK(8)
#define IDB_LOG_OID_DELETE IDB_LOG_MASK(9)
#define IDB_LOG_OID_ALL    (IDB_LOG_OID_CREATE | IDB_LOG_OID_READ | \
                            IDB_LOG_OID_WRITE | IDB_LOG_OID_DELETE)

#define IDB_LOG_MMAP        IDB_LOG_MASK(10)
#define IDB_LOG_MMAP_DETAIL IDB_LOG_MASK(47)
#define IDB_LOG_MTX         IDB_LOG_MASK(41)

/* storage manager index level */
#define IDB_LOG_IDX_CREATE   IDB_LOG_MASK(11)
#define IDB_LOG_IDX_REMOVE   IDB_LOG_MASK(12)
#define IDB_LOG_IDX_INSERT   IDB_LOG_MASK(14)
#define IDB_LOG_IDX_SUPPRESS IDB_LOG_MASK(15)
#define IDB_LOG_IDX_SEARCH   IDB_LOG_MASK(16)
#define IDB_LOG_IDX_SEARCH_DETAIL IDB_LOG_MASK(13)
#define IDB_LOG_IDX_ALL    (IDB_LOG_IDX_CREATE | IDB_LOG_IDX_REMOVE | \
			    IDB_LOG_IDX_INSERT | IDB_LOG_IDX_SEARCH_DETAIL | \
			    IDB_LOG_IDX_SUPPRESS | IDB_LOG_IDX_SEARCH)
     
/* object level */
#define IDB_LOG_OBJ_LOAD   IDB_LOG_MASK(17)
#define IDB_LOG_OBJ_CREATE IDB_LOG_MASK(18)
#define IDB_LOG_OBJ_UPDATE IDB_LOG_MASK(19)
#define IDB_LOG_OBJ_REMOVE IDB_LOG_MASK(20)
#define IDB_LOG_OBJ_ALL    (IDB_LOG_OBJ_LOAD | IDB_LOG_OBJ_CREATE | \
			    IDB_LOG_OBJ_UPDATE | IDB_LOG_OBJ_REMOVE)

#define IDB_LOG_OBJ_GBX     IDB_LOG_MASK(42)
#define IDB_LOG_OBJ_INIT    IDB_LOG_MASK(43)
#define IDB_LOG_OBJ_GARBAGE IDB_LOG_MASK(44)
#define IDB_LOG_OBJ_COPY    IDB_LOG_MASK(45)

#define IDB_LOG_OBJ_ALLOC (IDB_LOG_OBJ_GBX | IDB_LOG_OBJ_INIT | \
			   IDB_LOG_OBJ_GARBAGE | IDB_LOG_OBJ_COPY)

#define IDB_LOG_DEV         IDB_LOG_MASK(46)

/* method */
#define IDB_LOG_EXECUTE IDB_LOG_MASK(21)

/* object data level */
#define IDB_LOG_DATA_READ   IDB_LOG_MASK(22)
#define IDB_LOG_DATA_CREATE IDB_LOG_MASK(23)
#define IDB_LOG_DATA_WRITE  IDB_LOG_MASK(24)
#define IDB_LOG_DATA_DELETE IDB_LOG_MASK(25)
#define IDB_LOG_DATA_ALL    (IDB_LOG_DATA_CREATE | IDB_LOG_DATA_READ | \
			     IDB_LOG_DATA_WRITE | IDB_LOG_DATA_DELETE)

/* queries */
#define IDB_LOG_OQL_EXEC    IDB_LOG_MASK(26)
#define IDB_LOG_OQL_RESULT  IDB_LOG_MASK(30)

/* relationship level */
#define IDB_LOG_RELSHIP         IDB_LOG_MASK(27)
#define IDB_LOG_RELSHIP_DETAILS IDB_LOG_MASK(28)

#define IDB_LOG_SCHEMA_EVOLVE IDB_LOG_MASK(29)

#define IDB_LOG_USER_BOTTOM  50
#define IDB_LOG_USER_MAX     12

/* user level */
#define IDB_LOG_USER(X)  \
  (((X) >= 0 && (X) < IDB_LOG_USER_MAX) ? \
      IDB_LOG_MASK((X+IDB_LOG_USER_BOTTOM)) : \
       (unsigned long long)(fprintf(stderr, "out of range user log #%d\n", (X)), 0))

/* default log mask */
#define IDB_LOG_DEFAULT (IDB_LOG_LOCAL | IDB_LOG_SERVER | IDB_LOG_CONN | \
                         IDB_LOG_TRANSACTION | IDB_LOG_DATABASE | \
                         IDB_LOG_ADMIN | IDB_LOG_EXCEPTION | IDB_LOG_MTX)

/* no log */
#define IDB_LOG_NOLOG IDB_LOG_MASK(63)

namespace eyedblib {
  typedef unsigned long long LogMask;
  extern LogMask log_mask;
}

#define IDB_LOG(L, S) \
  do {if (((L) & eyedblib::log_mask) == (L)) {utlog_p(#L); utlog S;}} while(0)

#define IDB_LOG_D(L, S) \
  do {if ((((L)|IDB_LOG_DEV) & eyedblib::log_mask) == ((L)|IDB_LOG_DEV)) {utlog_p(#L); utlog S;}} while(0)

#define IDB_LOG_X(L, S) \
  do {if (((L) & eyedblib::log_mask) == (L)) utlog S;} while(0)

#define IDB_LOG_DX(L, S) \
  do {if ((((L)|IDB_LOG_DEV) & eyedblib::log_mask) == ((L)|IDB_LOG_DEV)) utlog S;} while(0)

#define IDB_LOG_F(S) \
  do { \
    FILE *logfd; \
 \
    utlog_p("FATAL_ERROR"); \
    utlog S;\
 \
    logfd = utlogFDSet(stderr); \
    utlog_p("FATAL_ERROR"); \
    utlog S; \
    (void)utlogFDSet(logfd);\
   } while (0)

#define IDB_LOG_FX(S) \
  do { \
    utlog_p("FATAL_ERROR"); \
    utlog S;\
   } while (0)


extern void utlogInit(const char *progName, const char *devname);
extern FILE *utlogFDGet();
extern FILE *utlogFDSet(FILE *);
extern void utlog(const char *fmt, ...);
extern void utlog_p(const char *s);
extern const char *utlogDevNameGet();
extern void utlogResetTimer();
extern void utlogSetLogDate(int on);
extern void utlogSetLogTimer(int on);
extern void utlogSetLogPid(int on);
extern void utlogSetLogProgName(int on);

#endif
