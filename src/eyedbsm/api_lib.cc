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

#include <assert.h>
#include <string.h>
#include "eyedbsm_p.h"

#include <eyedblib/rpc_lib.h>

// FD CHECK: include a lib/ private header
#include <lib/m_mem_p.h>

#include "transaction.h"

namespace eyedbsm {

  int pgsize, pgsize_pow2;

#ifdef	_SC_PAGESIZE
#define	getpagesize()	sysconf(_SC_PAGESIZE)
#endif

  int
  power2(int x)
  {
    int n, p;

    for (n = 0, p = 0; x; p++)
      {
	if ((x & 1) && ++n > 1)
	  return -1;

	x >>= 1;
      }

    return p-1;
  }

#define OFFSET(T, X) (unsigned long)(&((T *)0)->X)

#define CHECK_ALIGN(X) if (!(X)) {fprintf(stderr, "\nInternal error: invalid structure alignment: " #X ".\n\nCannot run eyedb on this architecture.\n\n"); exit(1);}

  static void check_alignments()
  {
#if 0
    CHECK_ALIGN(OFFSET(MapStat, u) == 8);
    CHECK_ALIGN(OFFSET(MapHeader, sizeslot) == 4);
    CHECK_ALIGN(OFFSET(MapHeader, mstat) == 24);
    CHECK_ALIGN(OFFSET(MapHeader, u) == 56);
    CHECK_ALIGN(OFFSET(DatafileDesc, mp.mtype) == 296);
    CHECK_ALIGN(OFFSET(DatafileDesc, mp.sizeslot) == 300);
    CHECK_ALIGN(OFFSET(DatafileDesc, __lastslot) == 368);
    CHECK_ALIGN(OFFSET(DatafileDesc, __dspid) == 372);
    CHECK_ALIGN(OFFSET(DbHeader, __magic) == 0);
    CHECK_ALIGN(OFFSET(DbHeader, __dbid) == 4);
    CHECK_ALIGN(OFFSET(DbHeader, state) == 8);
    CHECK_ALIGN(OFFSET(DbHeader, __guest_uid) == 12);
    CHECK_ALIGN(OFFSET(DbHeader, __prot_uid_oid) == 16);
    CHECK_ALIGN(OFFSET(DbHeader, __prot_list_oid) == 24);
    CHECK_ALIGN(OFFSET(DbHeader, __prot_lock_oid) == 32);
    CHECK_ALIGN(OFFSET(DbHeader, shmfile) == 40);
    CHECK_ALIGN(OFFSET(DbHeader, __nbobjs) == 296);
    CHECK_ALIGN(OFFSET(DbHeader, __ndat) == 300);
    CHECK_ALIGN(OFFSET(DbHeader, dat) == 304);
    CHECK_ALIGN(OFFSET(DbHeader, __ndsp) == 192816);
    CHECK_ALIGN(OFFSET(DbHeader, dsp) == 192820);
    CHECK_ALIGN(OFFSET(DbHeader, __def_dspid) == 246068);
    CHECK_ALIGN(OFFSET(DbHeader, vre) == 246070);
    CHECK_ALIGN(OFFSET(DbHeader, __lastidxbusy) == 248632);
    CHECK_ALIGN(OFFSET(DbHeader, __curidxbusy) == 248636);
    CHECK_ALIGN(OFFSET(DbHeader, __lastidxblkalloc) == 248640);
    CHECK_ALIGN(OFFSET(DbHeader, __lastnsblkalloc) == 248644);
    CHECK_ALIGN(OFFSET(HIdx::_Idx, key_count) == 12);
    CHECK_ALIGN(OFFSET(HIdx::_Idx, dspid) == 16);
    CHECK_ALIGN(OFFSET(HIdx::_Idx, keytype) == 20);
    CHECK_ALIGN(OFFSET(HIdx::_Idx, keysz) == 24);
    CHECK_ALIGN(OFFSET(HIdx::_Idx, datasz) == 28);
#endif
  }

  Status init()
  {
    check_alignments();

    const char *logmask = getenv("IDB_LOG_MASK");
    if (logmask) {
      utlogInit("", "stderr");
      sscanf(logmask, "%llx", &eyedblib::log_mask);
    }

    trs_init();
    mutexes_init();
    pgsize = getpagesize();
    pgsize_pow2 = power2(pgsize);
    m_init();

    return Success;
  }

  Status release()
  {
    mutexes_release();
    return Success;
  }
}
