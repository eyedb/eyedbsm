
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

#define STDFMT " object size %d, data `%s', size %d"

static void
read_objects(void *x)
{
  unsigned int sz_alloc = 0;
  char *rdata = 0;

  eyedbsm::Boolean found;
  eyedbsm::Oid oid;
  unsigned int count = 0;
  unsigned int total_sz = 0;

  eyedbsm::DbInfoDescription dbinfo;
  assert(!eyedbsm::statusPrint(eyedbsm::dbInfo(o_dbfile, &dbinfo), "dbinfo"));
  for (short datid = 0; datid < dbinfo.ndat; datid++) {
    if (!*dbinfo.dat[datid].file)
      continue;

    assert(!eyedbsm::statusPrint(eyedbsm::firstOidDatGet(o_dbh, datid, &oid, &found), "first oid get"));

    for (int n = 0; found; n++) {
      eyedbsm::Oid oid_n;
      count++;
      o_wait("before reading", n);
      unsigned int sz;

      assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &sz, o_read_lock, &oid),
			     "%s: reading size", o_progname));

      if (o_verbose)
	printf("reading %s: %d bytes\n", o_getOidString(&oid), sz);
      if (sz >= sz_alloc) {
	sz_alloc = sz + 1024;
	rdata = (char *)realloc(rdata, sz_alloc);
      }

      total_sz += sz;
      assert(!eyedbsm::statusPrint(eyedbsm::objectRead(o_dbh, 0, sz, rdata, o_read_lock,
					   0, 0, &oid),
			     "%s: reading", o_progname));
      if (o_verbose)
	printf("%s\n", rdata);
      assert (!eyedbsm::statusPrint(eyedbsm::nextOidDatGet(o_dbh, datid, &oid, &oid_n, &found), "next oid get"));
      oid = oid_n;
    }
  }

  printf("%d Oids read\n", count);
  printf("Total size %ub, %uKb, %uMb\n", total_sz, total_sz/1024,
	 total_sz/(1024*1024));
  o_count = count;
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Skip, o_stdusage, 0))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(read_objects, 0);

  if (o_trsend())
    return 1;

  return o_release();
}

