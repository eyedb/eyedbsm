
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


/* usage: ./hinsert -verbose `pwd`/db/foo.dbs OID 1 100 */

#include "olib.h"

static int
usage()
{
  o_usage(eyedbsm::False);
  fprintf(stderr, "count\n");
  return 1;
}


static unsigned int Count;

static void
insert_hash(void *x)
{
  printf("Reading hash index %s\n", o_getOidString(&o_oids[0]));
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);
  eyedbsm::Status s = hidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  const eyedbsm::Idx::KeyType &kt = hidx.getKeyType();
  //printf("kt = %d %d %d\n", kt.type, kt.count, kt.offset);

  //#define CONST

  for (unsigned int n = 0; n < Count; n++) {
    eyedbsm::Oid oid = o_oids[0];
#ifdef CONST
    char * key = "Original Sequence";
#else
    oid.setNX(oid.getNX() + n);
    oid.setUnique(oid.getUnique() + n);
    int len;
    char * key = o_make_data(kt, Count, n, len, eyedbsm::False);
#endif
    if (o_verbose) {
      printf("inserting key\n\t");
      o_trace_data(kt, key, eyedbsm::False);
      printf("\n\tdata: %s\n", eyedbsm::getOidString(&oid));
    }
    eyedbsm::Status s = hidx.insert(key, &oid);
    if (s) {
      eyedbsm::statusPrint(s, "inserting in hash");
      return;
    }
  }
  o_count = Count;
  if (getenv("DUMPMAP"))
    hidx.dumpMemoryMap();
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read, usage, 1))
    return 1;

  if (o_trsbegin())
    return 1;

  for (int i = 0; i < argc; i++) {
    if (!Count) {
      Count = atoi(argv[i]);
      if (!Count) return usage();
    }
    else
      return usage();
  }

  o_bench(insert_hash, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
