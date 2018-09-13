
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


/* usage: ./hvsinsert -verbose `pwd`/db/foo.dbs OID 1 100 */

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
  if (kt.type != eyedbsm::Idx::tString || kt.count != eyedbsm::HIdx::VarSize) {
    fprintf(stderr, "hash is not a varstring index %d\n", kt.count);
    return;
  }

#if 1
  char *dd_cnt_s = getenv("DATACNT");
  int dd_cnt = 1;
  if (dd_cnt_s) {
    dd_cnt = atoi(dd_cnt_s);
  }

  const char *use_cache = getenv("USE_CACHE");
  for (int n = 0; n < Count; n++) {
    char key[64];

    std::vector<const void *> xdata_v;

    eyedbsm::Oid *data_oid = new eyedbsm::Oid[dd_cnt];
  
    sprintf(key, "key #%d", n);
    for (int m = 0; m < dd_cnt; m++) {
      eyedbsm::Oid *oid = &data_oid[m];
      oid->setDbID(2);
      oid->setNX(3 * n + m);
      oid->setUnique(3 * n + m);
      xdata_v.push_back(oid);
    }

    if (o_verbose) {
      printf("inserting key\n\t");
      o_trace_data(kt, key, eyedbsm::True);
      printf("\n\t%d data\n", dd_cnt);
      //printf("\n\tdata: %s\n", eyedbsm::getOidString(&oid));
    }

    eyedbsm::Status s = (use_cache ? hidx.insert_cache(key, xdata_v) : hidx.insert(key, xdata_v));
    if (s) {
      eyedbsm::statusPrint(s, "inserting in hash");
      return;
    }
    delete [] data_oid;
  }

  if (use_cache) {
    printf("cache #1\n");
    s = hidx.flush_cache();
    if (s) {
      eyedbsm::statusPrint(s, "flushing cache");
      return;
    }
    printf("cache #2\n");
    s = hidx.flush_cache();
    if (s) {
      eyedbsm::statusPrint(s, "flushing cache");
      return;
    }
  }

#else
  for (int n = 0; n < Count; n++) {
    eyedbsm::Oid oid = o_oids[0];
    oid.setNX(oid.getNX() + n);
    oid.setUnique(oid.getUnique() + n);
    int len;
    char * key = o_make_varstring(n, len);
    if (o_verbose) {
      printf("inserting key\n\t");
      o_trace_data(kt, key, eyedbsm::True);
      printf("\n\tdata: %s\n", eyedbsm::getOidString(&oid));
    }

    eyedbsm::Status s = hidx.insert(key, &oid);
    if (s) {
      eyedbsm::statusPrint(s, "inserting in hash");
      return;
    }
  }
#endif
  if (getenv("DUMPMAP"))
    hidx.dumpMemoryMap();
  o_count = Count;
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read, usage))
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
