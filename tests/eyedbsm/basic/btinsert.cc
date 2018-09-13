
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


/* usage: ./btinsert -verbose `pwd`/db/foo.dbs OID 1 100 [-keysize 10] */

#include "olib.h"

static int
usage()
{
  o_usage(eyedbsm::False);
  fprintf(stderr, "[-keysize <keysize>]\n");
  return 1;
}

static unsigned int Count;
static char *key_data;

static void
insert_btree(void *x)
{
  printf("reading btree index %s\n", o_getOidString(&o_oids[0]));
  eyedbsm::BIdx bidx(o_dbh, o_oids[0]);
  eyedbsm::Status s = bidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading btree index");
    return;
  }

  unsigned int nkeys;
  const eyedbsm::Idx::KeyType *kt = bidx.getKeyTypes(nkeys);
  if (nkeys != 1) {
    fprintf(stderr, "cannot manage btree with multiple keys\n");
    return;
  }

  for (int n = 0; n < Count; n++) {
    eyedbsm::Oid oid = o_oids[0];
    oid.setNX(oid.getNX() + n);
    oid.setUnique(oid.getUnique() + n);
    int len;
    char *key;
    if (key_data) {
      key = key_data;
      len = strlen(key);
    }
    else
      key = o_make_data(kt[0], Count, n, len, eyedbsm::False);

    if (o_verbose) {
      printf("inserting key\n\t");
      o_trace_data(kt[0], key, eyedbsm::False);
      printf("\n\tdata: %s\n", eyedbsm::getOidString(&oid));
    }
    eyedbsm::Status s = bidx.insert(key, &oid);
    if (s) {
      eyedbsm::statusPrint(s, "inserting in btree");
      return;
    }
  }
  o_count = Count;
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
      if (!Count)
	return usage();
    }
    else if (!key_data) {
      key_data = argv[i];
    }
    else
      return usage();

  }

  o_bench(insert_btree, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
