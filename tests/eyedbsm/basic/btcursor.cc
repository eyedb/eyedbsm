
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

static int
usage()
{
  o_usage(eyedbsm::False);
  fprintf(stderr, "[-remove] <fromkey> <tokey>\n");
  return 1;
}

static unsigned int Count;
static eyedbsm::Boolean from_x, to_x;
static int from, to;
static eyedbsm::Boolean rmv = eyedbsm::False;

static void
read_btree(void *x)
{
  eyedbsm::BIdx bidx(o_dbh, o_oids[0]);
  eyedbsm::Status s = bidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading btree index");
    return;
  }

  unsigned nkeys;
  const eyedbsm::Idx::KeyType *kt = bidx.getKeyTypes(nkeys);
  if (nkeys != 1) {
    fprintf(stderr, "cannot manage btree with multiple keys\n");
    return;
  }

  int len;
  char *data = o_make_data(kt[0], 0, from, len, eyedbsm::False);
  char *skey = new char[len];
  memcpy(skey, data, len);
  data = o_make_data(kt[0], 0, to, len, eyedbsm::False);
  char *ekey = new char[len];
  memcpy(ekey, data, len);

  printf("searching between ");
  o_trace_data(kt[0], skey, eyedbsm::False);
  if (from_x) printf(" [X]");
  printf(" and ");
  o_trace_data(kt[0], ekey, eyedbsm::False);
  if (to_x) printf("[X]");
  printf("\n");

  eyedbsm::BIdxCursor c(&bidx, skey, ekey, from_x, to_x);
  o_idxsearch_realize(bidx, c, kt[0], Count, rmv);

  printf("%d found\n", Count);
  o_count = Count;
  delete [] skey;
  delete [] ekey;
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read, usage, 1))
    return 1;

  if (o_trsbegin())
    return 1;

  if (argc != 2 && argc != 3)
    return usage();

  int start = 0;
  if (!strcmp(argv[0], "-remove")) {
    if (argc != 3)
      return usage();
    start = 1;
    rmv = eyedbsm::True;
  }
  else if (argc != 2)
    return usage();

  if (*argv[start] == 'x') {
    from_x = eyedbsm::True;
    from = atoi(argv[start]+1);
  } else {
    from_x = eyedbsm::False;
    from = atoi(argv[start]);
  }
  if (*argv[start+1] == 'x') {
    to_x = eyedbsm::True;
    to = atoi(argv[start+1]+1);
  } else {
    to_x = eyedbsm::False;
    to = atoi(argv[start+1]);
  }

  o_bench(read_btree, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
