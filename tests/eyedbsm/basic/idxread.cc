
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
  fprintf(stderr, "\n");
  return 1;
}

static unsigned int count;

static void
read_index(void *x)
{
  printf("Reading hash or btree index %s\n", o_getOidString(&o_oids[0]));
  eyedbsm::Idx *idx;
  eyedbsm::Status s= eyedbsm::Idx::make(o_dbh, o_oids[0], idx);
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }
  s = idx->status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  printf("%d Objects Inserted\n", idx->getCount());
  eyedbsm::Oid *oids;
  unsigned int cnt;
  s = idx->getObjects(oids, cnt);
  if (s) {
    eyedbsm::statusPrint(s, "getting hash objects");
    return;
  }

  printf("%d Hash Objects\n", cnt);
  if (o_verbose) {
    printf("{\n");
    for (int i = 0; i < cnt; i++) {
      unsigned int size;
      s = eyedbsm::objectSizeGet(o_dbh, &size, eyedbsm::DefaultLock, &oids[i]);
      if (s) {
	eyedbsm::statusPrint(s, "reading size");
	return;
      }
      printf("\t%s [%db]\n", o_getOidString(&oids[i]), size);
    }
    printf("}\n");
  }

  eyedbsm::IdxCursor *c;
  if (idx->asHIdx())
    c = new eyedbsm::HIdxCursor(idx->asHIdx());
  else
    c = new eyedbsm::BIdxCursor(idx->asBIdx());
  int count;

  for (count = 0; ; count++) {
    eyedbsm::Idx::Key key;
    eyedbsm::Boolean found;
    eyedbsm::Oid oid;
    s = c->next(&found, &oid, &key);
    if (!found)
      break;

    if (o_verbose) {
      printf("keydata\n\t");
      printf("\n\tdata: %s\n", eyedbsm::getOidString(&oid));
    }
  }

  printf("%d found\n", count);
  o_count = count;
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read, usage))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(read_index, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
