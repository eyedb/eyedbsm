
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

static void
create_btree(void *x)
{
  eyedbsm::Idx::KeyType kt = o_get_idxKeyType(o_keytype);

  eyedbsm::BIdx bidx(o_dbh, sizeof(eyedbsm::Oid), &kt, o_dspid, o_degree);
  eyedbsm::Status s = bidx.status();
  if (s) eyedbsm::statusPrint(s, "creating btree index");
  o_oids[0] = bidx.oid();
  printf("has created %s\n", o_getOidString(&o_oids[0]));
}

static void
reimplement_hash(void *x)
{
  printf("Reading btree index %s for hash reimplementation\n",
	 o_getOidString(&o_oids[0]));
  eyedbsm::BIdx bidx(o_dbh, o_oids[0]);
  eyedbsm::Status s = bidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  s = bidx.reimplementToHash(o_oids[0], o_keycount, o_magorder, o_dspid,
			     o_impl_hints, eyedbsm::HIdxImplHintsCount);

  if (s) {
    eyedbsm::statusPrint(s, "reimplementing hash index");
    return;
  }
}

static void
reimplement_btree(void *x)
{
  printf("Reading btree index %s for btree reimplementation\n",
	 o_getOidString(&o_oids[0]));
  eyedbsm::BIdx bidx(o_dbh, o_oids[0]);
  eyedbsm::Status s = bidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  s = bidx.reimplementToBTree(o_oids[0], o_degree, o_dspid);

  if (s) {
    eyedbsm::statusPrint(s, "reimplementing hash index");
    return;
  }
}

int
main(int argc, char *argv[])
{
  o_keytype = "string:32";
  o_FileType ftype;
  if (o_index_manage(argc, argv, ftype, 1))
    return 1;

  if (o_trsbegin())
    return 1;

  if (o_reimplement_H)
    o_bench(reimplement_hash, 0);
  else if (o_reimplement_B)
    o_bench(reimplement_btree, 0);
  else
    o_bench(create_btree, 0);

  if (o_trsend())
    return 1;

  printf("Ending...\n");
  if (ftype == o_Create || ftype == o_Write)
    o_write_oids(o_oids, o_count);

  return o_release();
}
