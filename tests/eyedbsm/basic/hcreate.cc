
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
//#include <eyedb/lib/butils.h>

static void
create_hash(void *x)
{
  eyedbsm::Idx::KeyType kt = o_get_idxKeyType(o_keytype);

  printf("O_DSPID = %d\n", o_dspid);
  eyedbsm::HIdx hidx(o_dbh, kt, sizeof(eyedbsm::Oid), o_dspid, o_magorder,
	       o_keycount, o_impl_hints, eyedbsm::HIdxImplHintsCount);
  eyedbsm::Status s = hidx.status();
  if (s) eyedbsm::statusPrint(s, "creating hash index");
  o_oids[0] = hidx.oid();
  printf("has created hash index %s [keytype: %s]\n",
	 o_getOidString(&o_oids[0]), o_keytype);
}

static void
o_display_hashobjects(const eyedbsm::Oid &hoid)
{
  eyedbsm::HIdx hidx(o_dbh, &hoid);
  eyedbsm::Oid *oids;
  unsigned int cnt;
  eyedbsm::Status s = hidx.getObjects(oids, cnt);
  if (s) {
    eyedbsm::statusPrint(s, "getting new hash objects");
    return;
  }

  printf("%d Hash Objects\n", cnt);
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

static void
reimplement_hash(void *x)
{
  printf("Reading hash index %s for hash reimplementation\n",
	 o_getOidString(&o_oids[0]));
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);
  eyedbsm::Status s = hidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  s = hidx.reimplementToHash(o_oids[0], o_keycount, o_magorder, o_dspid,
			     o_impl_hints, eyedbsm::HIdxImplHintsCount);

  if (s) {
    eyedbsm::statusPrint(s, "reimplementing hash index");
    return;
  }
}

static void
reimplement_btree(void *x)
{
  printf("Reading hash index %s for btree reimplementation\n",
	 o_getOidString(&o_oids[0]));
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);
  eyedbsm::Status s = hidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  s = hidx.reimplementToBTree(o_oids[0], o_degree, o_dspid);

  if (s) {
    eyedbsm::statusPrint(s, "reimplementing hash index");
    return;
  }
}

static void
simulate_hash(void *x)
{
  printf("Reading hash index %s for Simulation\n", o_getOidString(&o_oids[0]));
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);
  eyedbsm::Status s = hidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading hash index");
    return;
  }

  eyedbsm::HIdx::Stats stats;
  s = hidx.simulate(stats, o_keycount, o_magorder,
		    o_impl_hints, eyedbsm::HIdxImplHintsCount);
  if (s) {
    eyedbsm::statusPrint(s, "simulating hash index");
    return;
  }

  stats.trace(o_fullstats);
}

int
main(int argc, char *argv[])
{
  o_FileType ftype;
  if (o_index_manage(argc, argv, ftype, 1))
    return 1;

  if (o_trsbegin())
    return 1;

  if (o_reimplement_H)
    o_bench(reimplement_hash, 0);
  else if (o_reimplement_B)
    o_bench(reimplement_btree, 0);
  else if (o_simulate)
    o_bench(simulate_hash, 0);
  else
    o_bench(create_hash, 0);

  if (o_trsend())
    return 1;

  printf("Ending...\n");
  if (ftype == o_Create || ftype == o_Write)
    o_write_oids(o_oids, o_count);

  return o_release();
}
