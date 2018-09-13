
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

//#define FIXED_DATASZ

#ifdef FIXED_DATASZ
static const unsigned int INDEX_DATASZ = sizeof(eyedbsm::Oid);
static const unsigned int DATASZ = INDEX_DATASZ;
#else
static const unsigned int INDEX_DATASZ = eyedbsm::HIdxDataVarSize;
static const unsigned int DATASZ = 128;
#endif

//#define DATA_GROUPED_BY_KEY

static unsigned int NN;
static unsigned int STEP_RM;

static eyedbsm::Status create_hash()
{
  eyedbsm::Idx::KeyType kt = o_get_idxKeyType("string:-1");

#ifdef DATA_GROUPED_BY_KEY
  o_impl_hints[eyedbsm::HIdx::DataGroupedByKey_Hints] = 4;
#endif

  eyedbsm::HIdx hidx(o_dbh, kt, INDEX_DATASZ, o_dspid, o_magorder,
		     o_keycount, o_impl_hints, eyedbsm::HIdxImplHintsCount);

  eyedbsm::Status s = hidx.status();

  if (s) {
    eyedbsm::statusPrint(s, "creating hash index");
    return s;
  }

  o_oids[0] = hidx.oid();

  printf("has created hash index %s [keytype: %s]\n", o_getOidString(&o_oids[0]), o_keytype);

  return eyedbsm::Success;
}

static void make_key(char key[], int n)
{
#ifdef DATA_GROUPED_BY_KEY
  sprintf(key, "key-%d", n/3);
#else
  sprintf(key, "key-%d", n);
#endif
}

static void make_data(char data[], int n)
{
#ifdef FIXED_DATASZ
  memset(data, 0, DATASZ);
  sprintf(data, "#%d", n, 2*n);
#else
  sprintf(data, "data-#%d", n, 100*n);
#endif
}

static eyedbsm::Status o_insert()
{
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);

  for (int n = 0; n < NN; n++) {
    char key[64];
    char data[DATASZ];

    make_key(key, n);
    make_data(data, n);

#ifdef DATA_GROUPED_BY_KEY
    eyedbsm::Status s = hidx.insert_cache(key, data);
#else
#ifdef FIXED_DATASZ
    eyedbsm::Status s = hidx.insert(key, data);
#else
    eyedbsm::Status s = hidx.insert(key, data, strlen(data)+1);
#endif
#endif
    if (s) {
      eyedbsm::statusPrint(s, "inserting");
      return s;
    }
    printf("inserting [%s] -> [%s]\n", key, data);
  }

#ifdef DATA_GROUPED_BY_KEY
  eyedbsm::Status s = hidx.flush_cache();
  if (s) {
    eyedbsm::statusPrint(s, "inserting");
    return s;
  }
#endif

  return eyedbsm::Success;
}

static eyedbsm::Status o_remove()
{
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);

  for (int n = 0; n < NN; n += STEP_RM) {
    char key[64];
    char data[DATASZ];

    make_key(key, n);
    make_data(data, n);

    eyedbsm::Boolean found;
#ifdef FIXED_DATASZ
    eyedbsm::Status s = hidx.remove(key, data);
#else
    eyedbsm::Status s = hidx.remove(key, data, strlen(data)+1, &found);
#endif
    if (s) {
      eyedbsm::statusPrint(s, "removing");
      return s;
    }
    assert(found);
  }

  return eyedbsm::Success;
}

static eyedbsm::Status o_read()
{
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);

  printf("\nKey Size %d\n", hidx.getIdx().keysz);
  printf("Key Count %u\n", hidx.getIdx().key_count);
  printf("Data Size %u\n", hidx.getIdx().datasz);
  printf("Data %sgrouped by key\n\n", hidx.isDataGroupedByKey() ? "" : "not ");

  eyedbsm::HIdxCursor c(&hidx);
  unsigned int count;

  for (count = 0; ; count++) {
    eyedbsm::Idx::Key key;
    eyedbsm::Boolean found;
    char data[DATASZ];

    eyedbsm::Status s = c.next(&found, data, &key);
    if (s) {
      eyedbsm::statusPrint(s, "getting next");
      return s;
    }

    if (!found) {
      break;
    }

    printf("[%s] -> [%s]\n", key.getKey(), data);
    int nn = atoi(&((char *)key.getKey())[4]);
    char xdata[DATASZ];
    make_data(xdata, nn);
    assert(!memcmp(xdata, data, strlen(data)+1));

    found = eyedbsm::False;
    //    s = hidx.searchAny(key.getKey(), &found, xdata);
    s = hidx.searchAny(key.getKey(), &found);
    if (s) {
      eyedbsm::statusPrint(s, "searching");
      return s;
    }
    assert(found);
  }

  printf("count %u\n", count);

  eyedbsm::HIdxCursor c1(&hidx);

  for (count = 0; ; count++) {
    eyedbsm::Idx::Key key;
    eyedbsm::Boolean found;
    eyedbsm::DataBuffer dataBuffer;

    eyedbsm::Status s = c1.next(&found, dataBuffer, &key);
    if (s) {
      eyedbsm::statusPrint(s, "getting next");
      return s;
    }

    if (!found) {
      break;
    }

    unsigned int datasz;
    void *data = dataBuffer.getData(datasz);
    printf("[%s] -> [%s] %u\n", key.getKey(), data, datasz);

    int nn = atoi(&((char *)key.getKey())[4]);
    char xdata[DATASZ];
    make_data(xdata, nn);
    assert(!memcmp(xdata, (char *)data, strlen((char *)data)+1));
  }

  printf("count %u\n", count);

  if (hidx.isDataGroupedByKey()) {
    eyedbsm::HIdxCursor c2(&hidx);
    for (;;) {
      eyedbsm::Idx::Key key;
      unsigned int found_cnt;
      eyedbsm::Status s = c2.next(&found_cnt, &key);

      if (s) {
	eyedbsm::statusPrint(s, "getting next");
	return s;
      }

      if (!found_cnt) {
	break;
      }

      printf("[%s] -> %d items\n", key.getKey(), found_cnt);
    }
  }

  return eyedbsm::Success;
}

static eyedbsm::Status o_stats()
{
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);

  std::string stats;
  eyedbsm::Status s = hidx.getStats(stats);
  if (s) {
    eyedbsm::statusPrint(s, "stating hash index");
    return s;
  }

  std::cout << stats;

  return eyedbsm::Success;
}

static eyedbsm::Status o_move()
{
  eyedbsm::HIdx hidx(o_dbh, &o_oids[0]);

  eyedbsm::Oid newoid;
  eyedbsm::Status s = hidx.move((short)o_dspid, newoid);
  if (s) {
    eyedbsm::statusPrint(s, "moving hash index");
    return s;
  }

  printf("%s -> %s\n", eyedbsm::getOidString(&o_oids[0]), eyedbsm::getOidString(&newoid));
  o_oids[0] = newoid;
  return eyedbsm::Success;
}

static int usage(const char *prog)
{
  std::cerr << "usage: " << prog << " DATABASE HOIDFILE\n";
  return 1;
}

int main(int argc, char *argv[])
{
  if (argc != 3) {
    return usage(argv[0]);
  }

  eyedbsm::init();

  o_dbfile = argv[1];

  if (o_dbopen()) {
    return 1;
  }

  o_oidfile = argv[2];

  if (o_fileopen(o_Create)) {
    return 1;
  }

  if (o_trsbegin())
    return 1;

  if (create_hash())
    return 1;

  if (o_trsend())
    return 1;

  o_write_oids(o_oids, 1); // not really necessary

  for (int n = 0; n < 10; n++) {
    NN = (n+1) * 120;
    STEP_RM = 3*(n+1);

    if (o_trsbegin())
      return 1;

    if (o_insert())
      return 1;

    if (o_trsend())
      return 1;

    if (o_trsbegin())
      return 1;

    if (o_read())
      return 1;

    if (o_trsend())
      return 1;

    if (o_trsbegin())
      return 1;

    if (o_remove())
      return 1;

    if (o_trsend())
      return 1;

    if (o_trsbegin())
      return 1;

    if (o_read())
      return 1;

    if (o_trsend())
      return 1;

    if (o_trsbegin())
      return 1;

    if (o_stats())
      return 1;

    if (o_trsend())
      return 1;

    if (o_trsbegin())
      return 1;

    if (o_move())
      return 1;

    if (o_trsend())
      return 1;
  }

  return o_release();
}
