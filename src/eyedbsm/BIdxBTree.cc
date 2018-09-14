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
   Authors: Stuart Pook
            Eric Viara <viara@sysra.com>
*/

#include <eyedbsmconfig.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <eyedbsm/eyedbsm.h>
#include "BIdxBTree.h"
#include "eyedbsm_p.h"
#include <assert.h>

#include <eyedblib/machtypes.h>
#include <eyedblib/rpc_lib.h>
#include <eyedblib/xdr.h>
#include <eyedblib/strutils.h>

#include <eyedblib/m_mem.h>

// FD CHECK: include a lib/ private header
#include "lib/m_mem_p.h"

#include <eyedblib/log.h>

//#define ESM_HIDX_REGISTER

namespace eyedbsm {

  static void
  idx_new_handler()
  {
    static char message[] = "Ran out of memory\n";
    write(2, message, sizeof message - 1);
    exit(1);
  }

  Status BIdx::fatal(Status s)
  {
    stat = s;
    statusPrint(stat, "IDX error real fatal");
    return stat;
  }

  Status BIdx::fatal()
  {
#if 1
    return stat;
#else
    Status s = stat;
    if (s) {
      if (s->err == TRANSACTION_NEEDED ||
	  s->err == RW_TRANSACTION_NEEDED)
	stat = Success;
    }
    return s;
#endif
  }

  BIdx::BIdx(DbHandle * vh, Oid const &idx,
	     Boolean (*precmp)(void const * p, void const * q,
			       KeyType const * type, int & r))
    : Idx(True, precmp), stat(Success), dbh(vh), treeOid(idx), free(0),
      occupied(0), _keyType(0), tmpnode(0)
  {
    BTree tree;
    if (readBTree(tree))
      return;

    size_t size; // V3_API_size_t
    if (fatal(objectSizeGet(dbh, &size, DefaultLock, &tree.type)))
      return;
    assert(size % sizeof (KeyType) == 0);
    _nkeys = size / sizeof (KeyType);
    assert(size == _nkeys * sizeof(KeyType));
    if (fatal(readKeyType(_keyType, _nkeys, tree.type)))
      return;
	
    dataSize = tree.dataSize;
    keySize = tree.keySize;
    dspid = tree.dspid;
    degree = tree.degree;
    maxchildren = tree.maxchildren;
    count = tree.count;
    tmpnode = Node::allocNode(degree);
  }

  void
  BIdx::open(Boolean (*_precmp)(void const * p, void const * q,
				KeyType const * type, int & r))
  {
    precmp = _precmp;
    opened = True;
  }

#define MAXKEYSIZE 0x1000

  static unsigned
  calKeySize(Idx::KeyType const p[], unsigned nkeys)
  {
    unsigned max = 0;
    for (; nkeys-- > 0; p++) {
      unsigned int r;
      if ((int)p->count < 0)
	r = ~0;
      else
	r = p->offset + Idx::typeSize(p->type) * p->count;
      if (r > max)
	max = r;
    }
    return max;
  }

  void
  BIdx::kdCopy(void * kO, void * dO, void const * k, void const * d,
	       unsigned int cnt) const
  {
    if (cnt > 1) {
      memmove(kO, k, keySize * cnt);
      memmove(dO, d, dataSize * cnt);
    }
    else {
      memcpy(kO, k, keySize);
      memcpy(dO, d, dataSize);
    }
  }

  Status
  BIdx::create(unsigned int _degree, unsigned dSize,
	       KeyType const keyType[], unsigned nkeys,
	       short _dspid)
  {
    if (!_degree)
      _degree = BIDX_DEF_DEGREE;
    assert(nkeys > 0);

    if (_degree > 32000) {
      stat = statusMake(ERROR, "BTree index: degree too large %u, "
			"maximum is 32000", degree);
      return fatal();
    }

#ifdef ESM_HIDX_REGISTER
    registerStart(dbh, AllOP);
#endif
    dataSize = dSize;
    keySize = calKeySize(keyType, nkeys);
    if ((int)keySize >= MAXKEYSIZE) {
      stat = statusMake(ERROR, "BTree index: key size is too large %u, "
			"maximum is %u", keySize, MAXKEYSIZE);
      return fatal();
    }

    if ((int)keySize < 0) {
      stat = statusMake(ERROR,
			"BTree index: variable key size is not supported");
      return fatal();
    }
    dspid = _dspid;
    degree = _degree;
    maxchildren = degree2MaxChildren(degree);
    count = 0;

    _nkeys = nkeys;
    _keyType = new KeyType[_nkeys];
    memcpy(_keyType, keyType, _nkeys * sizeof (KeyType));

    Node *root = Node::allocNode(degree);
    memset(root, 0, sizeof(*root));
    if (stat = objectCreate(dbh, 0, keySize * maxchildren, dspid, &root->keys)) {
      return fatal();
    }
    if (stat = objectCreate(dbh, 0, dataSize * maxchildren, dspid, &root->data))
      return fatal();

    root->leaf = 1;
    root->n = 0;

    BTree btree;
    memset(&btree, 0, sizeof(btree));
    btree.idxtype = BTreeType;
    btree.count = 0;
    btree.dspid = dspid;
    btree.version = 0;
    btree.degree = degree;
    btree.maxchildren = maxchildren;
    btree.keySize = keySize;
    btree.dataSize = dataSize;
    tmpnode = Node::allocNode(degree);
    if (stat = createNode(root, &btree.root))
      return fatal();

    Node::freeNode(root);
    if (stat = createKeyType(keyType, nkeys, &btree.type))
      return fatal();

    if (stat = objectCreate(dbh, 0, sizeof btree, dspid, &treeOid))
      return fatal();
    if (stat = writeBTree(btree))
      return fatal();

#ifdef ESM_HIDX_REGISTER
    Register *reg;
    registerGet(dbh, &reg);
    fprintf(stdout, "BIdx::create: ");
    registerTrace(stdout, reg);
    registerEnd(dbh);
#endif
    return Success;
  }

  BIdx::BIdx(DbHandle * vh, Type type, unsigned dSize,
	     short _dspid, unsigned int _degree)
    : Idx(False), stat(Success), dbh(vh), free(0), occupied(0),
      _keyType(0), tmpnode(0)
  {
    IDB_LOG(IDB_LOG_IDX_CREATE,
	    ("Creating BTree Index: datasz=%u\n", dSize));

    KeyType keyType;
    keyType.type = type;
    keyType.count = 1;
    keyType.offset = 0;
	
    create(_degree, dSize, &keyType, 1, _dspid);
    count = 0;
    if (!stat) {
      IDB_LOG(IDB_LOG_IDX_CREATE,
	      ("Have Created BTree Index: treeoid=%s\n",
	       getOidString(&treeOid)));
    }
  }

  BIdx::BIdx(DbHandle * vh, unsigned dSize, KeyType const keyType[],
	     short _dspid, unsigned int _degree, unsigned nkeys)
    : Idx(False), stat(Success), dbh(vh), free(0), occupied(0),
      _keyType(0), tmpnode(0)
  {
    create(_degree, dSize, keyType, nkeys, _dspid);
    count = 0;
    Node::freeNode(tmpnode);
    tmpnode = Node::allocNode(degree);
  }

  int
  BIdx::cmp(void const * p, void const * q, unsigned char swap)
  {
    int r;
    for (unsigned i = 0; i < _nkeys; i++) {
      if (r = compare(p, q, &_keyType[i], swap))
	return r;
    }
    return 0;
  }

  unsigned int
  BIdx::getCount() const
  {
    BTree tree;
    if (!readBTree(tree))
      return tree.count;
    return 0;
  }

  short
  BIdx::getDefaultDspid() const
  {
    BTree tree;
    if (!readBTree(tree))
      return tree.dspid;
    return -1;
  }

  void
  BIdx::setDefaultDspid(short _dspid)
  {
    BTree tree;
    if (!readBTree(tree)) {
      tree.dspid = _dspid;
      writeBTree(tree);
    }
  }

  static void
  add(Oid *&oids, unsigned int &cnt, unsigned int &alloc_cnt,
      const Oid &oid)
  {
    if (cnt >= alloc_cnt) {
      alloc_cnt = cnt + 32;
      oids = (Oid *)m_realloc(oids, alloc_cnt * sizeof(Oid));
    }

    oids[cnt++] = oid;
  }

  static Status
  getObjects(const BIdx *idx, Oid *&oids, unsigned int &cnt,
	     unsigned int &alloc_cnt, const Oid &oid)
  {
    Status s;
    BIdx::InCore x(const_cast<BIdx *>(idx));
    if (s = x.read(&oid))
      return s;
	
    add(oids, cnt, alloc_cnt, x.node->keys);
    add(oids, cnt, alloc_cnt, x.node->data);
    add(oids, cnt, alloc_cnt, oid);

    if (!x.node->leaf)
      for (unsigned i = 0; i <= x.node->n; i++)
	if (s = getObjects(idx, oids, cnt, alloc_cnt, x.node->c[i]))
	  return s;

    return Success;
  }

  Status
  BIdx::getObjects(Oid *&oids, unsigned int &cnt) const
  {
    unsigned int alloc_cnt = 0;
    cnt = 0;
    oids = 0;
    BTree tree;
    Status s = readBTree(tree);
    if (s) return s;
    add(oids, cnt, alloc_cnt, treeOid);
    add(oids, cnt, alloc_cnt, tree.type);
    return eyedbsm::getObjects(this, oids, cnt, alloc_cnt, tree.root);
  }

  Status
  BIdx::count_manage(int inc)
  {
    /*
      BTree tree;
      Status s = objectRead(dbh, 0, sizeof tree, &tree,
      DefaultLock, 0, &treeOid);
      if (s) return s;
      unsigned int o_count = tree.count;

      tree.count += inc;
      return objectWrite(dbh, 0, sizeof tree, &tree, &treeOid);
    */

    count += inc;
    unsigned int xcount = h2x_u32(count);
    return objectWrite(dbh, sizeof(unsigned int), sizeof count, &xcount,
		       &treeOid);
  }

  unsigned int
  BIdx::getMagOrder(unsigned int degree)
  {
    if (degree <= 128)
      return 100000;
    if (degree <= 256)
      return 1000000;

    return 10000000;
  }

  unsigned int
  BIdx::getDegree(unsigned int magorder)
  {
    if (magorder <= 100000)
      return 128;
    if (magorder <= 1000000)
      return 256;

    return 512;
  }

  std::string
  BIdx::Stats::toString() const
  {
    std::string s;

    s = std::string("Degree: ") + str_convert(idx->getDegree()) + "\n";
    s += std::string("Data Size: ") + str_convert(idx->getDataSize()) + "\n";
    s += std::string("Key Size: ") + str_convert(idx->getKeySize()) + "\n";
    s += std::string("Key Type: ") + typeString((Idx::Type)keyType) + "\n";
    s += std::string("Key Offset: ") + str_convert(keyOffset) + "\n";
    s += std::string("Total Object Count: ") + str_convert(total_object_count) + "\n";
    s += std::string("Total Btree Object Count: ") + str_convert(total_btree_object_count) + "\n";
    s += std::string("Total Btree Node Count: ") + str_convert(total_btree_node_count) + "\n";
    s += std::string("Btree Node Size: ") + str_convert(btree_node_size) + "\n";
    s += std::string("Btree Key Object Size: ") + str_convert(btree_key_object_size) + "\n";
    s += std::string("Btree Data Object Size: ") + str_convert(btree_data_object_size) + "\n";
    s += std::string("Total Btree Object Size: ") + str_convert(total_btree_object_size) + "\n";
    return s;
  }

  Status
  BIdx::copy_realize(Idx *idx) const
  {
    Status s = Success;
    BIdxCursor curs(const_cast<BIdx *>(this));
    unsigned char *data = new unsigned char[dataSize];

    for (;;) {
      Boolean found;
      Idx::Key key;

      s = curs.next(&found, data, &key);
      if (s) goto error;

      if (!found) break;

      s = idx->insert(key.getKey(), data);
      if (s) goto error;
    }

  error:
    delete [] data;
    return s;
  }

  Status BIdx::move(short dspid, eyedbsm::Oid &newoid)
  {
    return reimplementToBTree(newoid, degree, dspid);
  }

  Status
  BIdx::reimplementToHash(Oid &newoid, int key_count, int mag_order,
			  short _dspid,
			  const int *impl_hints,
			  unsigned int impl_hints_cnt,
			  hash_key_t hash_key,
			  void *hash_data,
			  KeyType *ktype)
  {
    HIdx hidx(dbh, (ktype ? *ktype : *_keyType), dataSize,
	      (_dspid == DefaultDspid ? dspid : _dspid),
	      mag_order,
	      key_count,
	      impl_hints, impl_hints_cnt);
    Status s = hidx.status();
    if (s) return s;

    hidx.open();
    s = copy_realize(&hidx);
    if (s) return s;
    newoid = hidx.oid();
    return destroy();
  }

  Status
  BIdx::reimplementToBTree(Oid &newoid, int _degree, short _dspid)
  {
    if (!_degree)
      _degree = BIDX_DEF_DEGREE;
    if (_dspid == DefaultDspid)
      _dspid = dspid;
	 
    if (_degree == degree && _dspid == dspid) {
      newoid = treeOid;
      return Success;
    }

    BIdx bidx(dbh, dataSize, _keyType, _dspid, _degree, _nkeys);

    Status s = bidx.status();
    if (s) return s;

    s = copy_realize(&bidx);
    if (s) return s;

    newoid = bidx.oid();
    return destroy();
  }

  void
  BIdx::Stats::trace(FILE *fd) const
  {
    fprintf(fd, toString().c_str());
  }

  Status
  BIdx::getStats(std::string& stats) const
  {
    Stats st;
    Status s = getStats(st);
    if (s) return s;
    stats = st.toString();
    return Success;
  }

  Status
  BIdx::getStats(BIdx::Stats &stats) const
  {
    stats.idx = this;
    stats.keyType = _keyType[0].type;
    stats.keyOffset = _keyType[0].offset;
    stats.total_object_count = getCount();

    Oid *oids = 0;
    unsigned int object_count;
    Status s = getObjects(oids, object_count);
    delete [] oids;
    if (s) return s;
    stats.total_btree_object_count = object_count;

    stats.total_btree_node_count = (stats.total_btree_object_count - 2) / 3;
    stats.btree_node_size = Node::nodeSize(this);
    stats.btree_key_object_size = dataSize * maxchildren;
    stats.btree_data_object_size = keySize * maxchildren;

    stats.total_btree_object_size = sizeof(BTree) + sizeof(KeyType) * _nkeys +
      (stats.btree_key_object_size +
       stats.btree_data_object_size +
       stats.btree_node_size) * stats.total_btree_node_count;

    return Success;
  }
}
