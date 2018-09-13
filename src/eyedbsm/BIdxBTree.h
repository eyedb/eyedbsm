/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2008 SYSRA
   
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

#include	<assert.h>

// EV 2017-06-05: reconnected for testing
//#define USE_CACHE
//#define USE_CACHE_CHECK
//#define USE_CACHE_T1
//#define USE_CACHE_TRACE

namespace eyedbsm {

  static inline unsigned int
  degree2MaxChildren(int degree)
  {
    return 2 * degree - 1;
  }

  static const int BIDX_IMPL_HINTS_CNT = 4;

  struct BIdx::BTree
  {
    unsigned int idxtype;
    unsigned int count;
    short dspid;
    unsigned int version;
    unsigned int degree;
    unsigned int maxchildren;
    unsigned int dataSize;
    unsigned int keySize;
    unsigned int impl_hints[BIDX_IMPL_HINTS_CNT]; // 24/12/01 for future use
    Oid root;
    Oid type;
  };

  struct BIdx::Node
  {
    int leaf;
    unsigned int n;
    Oid keys;
    Oid data;
    Oid c[1];

    static unsigned int nodeSize(const BIdx *idx);
    static unsigned int nodeSize(unsigned int);
    static Node *allocNode(BIdx *idx);
    static Node *allocNode(unsigned int degree);
    static Node *copyNode(BIdx *idx, Node *from);
    static void freeNode(Node *);
  };

  class BIdx::InCore
  {
#ifdef USE_CACHE
    void * keys_b, * data_b;
    Node * node_b;
#endif
    void * keys;
    void * data;
  public:
    BIdx * const idx;
    Oid oid;
    Node *node;
	
    InCore(BIdx *);				// constructor: create InCore
    InCore(InCore const &);			// copy constructor
    InCore& operator=(InCore const &);		// assignment: cleanup and copy
    ~InCore();					// destructor: cleanup

    Status create();
    Status destroy();
    Status write();
    Status read(Oid const *);
    void * k(unsigned i) { assert(i < node->n); return (char *)keys + i * idx->keySize;}
    void * d(unsigned i) { assert(i < node->n); return (char *)data + i * idx->dataSize;}
    void const * k(unsigned i) const { assert(i < node->n); return (char const *)keys + i * idx->keySize;}
    void const * d(unsigned i) const { assert(i < node->n); return (char const *)data + i * idx->dataSize;}
    void kdCopy(void * kOut, void * dOut, int xp, unsigned cnt = 1) const {
      idx->kdCopy(kOut, dOut, k(xp), d(xp), cnt);
    }
    void kdCopy(int xp, void const * kIn, void const * dIn, unsigned cnt = 1) {
      idx->kdCopy(k(xp), d(xp), kIn, dIn, cnt);
    }
    void kdCopy(int xp, InCore const * y, int yp, unsigned cnt = 1) {
      kdCopy(xp, y->k(yp), y->d(yp), cnt);
    }
    int cmp(unsigned i, void const * k, void const * d, unsigned char bswap) const;
    int cmp(unsigned i, void const * key, unsigned char bswap) const { return idx->cmp(k(i), key, bswap); }
  };

  Status objectRead(DbHandle const *dbh, size_t size, void * object, Oid const *const oid);
  Status objectWrite(DbHandle const *dbh, size_t size, void * object, Oid const *const oid);
  Status objectDelete(DbHandle const *dbh, size_t size, Oid const *const oid);

  void x2h_btree(BIdx::BTree &btree);
  void h2x_btree(BIdx::BTree &xbtree, const BIdx::BTree &hbtree);

  void x2h_keytype(Idx::KeyType *keytype, unsigned int nkeys);
  void h2x_keytype(Idx::KeyType *xkeytype,
		   const Idx::KeyType *hkeytype, unsigned int nkeys);

  void x2h_node(BIdx::Node &node, unsigned int maxchildren);
  void h2x_node(BIdx::Node &xnode, const BIdx::Node &hnode,
		unsigned int maxchildren, Boolean complete);
}
