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

#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<stdio.h>

#include <eyedbsm/eyedbsm.h>
#include	"BIdxBTree.h"
#include        "eyedbsm_p.h"
#include        <eyedbsm/xdr.h>
#include	<assert.h>

#include        <eyedblib/machtypes.h>
#include        <eyedblib/rpc_lib.h>
#include        <eyedblib/thread.h>

#include        <eyedblib/log.h>

namespace eyedbsm {

  Status
  BIdx::readBTree(BTree &btree) const
  {
#ifdef OBJREAD_TRACE
    std::cerr << "reading BTree\n";
#endif
    Status s = objectRead(dbh, sizeof btree, &btree, &treeOid);
    if (!s)
      x2h_btree(btree);
    return s;
  }

  Status
  BIdx::writeBTree(const BTree &hbtree) const
  {
    BTree xbtree;
    h2x_btree(xbtree, hbtree);
    return objectWrite(dbh, sizeof xbtree, &xbtree, &treeOid);
  }

  Status
  BIdx::readKeyType(KeyType *&_keyType, unsigned int _nkeys,
		    const Oid &keytype_oid) const
  {
    _keyType = new KeyType[_nkeys];
#ifdef OBJREAD_TRACE
    std::cerr << "reading keyType\n";
#endif
    Status s = objectRead(dbh, _nkeys*sizeof(KeyType), _keyType,
			  &keytype_oid);
    if (!s)
      x2h_keytype(_keyType, _nkeys);
    return s;
  }

  Status
  BIdx::createKeyType(const KeyType *hkeyType, unsigned int _nkeys,
		      Oid *keytype_oid) const
  {
    KeyType *xkeyType = new KeyType[_nkeys];
    h2x_keytype(xkeyType, hkeyType, _nkeys);
    Status s = objectCreate(dbh, xkeyType, _nkeys*sizeof(KeyType),
			    dspid, keytype_oid);
    delete [] xkeyType;
    return s;
  }

  Status
  BIdx::readNode(Node *node, const Oid &node_oid) const
  {
#ifdef OBJREAD_TRACE
    std::cerr << "reading node\n";
#endif
    Status s = objectRead(dbh, Node::nodeSize(this), node, &node_oid);
    if (!s)
      x2h_node(*node, maxchildren);
    return s;
  }

  static eyedblib::Mutex tmpnode_mt;

  Status
  BIdx::writeNode(const Node *node, const Oid &node_oid) const
  {
    eyedblib::MutexLocker _(tmpnode_mt);
    h2x_node(*tmpnode, *node, maxchildren, True);
    return objectWrite(dbh, Node::nodeSize(this), tmpnode, &node_oid);
  }

  Status
  BIdx::createNode(const Node *node, Oid *node_oid) const
  {
    eyedblib::MutexLocker _(tmpnode_mt);
    h2x_node(*tmpnode, *node, maxchildren, False);
    return objectCreate(dbh, tmpnode, Node::nodeSize(this), dspid, node_oid);
  }


  void x2h_keytype(Idx::KeyType *keytype, unsigned int nkeys)
  {
    static bool checked = false;
    if (!checked) {assert(sizeof(Idx::Type) == sizeof(eyedblib::int32)); checked = true;}

    for (int i = 0; i < nkeys; i++) {
      keytype[i].type = (Idx::Type)x2h_u32(keytype[i].type);
      keytype[i].count = x2h_u32(keytype[i].count);
      keytype[i].offset = x2h_u32(keytype[i].offset);
    }
  }

  void h2x_keytype(Idx::KeyType *xkeytype,
		   const Idx::KeyType *hkeytype, unsigned int nkeys)
  {
    for (int i = 0; i < nkeys; i++) {
      xkeytype[i].type = (Idx::Type)h2x_u32(hkeytype[i].type);
      xkeytype[i].count = h2x_u32(hkeytype[i].count);
      xkeytype[i].offset = h2x_u32(hkeytype[i].offset);
    }
  }

  void x2h_btree(BIdx::BTree &btree)
  {
    btree.idxtype = x2h_u32(btree.idxtype);
    btree.count = x2h_u32(btree.count);
    btree.dspid = x2h_16(btree.dspid);
    btree.version = x2h_u32(btree.version);
    btree.degree = x2h_u32(btree.degree);
    btree.maxchildren = x2h_u32(btree.maxchildren);
    btree.dataSize = x2h_u32(btree.dataSize);
    btree.keySize = x2h_u32(btree.keySize);
    for (int i = 0; i < BIDX_IMPL_HINTS_CNT; i++)
      //if (btree.impl_hints[i])
      btree.impl_hints[i] = x2h_u32(btree.impl_hints[i]);
    x2h_oid(&btree.root, &btree.root);
    x2h_oid(&btree.type, &btree.type);
  }

  void h2x_btree(BIdx::BTree &xbtree, const BIdx::BTree &hbtree)
  {
    xbtree.idxtype = h2x_u32(hbtree.idxtype);
    xbtree.count = h2x_u32(hbtree.count);
    xbtree.dspid = h2x_16(hbtree.dspid);
    xbtree.version = h2x_u32(hbtree.version);
    xbtree.degree = h2x_u32(hbtree.degree);
    xbtree.maxchildren = h2x_u32(hbtree.maxchildren);
    xbtree.dataSize = h2x_u32(hbtree.dataSize);
    xbtree.keySize = h2x_u32(hbtree.keySize);
    for (int i = 0; i < BIDX_IMPL_HINTS_CNT; i++)
      //if (hbtree.impl_hints[i])
      xbtree.impl_hints[i] = h2x_u32(hbtree.impl_hints[i]);
    h2x_oid(&xbtree.root, &hbtree.root);
    h2x_oid(&xbtree.type, &hbtree.type);
  }

  void x2h_node(BIdx::Node &node, unsigned int maxchildren)
  {
    node.leaf = x2h_32(node.leaf);
    node.n = x2h_u32(node.n);
    x2h_oid(&node.keys, &node.keys);
    x2h_oid(&node.data, &node.data);

    for (int i = 0; i <= maxchildren; i++) // 27/08/03 changed < to <=
      x2h_oid(&node.c[i], &node.c[i]);
  }

  void h2x_node(BIdx::Node &xnode, const BIdx::Node &hnode,
		unsigned int maxchildren, Boolean complete)
  {
    xnode.leaf = h2x_32(hnode.leaf);
    xnode.n = h2x_u32(hnode.n);
    h2x_oid(&xnode.keys, &hnode.keys);
    h2x_oid(&xnode.data, &hnode.data);

    if (complete)
      for (int i = 0; i <= maxchildren; i++) // 27/08/03 changed < to <=
	h2x_oid(&xnode.c[i], &hnode.c[i]);
  }
}
