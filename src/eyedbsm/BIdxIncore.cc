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

#include <eyedblib/thread.h>
#include	<stdlib.h>
#include	<iostream>
#include	<string.h>
#include	<assert.h>
#include <iostream>

#include <eyedbsm/eyedbsm.h>
#include	"BIdxBTree.h"
#include <eyedblib/m_mem.h>

// FD CHECK: include a lib/ private header
#include "lib/m_mem_p.h"

//#define USE_CACHE
//#define USE_CACHE_CHECK
//#define USE_CACHE_T1
//#define USE_CACHE_TRACE

#define NOMEMZERO

namespace eyedbsm {

  Status
  BIdx::InCore::create()
  {
#ifdef USE_CACHE
    if (oid.getNX()) {
      if (node_b) {
	node = node_b;
	node_b = 0;
      }

      if (keys_b) {
	keys = keys_b;
	keys_b = 0;
      }

      if (data_b) {
	data = data_b;
	data_b = 0;
      }
    }
#ifdef USE_CACHE_TRACE
    std::cerr << "InCore::create(" << getOidString(&oid);
#endif
#endif
    if (idx->stat = objectCreate(idx->dbh, keys,
				 idx->keySize * idx->maxchildren,
				 idx->dspid, &node->keys))
      return idx->fatal();
    if (idx->stat = objectCreate(idx->dbh, data,
				 idx->dataSize * idx->maxchildren,
				 idx->dspid, &node->data))
      return idx->fatal();
    if (idx->stat = idx->createNode(node, &oid))
      return idx->fatal();

#ifdef USE_CACHE_TRACE
    std::cerr << " => " << getOidString(&oid) << ")\n";
#endif
    return idx->stat;
  }

  Status
  BIdx::InCore::destroy()
  {
    if (idx->stat = objectDelete(idx->dbh, idx->keySize * idx->maxchildren, &node->keys))
      return idx->fatal();
    if (idx->stat = objectDelete(idx->dbh, idx->dataSize * idx->maxchildren, &node->data))
      return idx->fatal();
    if (idx->stat = objectDelete(idx->dbh, Node::nodeSize(idx), &oid))
      return idx->fatal();
    return idx->stat;
  }

  BIdx::InCore&
  BIdx::InCore::operator=(InCore const & y)
  {
    if (this != &y) {
#ifdef USE_CACHE_TRACE
      std::cerr << "InCore::operator=(InCore const &, " <<
	"node=" << node << ", node_b=" << node_b <<
	", y.node=" << y.node << ", y.node_b=" << y.node_b << ")\n";
#endif
      assert(idx == y.idx); 

#ifdef USE_CACHE
      if ((node && node == y.node) ||
	  (node && node == y.node_b) ||
	  (node_b && node_b == y.node) ||
	  (node_b && node_b == y.node_b))
	std::cerr << "BIdx::InCore::operator=(): strange...!\n";
#endif

      // changed the 16/04/02
      if (node != y.node) {
#ifdef USE_CACHE
	if (node_b) {
	  node = node_b;
	  node_b = 0;
	}

	if (node_b != y.node &&
	    node_b != y.node_b &&
	    node != y.node_b)
#endif
	  Node::freeNode(node);
      }

#ifdef USE_CACHE
      node_b = 0;
#endif
      node = Node::copyNode(idx, y.node);
      //cout << "copy this=" << this << ", from=" << &y << ", " << getOidString(&oid) << " -> " << getOidString(&y.oid) << "\n";
      oid = y.oid;
#ifdef USE_CACHE
      if (keys_b) {
	keys = keys_b;
	keys_b = 0;
      }
      if (data_b) {
	data = data_b;
	data_b = 0;
      }
#endif
      memcpy(keys, y.keys, idx->keySize * idx->maxchildren);
      memcpy(data, y.data, idx->dataSize * idx->maxchildren);
    }
    return *this;
  }

  struct BIdx::Space
  {
    void * keys;
    void * data;
    Space * next;
    friend class InCore;
    Space(BIdx * idx, Space * n)
      : next(n), keys(new char[idx->keySize * idx->maxchildren]), data(new char[idx->dataSize * idx->maxchildren])
    {
    }
    ~Space() { delete [] (char **)keys; delete [] (char **)data; }
  };

  BIdx::~BIdx()
  {
    delete [] _keyType;
    Space *p;

    for (; p = free; delete p)
      free = p->next;
    for (; p = occupied; delete p)
      occupied = p->next;

    Node::freeNode(tmpnode);
  }

  static void
  getSpace(BIdx * idx, BIdx::Space * * free, BIdx::Space * * occupied, void * * keys, void * * data)
  {
    BIdx::Space * p = *free;
    if (p) {
      *free = p->next;
      p->next = *occupied;
      *occupied = p;
    }
    else
      *occupied = p = new BIdx::Space(idx, *occupied);
    *keys = p->keys;
    *data = p->data;
  }

  BIdx::InCore::InCore(InCore const & y) : idx(y.idx)
  {
#ifdef USE_CACHE
    keys_b = data_b = 0;
    node_b = 0;
#endif
#ifdef USE_CACHE_TRACE
    std::cerr << "InCore::InCore(InCore const &)\n";
#endif
    getSpace(idx, &idx->free, &idx->occupied, &keys, &data);
    node = Node::copyNode(idx, y.node);
    oid = y.oid;
    memcpy(keys, y.keys, idx->keySize * idx->maxchildren);
    memcpy(data, y.data, idx->dataSize * idx->maxchildren);
  }

  BIdx::InCore::InCore(BIdx * b) : idx(b)
  {
#ifdef USE_CACHE
    keys_b = data_b = 0;
    node_b = 0;
#endif
    getSpace(idx, &idx->free, &idx->occupied, &keys, &data);
    /*
     *	The initializations below are just to shutup dbx/purify.
     *	The illegal value are to provoke an error if we forget to overwrite thes values.
     */
    node = Node::allocNode(idx);
    node->leaf = 2; // illegal value
    node->n = b->maxchildren + 2; // illegal value

    oid = Oid::nullOid;
#ifndef NOMEMZERO
    memset(keys, 0, idx->keySize * idx->maxchildren);
    memset(data, 0, idx->dataSize * idx->maxchildren);
#endif
  }

  BIdx::InCore::~InCore()
  {
    Space * p = idx->occupied;
#ifdef USE_CACHE
    if (node_b)
      node = node_b;
    if (keys_b)
      keys = keys_b;
    if (data_b)
      data = data_b;
#endif
    p->keys = keys;
    p->data = data;
    idx->occupied = p->next;
    p->next = idx->free;
    idx->free = p;
    Node::freeNode(node);
    //	delete [] (char *)keys; delete [] (char *)data;
  }

  Status
  BIdx::InCore::read(Oid const * oidp)
  {
#ifdef USE_CACHE_TRACE
    if (oid.getNX() && memcmp(&oid, oidp, sizeof(oid))) {
      std::cerr << "HORROR: changing oid in read " << getOidString(&oid) << " vs. "<< getOidString(oidp) << "\n";
    }
#endif
    oid = *oidp;

#ifdef USE_CACHE
    Status se;
    void *xdata = 0;
    if (idx->stat = objectReadCache(idx->dbh, 0, &xdata, DefaultLock,
				    &oid))
      return idx->fatal();
#ifdef USE_CACHE_TRACE
    std::cerr << "Reading node xdata = " << xdata << "\n";
#endif
    if (xdata) {
#ifdef USE_CACHE_TRACE
      std::cerr << "CHECK: this=" << this << ", node_b=" << node_b << ", node=" << node << "\n";
#endif

#ifdef USE_CACHE
      if (!node_b) // added the 16/04/02
	node_b = node;
      else
	std::cerr << "BIdx::InCore::read(): strange\n";
#endif

#ifdef USE_CACHE_TRACE
      std::cerr << "have read from cache " << getOidString(&oid) << "\n";
#endif
#ifdef USE_CACHE_CHECK

      if (idx->stat = idx->readNode(node, oid))
	return idx->fatal();
      assert(!memcmp(node, xdata, Node::nodeSize(idx)));
#endif
      node = (Node *)xdata;
    }
    else if (idx->stat = idx->readNode(node, oid))
      return idx->fatal();

    if (idx->stat = objectReadCache(idx->dbh, 0, &xdata, DefaultLock,
				    &node->keys))
      return idx->fatal();
#ifdef USE_CACHE_TRACE
    std::cerr << "Reading keys xdata = " << xdata << "\n";
#endif
    if (xdata) {
      if (!keys_b) // added the 16/04/02
	keys_b = keys;
#ifdef USE_CACHE_CHECK
      if (idx->stat = objectRead(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
	return idx->fatal();
      assert(!memcmp(keys, xdata, idx->keySize * idx->maxchildren));
#endif
      keys = xdata;
    }
    else if (idx->stat = objectRead(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
      return idx->fatal();
    if (idx->stat = objectReadCache(idx->dbh, 0, &xdata, DefaultLock,
				    &node->data))
      return idx->fatal();
#ifdef USE_CACHE_TRACE
    std::cerr << "Reading data xdata = " << xdata << "\n";
#endif
    if (xdata) {
      if (!data_b) // added the 16/04/02
	data_b = data;
#ifdef USE_CACHE_CHECK
      if (idx->stat = objectRead(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data))
	return idx->fatal();
      assert(!memcmp(data, xdata, idx->dataSize * idx->maxchildren));
#endif
      data = xdata;
    }
    else {
      idx->stat = objectRead(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data);
      if (idx->stat) {
	return idx->fatal();
      }
    }
    return idx->stat;

#else

    if (idx->stat = idx->readNode(node, oid))
      return idx->fatal();

#ifdef OBJREAD_TRACE
    std::cerr << "reading keys object " << getOidString(&node->keys) << " " << (idx->dataSize * idx->maxchildren) << '\n';
#endif
    if (idx->stat = objectRead(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
      return idx->fatal();
#ifdef OBJREAD_TRACE
    std::cerr << "reading data object " << getOidString(&node->data) << " " << (idx->dataSize * idx->maxchildren) << '\n';
#endif
    if (idx->stat = objectRead(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data))
      return idx->fatal();
    return idx->stat;
#endif
  }

  //
  // this routine can be improved a lot in insertion process:
  // 1. if btreeSplitChild has not been called, it is not necessary to write
  //    back to the database the entire node (which sizeof is 2068). Only leaf
  //    and n fields must be written
  // 2. only a part of keys and data could be written back to database according
  //    what has been shifted with kdCopy. In average, only half of the 2 objects
  //    must be written.

  Status
  BIdx::InCore::write()
  {
#if 0
    Node tmpnode;
    if (idx->stat = objectRead(idx->dbh, sizeof tmpnode, &tmpnode, &oid))
      return idx->fatal();
    printf("nodes %sdiffer\n", memcmp(&tmpnode, &node, sizeof(node)) ?
	   "" : "DO NOT ");
    printf("nodes %sreally differ\n", memcmp(tmpnode->c, node->c, sizeof(Oid) * (NCHILDREN+2)) ?
	   "" : "DO NOT ");
#endif

#ifdef USE_CACHE
    if (node_b) {
#ifdef USE_CACHE_TRACE
      std::cerr << "writing node cache this=" << this << ", " << node << ", " << getOidString(&oid) << "\n";
#endif
      if (idx->stat = objectWriteCache(idx->dbh, 0, node, &oid))
	return idx->fatal();
#ifdef USE_CACHE_CHECK
      void *xdata = 0;
      if (idx->stat = objectReadCache(idx->dbh, 0, &xdata, DefaultLock,
				      &oid))
	return idx->fatal();
#ifdef USE_CACHE_TRACE
      std::cerr << "xdata = " << xdata << "\n";
#endif
      assert(!memcmp(node, xdata, Node::nodeSize(idx)));
      if (idx->stat = idx->readNode(node_b, oid))
	return idx->fatal();
      assert(!memcmp(node, node_b, Node::nodeSize(idx)));
#endif
    }
    else if (idx->stat = idx->writeNode(node, oid))
      return idx->fatal();

    if (keys_b) {
#ifdef USE_CACHE_TRACE
      std::cerr << "writing keys cache " << keys_b << "\n";
#endif
#ifdef USE_CACHE_T1
      if (idx->stat = objectWrite(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
	return idx->fatal();
#else
      if (idx->stat = objectWriteCache(idx->dbh, 0, keys, &node->keys))
	return idx->fatal();
#endif
    }
    else if (idx->stat = objectWrite(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
      return idx->fatal();

    if (data_b) {
#ifdef USE_CACHE_TRACE
      std::cerr << "writing data cache " << keys_b << "\n";
#endif
#ifdef USE_CACHE_T1
      if (idx->stat = objectWrite(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data))
	return idx->fatal();
#else
      if (idx->stat = objectWriteCache(idx->dbh, 0, data, &node->data))
	return idx->fatal();
#endif
    }
    else if (idx->stat = objectWrite(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data))
      return idx->fatal();

#else

    if (idx->stat = idx->writeNode(node, oid))
      return idx->fatal();

    if (idx->stat = objectWrite(idx->dbh, idx->keySize * idx->maxchildren, keys, &node->keys))
      return idx->fatal();
    if (idx->stat = objectWrite(idx->dbh, idx->dataSize * idx->maxchildren, data, &node->data))
      return idx->fatal();
#endif

    return idx->stat;
  }

  int
  BIdx::InCore::cmp(unsigned i, void const * kIn, void const * dIn,
		    unsigned char bswap) const
  {
    int const r = idx->cmp(k(i), kIn, bswap);
    return (r) ? r : memcmp(d(i), dIn, idx->dataSize);
  }

  unsigned int BIdx::Node::nodeSize(const BIdx *idx)
  {
    return sizeof(Node) + idx->maxchildren * sizeof(Oid);
  }

  unsigned int BIdx::Node::nodeSize(unsigned int maxchildren)
  {
    return sizeof(Node) + maxchildren * sizeof(Oid);
  }

  BIdx::Node *BIdx::Node::allocNode(BIdx *idx)
  {
#ifdef NOMEMZERO
    return (Node *)m_malloc(nodeSize(idx));
#else
    return (Node *)m_calloc(nodeSize(idx), 1);
#endif
  }

  BIdx::Node *BIdx::Node::allocNode(unsigned int degree)
  {
#ifdef NOMEMZERO
    return (Node *)m_malloc(nodeSize(degree2MaxChildren(degree)));
#else
    return (Node *)m_calloc(nodeSize(degree2MaxChildren(degree)), 1);
#endif
  }

  BIdx::Node *BIdx::Node::copyNode(BIdx *idx, Node *from)
  {
    Node *node = allocNode(idx);
    memcpy(node, from, nodeSize(idx));
    return node;
  }

  void BIdx::Node::freeNode(Node *node)
  {
    ::free(node);
  }
}
