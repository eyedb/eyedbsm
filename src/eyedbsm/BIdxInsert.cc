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
#include	<string.h>
#include	<assert.h>
#include <iostream>

#include <eyedbsm/eyedbsm.h>
#include	"BIdxBTree.h"
#include	"IdxP.h"

//#define ESM_HIDX_REGISTER

namespace eyedbsm {

  static Status
  bTreeSplitChild(BIdx::InCore * x, int i, BIdx::InCore * y, BIdx::InCore * z)
  {
    Status s;
    int j;

    //cout << "\n **************** bTreeSplitChild\n";

    unsigned int degree = y->idx->getDegree();
    BIdx * idx = y->idx;
    z->node->leaf = y->node->leaf;
    z->node->n = degree - 1;
    for (j = 0; j < degree - 1; j++)
      z->kdCopy(j, y, j + degree);
    if (!y->node->leaf)
      for (j = 0; j < degree; j++)
	z->node->c[j] = y->node->c[j + degree];
    for (j = x->node->n; j >= i + 1; j--)
      x->node->c[j + 1] = x->node->c[j];
    x->node->c[i + 1] = z->oid;

    for (j = x->node->n++ - 1; j >= i; j--)
      x->kdCopy(j + 1, x, j);
    x->kdCopy(i, y, degree - 1);
    y->node->n = degree - 1;
    if (s = y->write())
      return s;
    if (s = z->write())
      return s;
    return x->write();
  }

  //#define CMP_TRACE
  //#define DICHO_VERIF
#define DICHO
  //#define DICHO_PARTIAL

#ifdef DICHO
  int
  find(int i, BIdx::InCore *x, void const * key, void const * data)
  {
    if (i < 0)
      return i;
    int start, end, k;

    start = 0;
    end = i+1;
    k = (i+1) >> 1;

    int nn;
#ifdef CMP_TRACE
    cout << "start = " << start << ", end = " << end << ", k = " << k
	 << ", i = " << i << "\n";
#endif
    for (nn = 1; ; nn++) {
      int old_k = k;
      int r = x->cmp(k, key, data, OP1_SWAP);
#ifdef CMP_TRACE
      cout << "cmp k = " << k << ", r = " << r << "\n";
#endif
      if (!r) {
	for (int j = k-1; j >= 0; j--) {
	  if (x->cmp(j, key, data, OP1_SWAP)) {
#ifdef CMP_TRACE
	    if (j+1 != k) 
	      cout << "... minimum is #" << (j+1) << endl;
#endif
	    k = j+1;
	    break;
	  }
	}
	break;
      }

      if (r > 0) {
	end = k;
	k = start + ((k - start) >> 1);
      }
      else {
	start = k;
	k = start + ((end - k) >> 1);
      }

      if (end - start <= 1 && (k == old_k || x->cmp(k, key, data, OP1_SWAP))) {
#ifdef CMP_TRACE
	cout << "break start = " << start << ", end = " << end << "\n";
#endif
	k = start;
	break;
      }
    }
    if (k == 0 && x->cmp(k, key, data, OP1_SWAP) > 0)
      k = -1;
#ifdef CMP_TRACE
    cout << "dichotomic found #" << k << " has made " << nn <<
      " comparisons\n";
#endif

#ifdef DICHO_VERIF
    int j;
    for (j = i; j >= 0 && x->cmp(j, key, data, OP1_SWAP) >= 0; j--)
      ;

    if (k != j)
      cout << "k " << k << " vs. j " << j;

    assert(k == j);
#endif

#ifndef DICHO_PARTIAL
    if (k != i)
      x->kdCopy(k + 2, x, k + 1, i - k);
#endif
    return k;
  }
#endif

  static Status
  bTreeInsertNonfull(BIdx * b, BIdx::InCore * x, void const * key, void const * data)
  {
    BIdx::InCore z(b);
    BIdx::InCore a(b);
    int i;
    Status s;
    BIdx * idx = x->idx;
    unsigned int degree = idx->getDegree();

    while (!x->node->leaf) {
      for (i = x->node->n - 1; i >= 0 && x->cmp(i, key, data, OP1_SWAP) >= 0; i--)
	;
      i++;
      if (s = z.read(&x->node->c[i]))
	return s;
      if (z.node->n == 2 * degree - 1) {
	if (s = a.create())
	  return s;;
	if (s = bTreeSplitChild(x, i, &z, &a))
	  return s;
	*x = (x->cmp(i, key, data, OP1_SWAP) <= 0) ? a : z;
      }
      else
	*x = z;
    }

    i = x->node->n - 1;
    x->node->n++;

    // the following loop can be improved:
    // 1. instead of making N kdCopy of 1 item (keySize and datSize), one
    //    could be perform the loop and then make only one kdCopy of N items
    // 2. a dichotomic comparison instead of performing the loop could reduce
    //    the number of comparison from N to log2(N)
	
#ifdef CMP_TRACE
    cout << "[btree degree = " << degree <<
      "] starting comparing for inserting at #" << i << '\n';
#endif
    int start_i = i;
#ifdef DICHO
    i = find(i, x, key, data);
#endif
#if defined(DICHO_PARTIAL) || !defined(DICHO)
    i = start_i;
    for (; i >= 0 && x->cmp(i, key, data, OP1_SWAP) >= 0; i--) {
#ifdef CMP_TRACE
      cout << "comparing for inserting #" << i << '\n';
#endif
      x->kdCopy(i + 1, x, i);
    }
#endif

#ifdef CMP_TRACE
    cout << "direct found #" << i <<
      " has made " << (start_i - i + 1) << " comparisons\n";
#endif

    unsigned int nkeys;
    const Idx::KeyType *keyType = idx->getKeyTypes(nkeys);
    if (keyType->type == Idx::tUnsignedChar ||
	keyType->type == Idx::tChar ||
	keyType->type == Idx::tSignedChar ||
	keyType->type == Idx::tString)
      x->kdCopy(i + 1, key, data);
    else {
      char xkey[Idx_max_type_size];
      Idx::h2x(xkey, key, *keyType);
      x->kdCopy(i + 1, xkey, data);
    }
    return x->write();
  }

  Status BIdx::insert(const void *key, const void *data, unsigned int datasz)
  {
    return statusMake(NOT_YET_IMPLEMENTED, "BIdx::insert(const void *key, const void *data, unsigned int datasz)");
  }

  //#define USE_CACHE
  Status BIdx::insert(void const * key, void const * data)
  {
    if (stat)
      return stat;

#ifdef ESM_HIDX_REGISTER
    registerStart(dbh, AllOP);
#endif
    IdxLock lockx(dbh, treeOid);
    Status s = lockx.lock();
    if (s)
      return s;

    BTree tree;
    BTree *xtree;
#ifdef USE_CACHE
    if (stat = objectReadCache(dbh, 0, (void **)&xtree, DefaultLock,
			       &treeOid))
      return fatal();
    if (!xtree) {
      if (stat = readBTree(tree))
	return fatal();
      xtree = &tree;
    }
#else
    if (stat = readBTree(tree))
      return fatal();
    xtree = &tree;
#endif
    BIdx::InCore x(this);
    // this can be improved:
    // one can read only one part of the node: the fields keys, data and n
    // and if n is == 2 * degree - 1, then we read the c[] array:
    // we should swap the attributes leaf, n, c, keys, data to
    // leaf, n, keys, data, c to improved partial readings
    if (stat = x.read(&xtree->root))
      return stat;
    if (x.node->n == 2 * degree - 1) {
      BIdx::InCore r = x;
      if (stat = x.create())
	return stat;
      xtree->root = x.oid;
#ifdef USE_CACHE
      if (xtree != &tree) {
	if (stat = objectWriteCache(dbh, 0, xtree, &treeOid))
	  return fatal();
      }
      else if (stat = writeBTree(tree))
	return fatal();
#else
      if (stat = writeBTree(tree))
	return fatal();
#endif
      x.node->leaf = 0;
      x.node->n = 0;
      x.node->c[0] = r.oid;
      BIdx::InCore z(this);
      if (stat = z.create())
	return stat;
      if (stat = bTreeSplitChild(&x, 0, &r, &z))
	return stat;
    }
    stat = bTreeInsertNonfull(this, &x, key, data);
#ifdef ESM_HIDX_REGISTER
    Register *reg;
    registerGet(dbh, &reg);
    fprintf(stdout, "BIdx::insert: ");
    registerTrace(stdout, reg);
    registerEnd(dbh);
#endif
    if (!stat)
      return count_manage(1);
    return stat;
  }
}
