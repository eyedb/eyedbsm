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
#include	<iostream>

#include <eyedbsm/eyedbsm.h>
#include	<BIdxBTree.h>
#include	<assert.h>

namespace eyedbsm {
  extern Boolean backend_interrupt;

  class BIdxChain
  {
    BIdxChain * _next;
    BIdx * const idx;
    BIdxChain(BIdxChain const &);
    BIdxChain & operator=(BIdxChain const &);
  public:
    BIdxChain * const prev;
    unsigned i;
    BIdx::InCore blk;

    BIdxChain(BIdx * b, BIdxChain * p) : blk(b), idx(b), prev(p), _next(0)  { }
    ~BIdxChain() {  if (_next) delete _next; }

    BIdxChain * next() { return (_next) ? _next : (_next = new BIdxChain(idx, this));}
  };


  static Status
  findFirst(Oid oid, BIdxChain * chain, BIdxChain * * last)
  {
    Status s;
    while ((s = chain->blk.read(&oid)) == 0 && !chain->blk.node->leaf) {
      chain->i = 0;
      oid = chain->blk.node->c[0];
      chain = chain->next();
    }
    chain->i = 0;
    if (chain->blk.node->n == 0)
      *last = 0;
    else
      *last = chain;
    return s;
  }

  static Status
  bTreeSearchAny(void const * key, Oid oid, BIdx::InCore * x, unsigned * ip, unsigned int *found_cnt, Boolean found_any)
  {
    *found_cnt = 0;
    for (;;) {
      if (backend_interrupt)
	return statusMake(BACKEND_INTERRUPTED, "");
      Status s;
      unsigned i;
      if (s = x->read(&oid))
	return s;
      for (i = 0; i < x->node->n && x->cmp(i, key, OP1_SWAP) < 0; i++)
	;
      if ((i < x->node->n && x->cmp(i, key, OP1_SWAP) == 0)) {
	*ip = i;
	(*found_cnt)++;
	if (found_any)
	  return Success;
      }
      if (x->node->leaf) {
	return Success;
      }
      oid = x->node->c[i];
    }

    return eyedbsm::Success;
  }

  Status
  BIdx::search(void const * key, unsigned int *found_cnt)
  {
    return searchPerform(key, found_cnt, eyedbsm::False, 0);
  }

  Status
  BIdx::searchAny(void const * key, Boolean * found, void * data)
  {
    unsigned int found_cnt;
    Status s = searchPerform(key, &found_cnt, eyedbsm::True, data);
    if (s)
      return s;
    *found = (found_cnt != 0) ? eyedbsm::True : eyedbsm::False;
    return eyedbsm::Success;
  }

  Status
  BIdx::searchPerform(void const * key, unsigned int * found_cnt, Boolean found_any, void * data)
  {
#if 1
    BIdxCursor curs(this, key, key, False, False);

    *found_cnt = 0;
    for (;;) {
      eyedbsm::Boolean found;
      eyedbsm::Status s = curs.next(&found, data);
      if (s)
	return s;

      if (!found)
	break;

      (*found_cnt)++;

      if (found_any)
	return eyedbsm::Success;
      }

    return eyedbsm::Success;
#else
    BTree tree;
    if (stat = readBTree(tree))
      return fatal();
    BIdx::InCore x(this);
    unsigned i;
    Status s;
#if 0
    if (!(s = bTreeSearchAny(key, tree.root, &x, &i, found_cnt, found_any))) {
      if (i < x.node->n && cmp(key, x.k(i), OP2_SWAP) == 0) {
	*found = True;
	if (data)
	  memcpy(data, x.d(i), dataSize);
      }
      else
	*found = False;
    }
#else
    if (!(s = bTreeSearchAny(key, tree.root, &x, &i, found_cnt, found_any))) {
      if (*found_cnt && data) {
	  memcpy(data, x.d(i), dataSize);
      }
    }
#endif
    return s;
#endif
  }

  static Status
  bTreeSearchFirst(void const * key, Oid oid, BIdxChain * c, BIdxChain * * last)
  {
    Boolean exact = False;
    for (;;) {
      Status s;
      if (s = c->blk.read(&oid))
	return s;
      int r;
      for (c->i = 0; c->i < c->blk.node->n && (r = c->blk.cmp(c->i, key, OP1_SWAP)) < 0; c->i++)
	;
      if (c->blk.node->leaf) {
	if (!exact || (c->i < c->blk.node->n && r == 0))
	  *last = c;
	return Success;
      }
      if (c->i < c->blk.node->n && r == 0) {
	*last = c;
	exact = True;
      }
      oid = c->blk.node->c[c->i];
      c = c->next();
    }
  }

  static void *
  copyKey(int n, void const * key)
  {
    if (key == 0)
      return 0;
    return memcpy(new char[n], key, n);
  }
	
  BIdxCursor::BIdxCursor
  (
   BIdx * idxIn,
   void const * sKeyIn,
   void const * eKeyIn,
   Boolean sExclusiveIn,
   Boolean eExclusiveIn,
   Boolean (*_user_cmp)(const void *key, void *cmp_arg),
   void *_cmp_arg
   )
  {
    //std::cout << "EV BIdxCursor OPT\n";
    idx = idxIn;
    sKey = copyKey(idx->keySize, sKeyIn);
    eKey = copyKey(idx->keySize, (eKeyIn == defaultSKey) ? sKeyIn : eKeyIn);
    sExclusive = sExclusiveIn;
    eExclusive = eExclusiveIn;
    chainFirst = chain = 0;
    user_cmp = _user_cmp;
    cmp_arg = _cmp_arg;
  }

  static Status
  nextBIdxChain(BIdxChain * cp, BIdxChain * * out)
  {
    cp->i++;
    if (!cp->blk.node->leaf)
      while (!cp->blk.node->leaf) {
	BIdxChain * p = cp->next();
	Status s;
	if (s = p->blk.read(&cp->blk.node->c[cp->i]))
	  return s;
	cp = p;
	cp->i = 0;
      }
    else if (cp->i >= cp->blk.node->n)
      while ((cp = cp->prev) && cp->i == cp->blk.node->n)
	;
    *out = cp;
    return Success;
  }		

  Status BIdxCursor::next(Boolean *found, DataBuffer &data, Idx::Key *key)
  {
    return statusMake(NOT_YET_IMPLEMENTED, "BIdxCursor::next(Boolean *found, DataBuffer &data, Idx::Key *key)");
  }

  Status
  BIdxCursor::next(unsigned int *found_cnt, Idx::Key *key)
  {
    *found_cnt = 0;
    // for now !
    return statusMake(ERROR, "cannot use this type of cursor on non data_grouped_by_key hash index");
  }

  Status
  BIdxCursor::next(Boolean * found, void * data, Idx::Key * key)
  {
    *found = False;
    for (;;) {
      if (backend_interrupt)
	return statusMake(BACKEND_INTERRUPTED, "");
      Status s;
      if (chain) {
	if (s = nextBIdxChain(chain, &chain))
	  return s;
      }
      else {
	BIdx::BTree tree;
	if (idx->stat = idx->readBTree(tree))
	  return idx->fatal();
	chainFirst = new BIdxChain(idx, 0);
	Status s;
	if (sKey) {
	  if (s = bTreeSearchFirst(sKey, tree.root, chainFirst, &chain))
	    return s;
	  if (chain->i == chain->blk.node->n)
	    if (s = nextBIdxChain(chain, &chain))
	      return s;
	}
	else if (s = findFirst(tree.root, chainFirst, &chain))
	  return s;
      }
      int r;
      while (chain && sKey &&
	     ((r = idx->cmp(sKey, chain->blk.k(chain->i), OP2_SWAP)) > 0 ||
	      (r == 0 && sExclusive)))
	if (s = nextBIdxChain(chain, &chain))
	  return s;

      if (!chain ||
	  (eKey && ((r = idx->cmp(eKey, chain->blk.k(chain->i), OP2_SWAP)) < 0 ||
		    (r == 0 && eExclusive)))) {
	*found = False;
	return Success;
      }

      // EV: added 13/12/01
      if (idx->precmp) {
	void const * sk = sKey ? sKey : eKey;
	if (sk && idx->precmp(sk, chain->blk.k(chain->i),
			      &idx->_keyType[0], r)) {
	  //printf("skipping entry\n");
	  if (!sKey)
	    continue;
	  *found = False;
	  return Success;
	}
      }
      // end added

      if (user_cmp && !user_cmp(chain->blk.k(chain->i), cmp_arg))
	continue;

      *found = True;
#if 0
      if (key)
	key->setKey(chain->blk.k(chain->i), -idx->keySize, *idx->_keyType);
#else
      if (key)
	key->setKey(chain->blk.k(chain->i), idx->keySize, *idx->_keyType);
#endif

      if (data)
	memcpy(data, chain->blk.d(chain->i), idx->dataSize);
      return Success;	
    }
  }

  BIdxCursor::~BIdxCursor()
  {
    delete [] (char **)sKey;
    delete [] (char **)eKey;
    delete chainFirst;
  }

  char const BIdxCursor::defaultSKey[] = "";
}
