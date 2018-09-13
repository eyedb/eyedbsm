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
#include	<string.h>
#include	<assert.h>

#include	<eyedbsm/eyedbsm.h>
#include	<eyedbsm/BIdx.h>
#include	"BIdxBTree.h"
#include	"IdxP.h"

namespace eyedbsm {

  static Boolean
  look(BIdx::InCore const * x, void const * key, void const * data, unsigned * ip)
  {
    unsigned i;
    for (i = 0; i < x->node->n; i++) {
      int r;
      if ((r = x->cmp(i, key, data, OP1_SWAP)) == 0) {
	*ip = i;
	return True;
      }
      else if (r > 0)	{
	*ip = i;
	return False;
      }
    }
    *ip = i;
    return False;
  }

  static void
  kdcCopy(BIdx::InCore * x, unsigned xp, BIdx::InCore const * y, unsigned yp)
  {
    x->kdCopy(xp, y, yp);
    x->node->c[xp] = y->node->c[yp];
  }

  static Status
  merge(BIdx::InCore * x, unsigned const i, BIdx::InCore * y, BIdx::InCore * z)
  {
    Status s;
    unsigned j;

    y->node->n++;
    y->kdCopy(y->node->n - 1, x, i);

    for (j = i; j < x->node->n - 1; j++)
      x->kdCopy(j, x, j + 1);
    for (j = i + 1; j < x->node->n; j++)
      x->node->c[j] = x->node->c[j + 1];
    x->node->n--;
    if (s = x->write())
      return s;

    unsigned const yn = y->node->n;
    y->node->n += z->node->n;
    for (j = 0; j < z->node->n; j++)
      kdcCopy(y, yn + j, z, j);
    y->node->c[yn + j] = z->node->c[j];
    return z->destroy();
  }

  /*
   *	Case 3a (move a key left)
   */
  static void
  moveLeft(BIdx::InCore * to, BIdx::InCore * middle, unsigned const middlep, BIdx::InCore * from)
  {
    unsigned i;
    to->node->n++;
    to->kdCopy(to->node->n - 1, middle, middlep);
    to->node->c[to->node->n] = from->node->c[0];

    middle->kdCopy(middlep, from, 0);

    for (i = 1; i < from->node->n; i++)
      kdcCopy(from, i - 1, from, i);
    from->node->c[i - 1] = from->node->c[i];
    from->node->n--;
  }

  /*
   *	Case 3a (move a key right)
   */
  static void
  moveRight(BIdx::InCore * to, BIdx::InCore * middle, unsigned const middlep, BIdx::InCore * from)
  {
    unsigned j;
    to->node->c[to->node->n + 1] = to->node->c[to->node->n];
    for (j = to->node->n++; j > 0; j--)
      kdcCopy(to, j, to, j - 1);
    to->kdCopy(0, middle, middlep - 1);
    to->node->c[0] = from->node->c[from->node->n];

    middle->kdCopy(middlep - 1, from, from->node->n - 1);
    from->node->n--;
  }

  Status
  change(BIdx::InCore * old, BIdx::InCore * newV, Boolean * write)
  {
    if (*write) {
      *write = False;
      Status s;
      if (s = old->write())
	return s;
    }
    *old = *newV;
    return Success;
  }

  static Status
  bTreeDelete(BIdx * idx, BIdx::InCore x, void const * key, void const * data,
	      Boolean * found)
  {
    unsigned writeBackPos;
    BIdx::InCore writeBackNode(idx);
    unsigned i;
    Status s;
    Boolean here;
    enum { KEY, FIRST, LAST } status = KEY; // what to delete
    BIdx::InCore y(idx);
    BIdx::InCore z(idx);
    Boolean writeX = False;
    unsigned int degree = idx->getDegree();
    while (!x.node->leaf) {
      if (status != KEY) {
	here = False;
	i = (status == FIRST) ? 0 : x.node->n;
      }
      else
	here = look(&x, key, data, &i);
		
      if (here) {
	if (s = y.read(&x.node->c[i]))
	  return s;
	if (y.node->n >= (unsigned)degree) {
	  writeBackNode = x;
	  writeBackPos = i;
	  status = LAST;
	  if (s = change(&x, &y, &writeX))
	    return s;
	}
	else {
	  if (s = z.read(&x.node->c[i + 1]))
	    return s;
	  if (z.node->n >= (unsigned)degree) {
	    writeBackNode = x;
	    writeBackPos = i;
	    status = FIRST;
	    if (s = change(&x, &z, &writeX))
	      return s;
	  }
	  else {
	    if (s = merge(&x, i, &y, &z))
	      return s;
	    writeX = True;
	    x = y;
	  }
	}
      }
      else {
	if (s = y.read(&x.node->c[i]))
	  return s;
	if (y.node->n != (unsigned)degree - 1) {
	  if (s = change(&x, &y, &writeX))
	    return s;
	}
	else {
	  if (i > 0 && (s = z.read(&x.node->c[i - 1])))
	    return s;
	  if (i > 0 && z.node->n >= (unsigned)degree) {
	    moveRight(&y, &x, i, &z);
	    if (s = z.write())
	      return s;
	    if (s = x.write())
	      return s;
	    x = y;
	  }
	  else {
	    if (i != x.node->n && (s = z.read(&x.node->c[i + 1])))
	      return s;
	    if (i != x.node->n && z.node->n >= (unsigned)degree) {
	      moveLeft(&y, &x, i, &z);
	      if ((s = z.write()) || (s = x.write()))
		return s;
	      x = y;
	    }
	    else if (i == x.node->n) {
	      if (s = merge(&x, i - 1, &z, &y))
		return s;
	      x = z;
	    }
	    else {
	      if (s = merge(&x, i, &y, &z))
		return s;
	      x = y;
	    }
	  }
	  writeX = True;
	}
      }
    }

    if (status == KEY)
      here = look(&x, key, data, &i);
    else {
      here = True;
      i = (status == FIRST) ? 0 : x.node->n - 1;
      writeBackNode.kdCopy(writeBackPos, &x, i);
      if (s = writeBackNode.write())
	return s;
    }
	
    if (here) {
      for (; i < x.node->n - 1; i++)
	x.kdCopy(i, &x, i + 1);
      x.node->n--;
      if (s = x.write())
	return s;
    }
    else if (writeX && (s = x.write()))
      return s;
    if (found)
      *found = here;
    return Success;
  }

  Status BIdx::remove(const void *key, const void *data, unsigned int datasz, Boolean *found)
  {
    return statusMake(NOT_YET_IMPLEMENTED, "BIdx::remove(const void *key, const void *data, unsigned int datasz, Boolean *found)");
  }

  Status BIdx::remove(void const * key, void const * data, Boolean * found)
  {
    if (stat)
      return stat;

    IdxLock lockx(dbh, treeOid);
    Status s = lockx.lock();
    if (s)
      return s;

    BIdx::InCore x(this);
    BTree tree;
    if (stat = readBTree(tree))
      return fatal();
    if (s = x.read(&tree.root))
      return s;
    if (s = bTreeDelete(this, x, key, data, found))
      return s;
    if (x.node->n == 0 && !x.node->leaf) {
      tree.root = x.node->c[0];
      if (stat = x.destroy())
	return stat;
      if (stat = writeBTree(tree))
	return fatal();
    }

    return count_manage(-1);

  }
}
