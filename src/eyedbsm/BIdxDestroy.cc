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

#include <eyedbsm/eyedbsm.h>
#include	"BIdxBTree.h"

namespace eyedbsm {

  static Status
  destroyS(BIdx * idx, Oid oid)
  {
    Status s;
    BIdx::InCore x(idx);
    if (s = x.read(&oid))
      return s;
	
    if (!x.node->leaf)
      for (unsigned i = 0; i <= x.node->n; i++)
	if (s = destroyS(idx, x.node->c[i]))
	  return s;

    return x.destroy();
  }

  Status
  BIdx::destroy()
  {
    BTree tree;
    if (stat = readBTree(tree))
      return fatal();
    if (stat = objectDelete(dbh, sizeof tree, &treeOid))
      return fatal();
    if (stat = objectDelete(dbh, _nkeys * sizeof (KeyType), &tree.type))
      return fatal();
    return destroyS(this, tree.root);
  }
}
