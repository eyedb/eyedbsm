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

//#ifdef SECURE

namespace eyedbsm {

Status
objectWrite(DbHandle const *dbh, size_t size, void * object, Oid const *const oid)
{
#ifdef SECURE
	Status s;
	int actualSize;
	if (s = objectSizeGet(dbh, &actualSize, DefaultLock, oid))
		return s;
	assert(size == actualSize);
#endif
	return objectWrite(dbh, 0, size, object, oid);
}

Status
objectRead(DbHandle const *dbh, size_t size, void * object, Oid const *const oid)
{
#ifdef OBJREAD_TRACE
  std::cerr << "READING " << getOidString(oid) << '\n';
#endif
#ifdef SECURE
	Status s;
	int actualSize;
	if (s = objectSizeGet(dbh, &actualSize, DefaultLock, oid))
		return s;
	assert(size == actualSize);
#endif
	return objectRead(dbh, 0, 0, object, DefaultLock, 0, 0, oid);
}

Status
objectDelete(DbHandle const *dbh, size_t size, Oid const *const oid)
{
#ifdef SECURE
	Status s;
	int actualSize;
	if (s = objectSizeGet(dbh, &actualSize, DefaultLock, oid))
		return s;
	assert(size == actualSize);
#endif
	return objectDelete(dbh, oid);
}

}
