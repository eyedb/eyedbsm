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

#include <eyedbsmconfig.h>

#include "kern_p.h"

#define ROOT_ENTRY_BEGIN_SCAN(dbr) \
{\
   DbHeader _dbh(DBSADDR(dbh)); \
   for (int j = 0; j < MAX_ROOT_ENTRIES; j++) { \
     DbRootEntry _dbr = _dbh.vre(j); \
     DbRootEntry *dbr = &_dbr; \

       /*
#define ROOT_ENTRY_BEGIN_SCAN(dbr) \
{\
   DbRootEntry *dbr, \
   *dbrend = &dbh->vd->dbs_addr->vre[MAX_ROOT_ENTRIES]; \
   for (dbr = dbh->vd->dbs_addr->vre; dbr < dbrend; dbr++) \
     {
*/

#define ROOT_ENTRY_END_SCAN(dbr) \
     } \
}

namespace eyedbsm {

Status
ESM_rootEntrySet(DbHandle const *dbh, char const *const key,
		 void const *const data, unsigned int size, Boolean create)
{
#undef PR
#define PR "rootEntrySet: "
  if (!check_dbh(dbh))
    return statusMake(INVALID_DB_HANDLE, PR IDBH);
  else if (!key)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "null key given");
  else if (strlen(key) >= (size_t)MAX_ROOT_KEY)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "maximum key size exceeded: `%d' (maximum is `%d'", strlen(key), MAX_ROOT_KEY);
  else if (size < 0)
    return statusMake(INVALID_ROOT_ENTRY_SIZE, PR "invalid negative size given: `%d'", size);
  else if (size > MAX_ROOT_DATA)
    return statusMake(INVALID_ROOT_ENTRY_SIZE, PR "maximum data size exceeeded: `%d' (maximum is `%d'", size, MAX_ROOT_DATA);
  else
    {
      ROOT_ENTRY_BEGIN_SCAN(dbr)
	if (!strcmp(dbr->key(), key))
          {
            if (create)
	      return statusMake(ROOT_ENTRY_EXISTS, PR "root entry already exists: '%s'", key);
	    memcpy(dbr->data(), data, size);
	    return Success;
	  }

      ROOT_ENTRY_END_SCAN(dbr)

      ROOT_ENTRY_BEGIN_SCAN(dbr)
	if (!dbr->key()[0])
	  {
	    strcpy(dbr->key(), key);
	    memcpy(dbr->data(), data, size);
	    return Success;
	  }
      ROOT_ENTRY_END_SCAN(dbr)

      return statusMake(TOO_MANY_ROOT_ENTRIES, PR "too many root entries: `%d'", MAX_ROOT_ENTRIES);
    }
}

Status
ESM_rootEntryGet(DbHandle const *dbh, char const *const key,
		void *data, int maxsize)
{
#undef PR
#define PR "rootEntryGet: "
  if (!check_dbh(dbh))
    return statusMake(INVALID_DB_HANDLE, PR IDBH);
  else if (!key)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "null key given");
  else if (strlen(key) >= (size_t)MAX_ROOT_KEY)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "maximum key size exceeded: `%d' (maximum is `%d'", strlen(key), MAX_ROOT_KEY);
  else if (maxsize < 0)
    return statusMake(INVALID_ROOT_ENTRY_SIZE, PR "negative maximum size given: `%d'", maxsize);
  else
    {
      ROOT_ENTRY_BEGIN_SCAN(dbr)
	if (strcmp(dbr->key(), key) == 0)
	  {
	    memcpy(data, dbr->data(), MIN(maxsize, MAX_ROOT_DATA));
	    return Success;
	  }
      ROOT_ENTRY_END_SCAN(dbr)
	return statusMake(ROOT_ENTRY_NOT_FOUND, PR "root entry not found: '%s'", key);
    }
}

Status
ESM_rootEntryDelete(DbHandle const *dbh, char const *const key)
{
#undef PR
#define PR "rootEntryDelete: "
  if (!check_dbh(dbh))
    return statusMake(INVALID_DB_HANDLE, PR IDBH);
  else if (!key)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "null key given");
  else if (strlen(key) >= (size_t)MAX_ROOT_KEY)
    return statusMake(INVALID_ROOT_ENTRY_KEY, PR "maximum key size exceeded: `%d' (maximum is `%d'", strlen(key), MAX_ROOT_KEY);
  else
    {
      ROOT_ENTRY_BEGIN_SCAN(dbr)
	if (strcmp(dbr->key(), key) == 0)
	  {
	    dbr->key()[0] = 0;
	    return Success;
	  }
      ROOT_ENTRY_END_SCAN(dbr)
	return statusMake(ROOT_ENTRY_NOT_FOUND, PR "root entry not found: '%s'", key);
    }
}

}
