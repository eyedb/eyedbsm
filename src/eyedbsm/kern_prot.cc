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

namespace eyedbsm {

const Protection p_all = { ReadAll, WriteAll },
  p_none = { ReadNone, WriteNone };

Status
ESM_protectionDelete(DbHandle const *dbh, Oid const *const oid)
{
  DbDescription *vd = dbh->vd;
  DbHeader _dbh(vd->dbs_addr);
  DbHeader *h = &_dbh;
  Status se;
  Oid *oid_array, *o;
  int i, j;
  size_t size; // V3_API_size_t

#undef PR
#define PR "protectionDelete: "
  if (!(vd->flags & VOLRW))
    return statusMake(WRITE_FORBIDDEN, PR WF, dbh->dbfile);

  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
  if ( !(se = ESM_objectSizeGet(dbh, &size, LockS, &prot_list_oid, OPDefault)) )
    {
      oid_array = (Oid *)m_malloc(size);
      if ( !(se = ESM_objectRead(dbh, 0, 0, oid_array, LockS, 0, 0,
				&prot_list_oid, OPDefault)) )
	{
	  Oid xoid;
	  h2x_oid(&xoid, oid);
	  for (o = oid_array, i = 0; i < vd->nprot_list; o++, i++)
	    if (!memcmp(o, &xoid, sizeof(Oid)))
	      {
		for (j = i; j < vd->nprot_list-1; j++, o++)
		  *o = *(o+1);

		if ( !( se = ESM_objectDelete(dbh, &prot_list_oid,
					     OPDefault)) )
		  {
		    if (--vd->nprot_list > 0)
		      ESM_objectCreate(dbh, oid_array, size-sizeof(Oid),
				      DefaultDspid, &prot_list_oid, OPDefault);
		    else
		      prot_list_oid.setUnique(0);
		    se = protectionRunTimeUpdate(dbh);
		  }
		free(oid_array);
		h2x_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
		return Success;
	      }
	  se = statusMake(PROTECTION_NOT_FOUND, PR "protection not found: '%s'", getOidString(oid));
	}
      free(oid_array);
    }

  return se;
}

Status
ESM_protectionCreate(DbHandle const *dbh,
		    ProtectionDescription const *desc,
		    Oid *oid)
{
  DbDescription *vd = dbh->vd;
  DbHeader _dbh(vd->dbs_addr);
  DbHeader *h = &_dbh;
  int i, j;
  size_t size = protectionDescriptionInternalSize(vd->nprot_uid); // V3_API_size_t
  DbProtectionDescription *u;
  ProtectionDescriptionInternal *dbi, **l;
  ProtectionAtom const *v;
  Status se;
  Oid roid;
  
#undef PR
#define PR "protectionCreate: "
  if (!(vd->flags & VOLRW))
    return statusMake(WRITE_FORBIDDEN, PR WF, dbh->dbfile);

  if (strlen(desc->name) >= sizeof(desc->name))
    return statusMake(PROT_NAME_TOO_LONG, PR "protection name is too long: '%s', maximum allowed is `%d'", desc->name, sizeof(desc->name));

  for (l = vd->vol_desc_list, i = 0; i < vd->nprot_list; l++, i++)
    if (!strcmp((*l)->name, desc->name))
      return statusMake(PROTECTION_DUPLICATE_NAME, PR "protection already exists: '%s'", desc->name);

  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
  if (se = ESM_objectLock(dbh, &prot_lock_oid,
			 (TransactionOP)(OWRITE | LOCKX),
			 NULL, NULL))
    return se;

  dbi = (ProtectionDescriptionInternal *)m_calloc(size, 1);

  for (v = desc->desc, i = 0; i < desc->nprot; i++, v++)
    {
      if ( (j = uidIndGet(dbh, v->uid)) == INVALID )
	{
	  free(dbi);
	  return statusMake(PROTECTION_INVALID_UID, PR "uid is not valid `%d'", v->uid);
	}
      else
	dbi->prot[j] = v->prot;
    }

  strcpy(dbi->name, desc->name);
  dbi->nprot = desc->nprot;

  if ( !(se = ESM_objectCreate(dbh, dbi, size, DefaultDspid, &roid, OPDefault)) )
    {
      if ( !(se = ESM_objectCreate(dbh, &roid, sizeof(Oid), DefaultDspid, oid, OPDefault)) )
	{
	  Oid *o;

	  se = ESM_objectSizeGet(dbh, &size, LockS, &prot_list_oid, OPDefault);
	  if (!se)
	    {
	      o = (Oid *)m_malloc(size + sizeof(Oid));
	      if ( (se = ESM_objectRead(dbh, 0, 0, o,
				       LockS, 0, 0,
				       &prot_list_oid, OPDefault)) /*||
							     (se = ESM_objectDelete(dbh, &h->prot_list_oid, OPDefault)) */)
		{
		  free(o);
		  return se;
		}
	    }
	  else
	    {
	      size = 0;
	      o = (Oid *)m_malloc(sizeof(Oid));
	    }

#ifdef ESM_DBG
	  printf("PROTLIST %d\n", vd->nprot_list);
#endif
	  o[vd->nprot_list] = *oid;

#ifdef ESM_DBG
	  printf("Create %d (%d %d)\n", size + sizeof(Oid), roid.ns,
		 roid.unique);
#endif

	  if (!prot_list_oid.getUnique())
	    se = ESM_objectCreate(dbh, o, size + sizeof(Oid), DefaultDspid,
				 &prot_list_oid, OPDefault);
	  else
	    {
	      se = ESM_objectSizeModify(dbh, size + sizeof(Oid),
				       True, &prot_list_oid,
				       OPDefault);
	      se = ESM_objectWrite(dbh, 0, size + sizeof(Oid), o,
				  &prot_list_oid, OPDefault);
	    }

	  free(o);
	  vd->nprot_list++;
	  if (!se)
	    h2x_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
	  return (!se ? protectionRunTimeUpdate(dbh) : se);
	}
    }

  return se;
}

Status
ESM_protectionModify(DbHandle const *dbh,
		    ProtectionDescription const *desc,
		    Oid const *oid)
{
  DbDescription *vd = dbh->vd;
  //  DbHeader *h = vd->dbs_addr;
  int i, j, size = protectionDescriptionInternalSize(vd->nprot_uid);
  DbProtectionDescription *u;
  ProtectionDescriptionInternal *dbi, **l;
  ProtectionAtom const *v;
  Status se;
  Oid roid, *o;
  
#undef PR
#define PR "protectionModify: "
  if (!(vd->flags & VOLRW))
    return statusMake(WRITE_FORBIDDEN, PR WF, dbh->dbfile);

  if (strlen(desc->name) >= sizeof(desc->name))
    return statusMake(PROT_NAME_TOO_LONG, PR "protection name is too long: '%s', maximum allowed is `%d'", desc->name, sizeof(desc->name));

  for (l = vd->vol_desc_list, o = vd->vol_prot_list_oid,
	 i = 0; i < vd->nprot_list; l++, i++, o++)
    if (!memcmp(oid, o, sizeof(Oid)))
      {
	dbi = (ProtectionDescriptionInternal *)m_calloc(size, 1);

	for (v = desc->desc, i = 0; i < desc->nprot; i++, v++)
	  {
	    if ( (j = uidIndGet(dbh, v->uid)) == INVALID )
	      {
		free(dbi);
		return statusMake_s(PROTECTION_INVALID_UID);
	      }
	    else
	      dbi->prot[j] = v->prot;
	  }

	strcpy(dbi->name, desc->name);
	dbi->nprot = desc->nprot;

	if (!(se = ESM_objectRead(dbh, 0, 0, &roid, LockS, 0, 0, oid, OPDefault)) &&
	    !(se = ESM_objectDelete(dbh, &roid, OPDefault)) &&
	    !(se = ESM_objectCreate(dbh, dbi, size, DefaultDspid, &roid, OPDefault)))
	  se = ESM_objectWrite(dbh, 0, 0, &roid, oid, OPDefault);

	free(dbi);
	return (!se ? protectionRunTimeUpdate(dbh) : se);
      }

  return statusMake_s(PROTECTION_NOT_FOUND);
}

Status
protectionGet_realize(DbHandle const *dbh,
			 ProtectionDescriptionInternal *src,
			 ProtectionDescription **desc)
{
  int nprot_uid = dbh->vd->nprot_uid;
  ProtectionDescription *dest;
  int j;

  dest = *desc = (ProtectionDescription *)
    m_calloc(protectionDescriptionSize(nprot_uid), 1);

  strcpy(dest->name, src->name);
  dest->nprot = nprot_uid;

  for (j = 0; j < nprot_uid; j++)
    {
      dest->desc[j].uid = indUidGet(dbh, j);
      dest->desc[j].prot = src->prot[j];
    }
  return Success;
}

Status
ESM_protectionGetByName(DbHandle const *dbh,
		       char const *name, ProtectionDescription **desc,
		       Oid *oid)
{
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;
  ProtectionDescriptionInternal **l;
  int i;
  Oid *o;

  for (l = vd->vol_desc_list, o = vd->vol_prot_list_oid,
	 i = 0; i < vd->nprot_list; l++, i++, o++)
    if (!strcmp((*l)->name, name))
      {
	*oid = *o;
	return protectionGet_realize(dbh, *l, desc);
      }

  return statusMake_s(PROTECTION_NOT_FOUND);
}

Status
ESM_protectionListGet(DbHandle const *dbh,
		     Oid **oid, ProtectionDescription ***desc,
		      unsigned int *nprot)
{
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;
  ProtectionDescriptionInternal **l;
  Oid *o;
  int i;

  *oid = (Oid *)m_calloc(sizeof(Oid) * vd->nprot_list, 1);
  *desc = (ProtectionDescription **)
    m_calloc(sizeof(ProtectionDescription *) * vd->nprot_list, 1);
  *nprot = vd->nprot_list;

  for (l = vd->vol_desc_list, o = vd->vol_prot_list_oid,
	 i = 0; i < vd->nprot_list; l++, i++, o++)
    {
      (*oid)[i] = *o;
      protectionGet_realize(dbh, *l, &((*desc)[i]));
    }

  return Success;
}

Status
ESM_protectionGetByOid(DbHandle const *dbh,
		      Oid const *oid,
		      ProtectionDescription **desc)
{
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;
  ProtectionDescriptionInternal **l;
  int i;
  Oid *o;

  for (l = vd->vol_desc_list, o = vd->vol_prot_list_oid,
	 i = 0; i < vd->nprot_list; l++, i++, o++)
    if (oidloc_cmp(oidLocGet(dbh, o), oidLocGet(dbh, oid)) &&
	o->getUnique() == oid->getUnique())
      return protectionGet_realize(dbh, *l, desc);

  return statusMake_s(PROTECTION_NOT_FOUND);
}

 Status
dbProtectionCheck(DbHandle const *dbh, int flag)
{
  DbHeader _dbh(DBSADDR(dbh));
  DbHeader *h = &_dbh;
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;
  Status se;
  int uid = getUid(0), i;
  DbProtectionDescription *u;

  if (vd->suser)
    return Success;

  vd->uid = uid;
  vd->uid_ind = uidIndGet(dbh, uid);

  if (vd->uid_ind == INVALID)
    {
      if (x2h_32(_dbh.__guest_uid()) == INVALID_UID)
	return statusMake_s(DATABASE_ACCESS_DENIED);
      else
	{
	  uid = x2h_32(_dbh.__guest_uid());
	  vd->uid = uid;
	  vd->uid_ind = uidIndGet(dbh, uid);
	}
    }

  for (u = vd->vol_uid, i = 0; i < vd->nprot_uid; i++, u++)
    if (u->uid == uid)
      {
	if (((flag & VOLREAD) && u->prot.r == ReadAll) ||
	    ((flag & VOLRW) && u->prot.r == ReadAll &&
	     u->prot.w == WriteAll))
	  return Success;
	else
	  break;
      }

  return statusMake_s(DATABASE_ACCESS_DENIED);
}

Status
protectionRunTimeUpdate(DbHandle const *dbh)
{
  DbDescription *vd = dbh->vd;
  DbHeader _dbh(DBSADDR(dbh));
  DbHeader *h = &_dbh;
  Status se;
  size_t size; // V3_API_size_t
  
  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);

  if (!(se = ESM_objectSizeGet(dbh, &size, LockS, &prot_list_oid, OPDefault)))
    {
      Oid *o;
      ProtectionDescriptionInternal **v;
      int i;
      Oid roid;
      Oid *vol_prot_list_oid;
      ProtectionDescriptionInternal **vol_desc_list;

      vol_prot_list_oid = (Oid *)m_malloc(size);
      if (se = ESM_objectRead(dbh, 0, 0, vol_prot_list_oid,
			     LockS, 0, 0, &prot_list_oid, OPDefault))
	return se;
	
      /*
	printf("SIZE %d, size/sizeof(Oid) %d, nprot_list %d\n",
	size, size/sizeof(Oid), vd->nprot_list);
	*/

      vd->nprot_list = size/sizeof(Oid);

      vol_desc_list = (ProtectionDescriptionInternal **)
	m_malloc(sizeof(ProtectionDescriptionInternal *) *
		 vd->nprot_list);
	
      for (o = vol_prot_list_oid, v = vol_desc_list,
	     i = 0; i < vd->nprot_list; o++, v++, i++)
	{
	  if (!(se = ESM_objectRead(dbh, 0, 0, &roid, LockS, 0, 0, o, OPDefault)))
	    {
	      *v = (ProtectionDescriptionInternal *)
		m_calloc(protectionDescriptionInternalSize(vd->nprot_uid), 1);
	      if (se = ESM_objectRead(dbh, 0, 0, *v, LockS, 0, 0, &roid, OPDefault))
		errorInit();
	      /*
		else
		printf("HAVE READ protection %s\n", (*v)->name);*/
	    }
	  else
	    return se;
	}
      
      if (vd->vol_prot_list_oid)
	free(vd->vol_prot_list_oid);
      if (vd->vol_desc_list)
	free(vd->vol_desc_list);
      
      vd->vol_prot_list_oid = vol_prot_list_oid;
      vd->vol_desc_list = vol_desc_list;
      
#ifdef DICO_ALG
      qsort(vd->vol_prot_list_oid, vd->nprot_list, sizeof(Oid),
	    oid_cmp);
#endif
    }
  //  h2x_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
  return Success;
}
	      
Status
dbProtectionRunTimeUpdate(DbHandle const *dbh)
{
  DbDescription *vd = dbh->vd;
  DbHeader _dbh(DBSADDR(dbh));
  DbHeader *h = &_dbh;
  Status se;
  size_t size; // V3_API_size_t
  
  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);

  if (!(se = ESM_objectSizeGet(dbh, &size, LockS, &prot_uid_oid,
			      OPDefault))) {
    if (!size) {
      free(vd->vol_uid);
      vd->nprot_uid = 0;
      vd->vol_uid = 0;
      return Success;
    }

    free(vd->vol_uid);
    vd->vol_uid = (DbProtectionDescription *)m_malloc(size);
    
    vd->nprot_uid = size/sizeof(Oid);
    
    ESM_objectRead(dbh, 0, 0, vd->vol_uid, LockS, 0, 0, &prot_uid_oid,
		  OPDefault);

#ifdef ESM_DBG
    printf("dbProtectionRunTimeUpdate'nprot_uid' %d\n", vd->nprot_uid);
    for (int i = 0; i < vd->nprot_uid; i++)
      printf("%d: %d %d %d\n", i, vd->vol_uid[i].uid,
	     vd->vol_uid[i].prot.r, vd->vol_uid[i].prot.w);
#endif
  }

  return se;
}
	      
Status
ESM_protectionsRunTimeUpdate(DbHandle const *dbh)
{
  Status s = dbProtectionRunTimeUpdate(dbh);
  if (s) return s;
  return protectionRunTimeUpdate(dbh);
}

Status
ESM_dbProtectionGet(DbHandle const *dbh,
		    DbProtectionDescription **desc, unsigned int *nprot)
{
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;
  unsigned int size = sizeof(DbProtectionDescription) * vd->nprot_uid;
  
  *nprot = vd->nprot_uid;
  *desc = (DbProtectionDescription *)m_malloc(size);

  memcpy(*desc, vd->vol_uid, size);
  return Success;
}

Status
ESM_dbProtectionAdd(DbHandle const *dbh,
		   DbProtectionDescription const *desc, int nprot)
{
  DbDescription *vd = dbh->vd;
  DbHeader _dbh(DBSADDR(dbh));
  DbHeader *h = &_dbh;
  Status se;
  DbProtectionDescription const *u, *v;
  int i, j, n;

  /*
    printf("ESM_dbProtectionAdd(Prot %s, %s)\n",
    getOidString(&h->prot_uid_oid),
    getOidString(&h->prot_list_oid));
    */

  if (!(vd->flags & VOLRW))
    return statusMake_s(WRITE_FORBIDDEN);

  for (u = desc, i = 0; i < nprot; i++, u++)
    for (v = u+1, j = i+1; j < nprot; j++, v++)
      if (v->uid == u->uid)
	return Success;
  
  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);

  if (se = ESM_objectLock(dbh, &prot_lock_oid,
			 (TransactionOP)(OWRITE | LOCKX),
			 NULL, NULL))
    return se;

  if (!prot_uid_oid.getUnique())
    {
      unsigned int size = sizeof(DbProtectionDescription) * nprot;
      if ( !(se = ESM_objectCreate(dbh, desc, size, DefaultDspid,
				  &prot_uid_oid, OPDefault)) )
	{
	  vd->nprot_uid = nprot;
	  free(vd->vol_uid);
	  if (!size)
	    vd->vol_uid = 0;
	  else
	    vd->vol_uid = (DbProtectionDescription *)m_malloc(size);
	  memcpy(vd->vol_uid, desc, size);
#ifdef BUG_2
	  protectionRunTimeUpdate(dbh);
#endif
	}

      h2x_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
#ifndef BUG_2
      protectionRunTimeUpdate(dbh);
#endif
      return se;
    }
  else
    {
      unsigned int size = sizeof(DbProtectionDescription) * (vd->nprot_uid + nprot);
      DbProtectionDescription *vol_uid =
	(DbProtectionDescription *)m_malloc(size), *v;

      memcpy(vol_uid, vd->vol_uid, sizeof(DbProtectionDescription) *
	     vd->nprot_uid);

      n = vd->nprot_uid;

      for (u = desc, i = 0; i < nprot; u++, i++)
	{
	  for (v = vol_uid, j = 0; j < vd->nprot_uid; v++, j++)
	    if (v->uid == u->uid)
	      {
		*v = *u;
		break;
	      }

	  if (j == vd->nprot_uid)
	    vol_uid[n++] = *u;
	}

      if (!(se = ESM_objectSizeModify(dbh, size, True, &prot_uid_oid, OPDefault)))
	{
	  if (!(se = ESM_objectWrite(dbh, 0, size, vol_uid, &prot_uid_oid,
				    OPDefault)))
	    {
	      //4/10/05
	      //free(vd->vol_uid);
	      vd->nprot_uid = n;
	      free(vd->vol_uid);
	      vd->vol_uid = vol_uid;
	    }
	}

      protectionRunTimeUpdate(dbh);
      return se;
    }
}

Status
ESM_dbProtectionDelete(DbHandle const *dbh,
		      int const *uid, int nuid)
{
  return statusMake_s(ERROR);
}

Status
protectionInit(DbHandle const *dbh)
{
  Status status;

  DbHeader _dbh(DBSADDR(dbh));
  DbHeader *h = &_dbh;
  Oid prot_lock_oid, prot_list_oid, prot_uid_oid;
  x2h_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);

  status = ESM_objectCreate(dbh, ObjectZero, 0, DefaultDspid,
			   &prot_uid_oid, OPDefault);
  if (status)
    return status;

  status = ESM_objectCreate(dbh, ObjectZero, 0, DefaultDspid,
			   &prot_list_oid, OPDefault);
  if (status)
    return status;

  status = ESM_objectCreate(dbh, ObjectZero, 0, DefaultDspid,
			   &prot_lock_oid, OPDefault);
  if (!status)
    h2x_protoids(&prot_lock_oid, &prot_list_oid, &prot_uid_oid, h);
  return status;
}

const Protection *
protGet(DbHandle const *dbh, Oid const *oid, int uid)
{
  DbDescription *vd = dbh->vd;
  if (vd->suser || !uid || !oid->getUnique()) /* adds !uid 20/08/97 */
    return &p_all;
  else
    {
      Oid *o;
      ProtectionDescriptionInternal **v;
      ProtectionAtom *u;
      //DbHeader *h = vd->dbs_addr;

      /*      printf("protGet(%s)\n", getOidString(oid)); */
      if (ESM_protectionsMustUpdate(dbh))
	{
	  printf("MUST update protections\n");
	  dbProtectionRunTimeUpdate(dbh);
	  protectionRunTimeUpdate(dbh);
	}

#ifdef DICO_ALG
      if (o = (Oid *)bsearch(oid, vd->vol_prot_list_oid, vd->nprot_list,
				sizeof(Oid), oid_cmp))
	return &vd->vol_desc_list[((int)o-(int)vd->vol_prot_list_oid) / 
				 sizeof(Oid)]->prot[j];
      return &p_none;
#else
      if (vd->vol_prot_list_oid && vd->vol_desc_list)
	{
          int i, j = uidIndGet(dbh, INVALID);
	  int cont = 0;
          if (j == INVALID)
            return &p_none;

	  for ( ; cont < 2; cont++)
	    {
	      for (o = vd->vol_prot_list_oid, v = vd->vol_desc_list,
		     i = 0; i < vd->nprot_list; o++, v++, i++)
		if (oidloc_cmp(oidLocGet(dbh, o), 
				  oidLocGet(dbh, oid)) &&
		    o->getUnique() == oid->getUnique())
		  return &(*v)->prot[j];

	      printf("TRIES TO update protections\n");
	      dbProtectionRunTimeUpdate(dbh);
	      protectionRunTimeUpdate(dbh);
	    }
	  
	  return &p_none;
	}
      else
	return &p_all;
#endif
    }
}

Status
ESM_guestUidSet(DbHandle *dbh, int uid)
{
  if (!(dbh->vd->flags & VOLRW))
    return statusMake_s(WRITE_FORBIDDEN);
  else if (uid != INVALID_UID && uidIndGet(dbh, uid) == INVALID)
    return statusMake_s(PROTECTION_INVALID_UID);
  else
    {
      DbHeader(DBSADDR(dbh)).__guest_uid() = h2x_32(uid);
      return Success;
    }
}

Status
ESM_guestUidGet(DbHandle const *dbh, int *uid)
{
  *uid = x2h_32(DbHeader(DBSADDR(dbh)).__guest_uid());
  return Success;
}

static int dbg_uid;

void
dbg_setuid(int uid)
{
  dbg_uid = uid;
}

int
getUid(DbHandle const *dbh)
{
  if (dbh)
    return dbh->vd->uid;
  else
    return (dbg_uid ? dbg_uid : getuid());
}

int
uidIndGet(DbHandle const *dbh, int uid)
{
  if (uid == INVALID)
    return dbh->vd->uid_ind;
  else
    {
      DbDescription *vd = dbh->vd;
      //DbHeader *h = vd->dbs_addr;

      DbProtectionDescription *u;
      int i;

      for (u = vd->vol_uid, i = 0; i < vd->nprot_uid; i++, u++)
	if (u->uid == uid)
	  return i;

      return INVALID;
    }
}

int
indUidGet(DbHandle const *dbh, int ind)
{
  DbDescription *vd = dbh->vd;
  //DbHeader *h = vd->dbs_addr;

  return vd->vol_uid[ind].uid;
}

Status
ESM_dbSetuid(DbHandle *dbh, int uid)
{
  if (dbh->vd->rsuser)
    {
      int uid_ind;
      if ( (uid_ind = uidIndGet(dbh, uid)) == INVALID )
	return statusMake_s(DATABASE_ACCESS_DENIED);
      else
	{
	  dbh->vd->uid     = uid;
	  dbh->vd->uid_ind = uid_ind;
	  dbh->vd->suser   = False;
	  return Success;
	}
    }
  else
    return statusMake_s(NO_SETUID_PRIVILEGE);
}

Status
ESM_suserUnset(DbHandle *dbh)
{
  dbh->vd->suser = False;
  return Success;
}

unsigned int
ESM_xidGet(DbHandle *dbh)
{
  return dbh->vd->xid;
}

void
ESM_uidSet(DbHandle *dbh, int uid)
{
  dbh->vd->uid = uid;
  dbh->vd->uid_ind = uidIndGet(dbh, uid);
}

int
ESM_uidGet(DbHandle *dbh)
{
  return dbh->vd->uid;
}

}
