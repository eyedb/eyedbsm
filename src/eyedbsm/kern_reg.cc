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

#include <kern_p.h>

namespace eyedbsm {
Status
ESM_registerStart(DbHandle const *dbh, unsigned int reg_mask)
{
  dbh->vd->reg = (Register *)m_calloc(sizeof(Register), 1);
  dbh->vd->reg_alloc = 0;
  dbh->vd->reg_mask = reg_mask;
  return Success;
}

Status
ESM_registerClear(DbHandle const *dbh)
{
  unsigned int reg_mask = dbh->vd->reg_mask;
  Status s = registerEnd(dbh);
  if (s) return s;
  return registerStart(dbh, reg_mask);
}

Status
ESM_registerEnd(DbHandle const *dbh)
{
  if (dbh->vd->reg)
    {
      dbh->vd->reg_alloc = 0;

      free(dbh->vd->reg->entries);
      dbh->vd->reg->entries = 0;

      free(dbh->vd->reg);
      dbh->vd->reg = 0;
    }

  return Success;
}

Status
ESM_registerGet(DbHandle const *dbh, Register **reg)
{
  *reg = dbh->vd->reg;
  return Success;
}

static void ESM_addToRegister(DbHandle const *dbh, OP op, const Oid *oid, size_t create_size, size_t start_rw, size_t length_rw, size_t sizemod_size)
{
  if (!dbh->vd->reg)
    return;

  Register *reg = dbh->vd->reg;
  if (reg->oid_cnt >= dbh->vd->reg_alloc)
    {
      dbh->vd->reg_alloc += 1024;
      reg->entries = (RegisterEntry *)
	m_realloc(reg->entries,
		sizeof(RegisterEntry)*dbh->vd->reg_alloc);
    }

  RegisterEntry *entry = &reg->entries[reg->oid_cnt++];
  entry->op = op;
  entry->oid = *oid;
  entry->create_size = create_size;
  entry->start_rw = start_rw;
  entry->length_rw = length_rw;
  entry->sizemod_size = sizemod_size;
}

void
ESM_addToRegisterCreate(DbHandle const *dbh, const Oid *oid, size_t size)
{
  ESM_addToRegister(dbh, CreateOP, oid, size, 0, 0, 0);
}


void
ESM_addToRegisterRead(DbHandle const *dbh, const Oid *oid, size_t start, size_t length)
{
  ESM_addToRegister(dbh, ReadOP, oid, 0, start, length, 0);
}

void
ESM_addToRegisterWrite(DbHandle const *dbh, const Oid *oid, size_t start, size_t length)
{
  ESM_addToRegister(dbh, WriteOP, oid, 0, start, length, 0);
}

void
ESM_addToRegisterSizeMod(DbHandle const *dbh, const Oid *oid, size_t size)
{
  ESM_addToRegister(dbh, SizeModOP, oid, 0, 0, 0, size);
}

void
ESM_addToRegisterSizeGet(DbHandle const *dbh, const Oid *oid)
{
  ESM_addToRegister(dbh, SizeGetOP, oid, 0, 0, 0, 0);
}

void
ESM_addToRegisterDelete(DbHandle const *dbh, const Oid *oid)
{
  ESM_addToRegister(dbh, DeleteOP, oid, 0, 0, 0, 0);
}

void
ESM_addToRegisterLock(DbHandle const *dbh, const Oid *oid, OP lock)
{
  ESM_addToRegister(dbh, lock, oid, 0, 0, 0, 0);
}

//
// FRONTEND functions
//

const char *
getOPString(OP op)
{
  switch(op)
    {
    case CreateOP:
      return "CREATE";

    case ReadOP:
      return "READ";

    case WriteOP:
      return "WRITE";

    case DeleteOP:
      return "DELETE";

    case SizeModOP:
      return "SIZEMOD";

    case SizeGetOP:
      return "SIZEGET";

    case LockNOP:
      return "LOCKN";

    case LockSOP:
      return "LOCKS";

    case LockXOP:
      return "LOCKX";

    case LockSXOP:
      return "LOCKSX";

    case LockPOP:
      return "LOCKP";
    }

  return 0;
}

void
registerEntryTrace(FILE *fd, const RegisterEntry *entry)
{
  fprintf(fd, "%-25s %-10s ", getOidString(&entry->oid),
	  getOPString(entry->op));

  switch(entry->op)
    {
    case CreateOP:
      fprintf(fd, "size=%d", entry->create_size);
      break;

    case ReadOP:
    case WriteOP:
      fprintf(fd, "start=%d, length=%d",
	      entry->start_rw, entry->length_rw);
      break;

    case DeleteOP:
    case LockSOP:
    case LockNOP:
    case LockXOP:
    case LockSXOP:
    case LockPOP:
    case SizeGetOP:
      break;

    case SizeModOP:
      fprintf(fd, "size=%d", entry->sizemod_size);
      break;
    }

  fprintf(fd, "\n");
}

void
registerTrace(FILE *fd, const Register *reg)
{
  fprintf(fd, "Oid Count %d\n{\n", reg->oid_cnt);
  for (int i = 0; i < reg->oid_cnt; i++)
    {
      fprintf(fd, "\t");
      registerEntryTrace(fd, &reg->entries[i]);
    }
  fprintf(fd, "}\n");
}

}
