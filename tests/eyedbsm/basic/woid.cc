
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


#include "olib.h"

static int usage(const char *prog)
{
  fprintf(stderr, "usage: %s <oid> <file>\n", prog);
  return 1;
}

int
main(int argc, char *argv[])
{
  if (argc != 3) {
    return usage(argv[0]);
  }

  o_oidfile = argv[2];
  unsigned int nx, dbid, unique;
  if (sscanf(argv[1], "%u.%u.%u:oid", &nx, &dbid, &unique) != 3) {
    return usage(argv[0]);
  }

  o_fileopen(o_Create);

  eyedbsm::Oid oid;
  oid.setNX(nx);
  oid.setDbID(dbid);
  oid.setUnique(unique);

  o_write_oids(&oid, 1);

  return 0;
}
