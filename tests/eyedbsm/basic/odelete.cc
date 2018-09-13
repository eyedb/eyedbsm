
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

#define STDFMT " object size %d, data `%s', size %d"

static void
delete_objects(void *x)
{
  int n;

  for (n = 0; n < o_count; n++)
    {
      int pn = o_GETN(n);
      unsigned int sz;
      assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &sz, o_read_lock, &o_oids[pn]),
	     "%s: reading size", o_progname));

      o_wait("before deleting", pn);

      if (o_verbose)
	printf("deleting %s: %d bytes\n", o_getOidString(&o_oids[pn]), sz);

      assert(!eyedbsm::statusPrint(eyedbsm::objectDelete(o_dbh, &o_oids[pn]),
			     "%s: deleting object", o_progname));

    }
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(delete_objects, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
