
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

//#define PARALLEL

static void
create_objects(void *x)
{
  int n;

#ifdef PARALLEL
  int len = 100;
  char *data = o_make_data_0(len, o_count, 0);
  int sz = strlen(data)+1;
#endif
  for (n = 0; n < o_count; n++)
    {
#ifndef PARALLEL
      int len = n+100;
      char *data = o_make_data_0(len, o_count, n);
      int sz = strlen(data)+1;
#endif

      o_wait("before creating", n);

      assert(!eyedbsm::statusPrint(eyedbsm::objectCreate(o_dbh, data, sz, o_dspid,
					     &o_oids[n]),
			     "%s: creating" STDFMT, o_progname, n, data,
			     sz));
      if (o_verbose)
	printf("creating %s: %d bytes\n", o_getOidString(&o_oids[n]), sz);
#ifndef PARALLEL
      free(data);
#endif
    }
#ifdef PARALLEL
  free(data);
#endif
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Create))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(create_objects, 0);

  if (o_trsend())
    return 1;

  o_write_oids(o_oids, o_count);

  return o_release();
}

