
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

#define STDFMT " object size %d, obj #%d"

static void
write_objects(void *x)
{
  int n, i;
  int sz;
  char rdata[4096], *data;

  n = 0;
  data = o_make_data_1(sz, o_count, n);
  assert (sz < sizeof rdata);
  for (n = 0; n < o_count; n++)
    {
      int pn = o_GETN(n);
      unsigned int size;
      o_wait("before getting size of", pn);
	
      assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &size, o_read_lock, &o_oids[pn]),
	     "%s: reading size" STDFMT, o_progname, pn));


      o_wait("before writing", pn);

      if (o_verbose)
	printf("writing %s: %d bytes\n", o_getOidString(&o_oids[pn]), size);

      assert(!eyedbsm::statusPrint(eyedbsm::objectWrite(o_dbh, 0, size, data,
					    &o_oids[pn]),
			     "%s: creating" STDFMT, o_progname, pn));

      /*
      if (!n)
	printf("STARTING @%d\n", pthread_self());
      */
      /*
      void *xdata = 0;
      assert (!eyedbsm::statusPrint(eyedbsm::objectReadCache(o_dbh, 0, &xdata, eyedbsm::LockS,
						 &o_oids[pn]),
			      "%s: reading cached object", o_progname));

      if (xdata)
	assert(!memcmp(xdata, data, sz));

      assert(!eyedbsm::statusPrint(eyedbsm::objectRead(o_dbh, 0, sz, rdata, eyedbsm::LockS,
					   0, 0, &o_oids[pn]),
			     "%s: creating" STDFMT, o_progname, pn));
      assert(!memcmp(rdata, data, sz));
      */
    }
  //printf("ENDING @%d\n", pthread_self());
  free(data);
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(write_objects, 0);

  if (o_trsend())
    return 1;

  return o_release();
}

