
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
#include <stdlib.h>

#define STDFMT " object size %d, obj #%d"

static void
chsize_objects(void *x)
{
  int n, i;
  unsigned int sz;
  char rdata[4096], *data;

/*#define NJ 10*/
#define NJ 1
#define NINC 16
  for (n = 0; n < o_count; n++)
    {
      int pn = o_GETN(n);
      unsigned int nsz;
      int j;
      char *sdata, *idata;
      assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &sz, o_read_lock, &o_oids[pn]),
	     "%s: reading size" STDFMT, o_progname, pn));
      
      o_wait("before reading 1", pn);

      if (o_verbose)
	printf("reading %s: %d bytes\n", o_getOidString(&o_oids[pn]), sz);

      idata = (char *)malloc(sz);
      sdata = (char *)malloc(sz + NINC * (NJ+1));
      assert(!eyedbsm::statusPrint(eyedbsm::objectRead(o_dbh, 0, 0, idata, o_read_lock, 0,
					   0, &o_oids[pn]),
			     "%s: reading object" STDFMT, o_progname, pn));

      for (nsz = sz + NINC, j = 0; j < NJ; nsz += NINC, j++)
	{
	  unsigned int tsz;
	  assert(nsz >= 0);
	  o_wait("before reading 2", pn);
	  assert(!eyedbsm::statusPrint(eyedbsm::objectRead(o_dbh, 0, 0, sdata,
					       o_read_lock, 0, 0, &o_oids[pn]),
				 "%s: reading object" STDFMT, o_progname, pn));
	  assert(!memcmp(idata, sdata, sz));

	  if (o_verbose)
	    printf("modifying size %s: %d -> %d bytes\n",
		   o_getOidString(&o_oids[pn]), nsz-NINC, nsz);

	  o_wait("before size modify", pn);
	  assert(!eyedbsm::statusPrint(eyedbsm::objectSizeModify(o_dbh, nsz, eyedbsm::True, &o_oids[pn]),
				 "%s: size modify" STDFMT, o_progname, pn));

	  o_wait("before reading 3", pn);
	  assert(!eyedbsm::statusPrint(eyedbsm::objectRead(o_dbh, 0, 0, sdata,
					       o_read_lock, 0, 0, &o_oids[pn]),
				 "%s: reading object" STDFMT, o_progname, pn));
	  assert(!memcmp(idata, sdata, sz));

	  assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &tsz, o_read_lock, &o_oids[pn]),
				 "%s: reading size" STDFMT, o_progname, pn));

	  assert(nsz == tsz);
	  assert(!eyedbsm::statusPrint(eyedbsm::objectSizeGet(o_dbh, &tsz, o_read_lock, &o_oids[pn]),
				 "%s: reading size" STDFMT, o_progname, pn));
	  assert(nsz == tsz);
	}

      free(sdata);
      free(idata);
    }
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read))
    return 1;

  if (o_trsbegin())
    return 1;

  o_bench(chsize_objects, 0);

  if (o_trsend())
    return 1;

  return o_release();
}

