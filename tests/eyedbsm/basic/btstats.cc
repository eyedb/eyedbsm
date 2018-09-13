
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
//#include <eyedb/lib/bstring.h>

static int
usage()
{
  o_usage(eyedbsm::False);
  fprintf(stderr, "-struct|-string\n");
  return 1;
}

static unsigned int count;
static eyedbsm::Boolean structStats = eyedbsm::False;
static eyedbsm::Boolean stringStats = eyedbsm::False;
static eyedbsm::Boolean fullStats = eyedbsm::False;

static void
stats_btree(void *x)
{
  printf("Reading btree index %s\n", o_getOidString(&o_oids[0]));
  eyedbsm::BIdx bidx(o_dbh, o_oids[0]);
  eyedbsm::Status s = bidx.status();
  if (s) {
    eyedbsm::statusPrint(s, "reading btree index");
    return;
  }

  if (stringStats) {
    std::string str;
    s = bidx.getStats(str);
    if (s) {
      eyedbsm::statusPrint(s, "getting hash stats");
      return;
    }
    printf(str.c_str());
  }

  if (structStats) {
    eyedbsm::BIdx::Stats stats;
    s = bidx.getStats(stats);
    if (s) {
      eyedbsm::statusPrint(s, "getting hash stats");
      return;
    }
    
    stats.trace();
  }
}

int
main(int argc, char *argv[])
{
  if (o_init(argc, argv, o_Read, usage))
    return 1;

  for (int i = 0; i < argc; i++) {
    char *s = argv[i];
    if (!strcmp(s, "-string"))
      stringStats = eyedbsm::True;
    else if (!strcmp(s, "-struct"))
      structStats = eyedbsm::True;
    else
      return usage();
  }

  if (!stringStats && !structStats)
    return usage();

  if (o_trsbegin())
    return 1;

  o_bench(stats_btree, 0);

  if (o_trsend())
    return 1;

  return o_release();
}
