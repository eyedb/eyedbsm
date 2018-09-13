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

#include "eyedbsmconfig.h"

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <eyedblib/machtypes.h>
#include <eyedblib/butils.h>
#include <eyedblib/thread.h>

#define IS_INT(c) (c == 'D' || c == 'I' || c == 'O' || c == 'X')

#define NBUFS 8

namespace eyedblib {
  static Mutex mt;
}

namespace eyedblib {
  char *
  getFBuffer(const char *fmt, va_list ap)
  {
    static int argstr_alloc;
    static enum Type {INT, LONG, STR} *argstr;
    static int buffer_which;
    static int buffer_len[NBUFS];
    static char *buffer[NBUFS];

    MutexLocker _(mt);
    int n;
    int argstr_cnt = 0;
    int argint_cnt = 0;
    int arg_cnt = 0;
    unsigned int len = 0;

    unsigned int len_1 = strlen(fmt);
    for (; ;fmt++)
      {
	char c = *fmt;
	char num[32];
	char *pnum;
	int is_long;

	if (!c)
	  break;

	if (c != '%')
	  {
	    len++;
	    continue;
	  }

	is_long = 0;
	pnum = num;
	while (c = *++fmt)
	  {
	    if (!c)
	      break;
	  
	    if (c >= '0' && c <= '9')
	      {
		*pnum++ = c;
		continue;
	      }

	    if (c == 'l')
	      {
		is_long++;
		continue;
	      }

	    c = (c >= 'a' && c <= 'z' ? c + 'A'-'a' : c);

	    if (IS_INT(c) || c == 'U' || c == 'E' || c == 'G' || c == 'C')
	      {
		if (c == 'U' && (IS_INT(*(fmt+1)) || *(fmt+1) == 'l'))
		  continue;

		if (arg_cnt >= argstr_alloc)
		  {
		    argstr_alloc = arg_cnt + 12;
		    argstr = (enum Type *)
		      realloc(argstr, sizeof(enum Type)*argstr_alloc);
		  }

		if (is_long > 1)
		  {
		    argstr[arg_cnt++] = LONG;
		    argint_cnt++;
		  }
		else
		  argstr[arg_cnt++] = INT;

		argint_cnt++;
		break;
	      }

	    if (c == 'S')
	      {
		if (arg_cnt >= argstr_alloc)
		  {
		    argstr_alloc = arg_cnt + 12;
		    argstr = (enum Type *)
		      realloc(argstr, sizeof(enum Type)*argstr_alloc);
		  }

		argstr[arg_cnt++] = STR;
		argstr_cnt++;
		break;
	      }
	  
	    if (c == '%')
	      {
		len++;
		break;
	      }

	    /* and what about float and double!!!!!! */
	    /* len += 512; */

	    /* unknown format sequence !? */
	    len += 2;
	    break;
	  }

	if (pnum != num)
	  {
	    *pnum = 0;
	    len += atoi(num);
	  }
      }

    len += argint_cnt * 20;

    for (n = 0; n < arg_cnt; n++)
      {
	if (argstr[n] == STR)
	  len += strlen(va_arg(ap, char *));
	else if (argstr[n] == LONG)
	  (void)va_arg(ap, long long);
	else
	  (void)va_arg(ap, int);
      }

    if (buffer_which >= NBUFS)
      buffer_which = 0;

    if (len+1 >= buffer_len[buffer_which])
      {
	free(buffer[buffer_which]);
	buffer_len[buffer_which] = len + 128 + 1024; // test
	buffer[buffer_which] = (char *)malloc(buffer_len[buffer_which]);
      }

    return buffer[buffer_which++];
  }

  void display_time(const char *fmt, ...)
  {
    va_list ap;
    struct timeval tp;

    gettimeofday(&tp, NULL);

#ifdef HAVE_UNSIGNED_LONG_LONG
    unsigned long long ms = (unsigned long long)tp.tv_sec * 1000 + tp.tv_usec/1000;
#endif

    va_start(ap, fmt);

    vfprintf(stdout, fmt, ap);
    fprintf(stdout, ": %lld ms\n", ms);
    va_end(ap);
  }

  int
  is_number(const char *s)
  {
    char c;
    if (!*s)
      return 0;
  
    while (c = *s++)
      if (!(c >= '0' && c <= '9'))
	return 0;

    return 1;
  }

#define USEC_PER_SECOND 1000000
#define USEC_PER_MS        1000

  const char *setbuftime(eyedblib::int64 t)
  {
#define NT 4
    static char buftim[NT][64];
    static int nt;
    char *ds;

    time_t sec = t / USEC_PER_SECOND;
    eyedblib::int64 usec = t % USEC_PER_SECOND;
    const char *s = ctime(&sec);

    if (nt == NT)
      nt = 0;

    ds = buftim[nt++];
    strcpy(ds, s);
    ds[strlen(ds)-1] = 0;

    char buf[64];
    sprintf(buf, " %03d.%03dms", (int)(usec / USEC_PER_MS),
	    (int)(usec % USEC_PER_MS));
    strcat(ds, buf);

    return ds;
  }
}
