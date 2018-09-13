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

#include <stdio.h>
#include <eyedblib/strutils.h>
#include <sstream>

std::string str_convert(char c, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, c);
  return tok;
}

std::string str_convert(int l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

std::string str_convert(unsigned int l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

std::string str_convert(short l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

std::string str_convert(long l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

std::string str_convert(long long l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

/*
std::string str_convert(unsigned long l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}

std::string str_convert(unsigned long long l, const char *fmt)
{
  char tok[64];
  sprintf(tok, fmt, l);
  return tok;
}
*/

std::string str_convert(double d, const char *fmt)
{
  char tok[512];
  sprintf(tok, fmt, d);
  return tok;
}

std::string str_convert(size_t s)
{
  std::ostringstream ostr;
  ostr << s;
  return ostr.str();
}

