/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2008 SYSRA
   
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


#ifndef _EYEDBLIB_STRUTILS_H
#define _EYEDBLIB_STRUTILS_H

#include <string>

std::string str_convert(char, const char *fmt = "%c");
std::string str_convert(int, const char *fmt = "%d");
std::string str_convert(unsigned int, const char *fmt = "%u");
std::string str_convert(short, const char *fmt = "%d");
std::string str_convert(long, const char *fmt = "%ld");
std::string str_convert(long long, const char *fmt = "%lld");
//std::string str_convert(unsigned long, const char *fmt = "%lud");
//std::string str_convert(unsigned long long, const char *fmt = "%llud");
std::string str_convert(double, const char *fmt = "%f");
std::string str_convert(size_t);

#endif
