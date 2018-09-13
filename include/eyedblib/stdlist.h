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


#ifndef _EYEDBLIB_STDLIST_H
#define _EYEDBLIB_STDLIST_H

#include <algorithm>
#include <list>

template <class T>
bool std_list_contains(std::list<T> &l, T o)
{
  return std::find(l.begin(), l.end(), o) != l.end();
}

template <class T>
bool std_list_erase(std::list<T> &l, T o)
{
  typename std::list<T>::iterator it = std::find(l.begin(), l.end(), o);

  if (it != l.end()) {
    l.erase(it);
    return true;
  }    
  return false;
}

#endif
