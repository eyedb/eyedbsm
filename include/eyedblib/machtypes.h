
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


#ifndef _EYEDBLIB_MACHTYPES_H
#define _EYEDBLIB_MACHTYPES_H

namespace eyedblib {

  /**
     @addtogroup eyedblib
     @{
  */

  typedef char               int8;
  typedef int                int32;
  typedef short              int16;
  typedef long long          int64;

  typedef unsigned char      uchar;
  typedef unsigned char      uint8;
  typedef unsigned int       uint32;
  typedef unsigned short     uint16;
  typedef unsigned long long uint64;

  typedef float              float32;
  typedef double             float64;

  /**
     @}
  */
}

#endif
