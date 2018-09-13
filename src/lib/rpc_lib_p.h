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

#if defined(HAVE_STRUCT_IN_ADDR_S_ADDR)
#define RPC_BYTE1(addr) (addr->s_addr >> 24)
#define RPC_BYTE2(addr) ((addr->s_addr >> 16) & 0xff)
#define RPC_BYTE3(addr) ((addr->s_addr >> 8) & 0xff)
#define RPC_BYTE4(addr) (addr->s_addr & 0xff)
#elif defined(HAVE_STRUCT_IN_ADDR__S_UN)
#define RPC_BYTE1(addr) (addr->_S_un._S_un_b.s_b1)
#define RPC_BYTE2(addr) (addr->_S_un._S_un_b.s_b2)
#define RPC_BYTE3(addr) (addr->_S_un._S_un_b.s_b3)
#define RPC_BYTE4(addr) (addr->_S_un._S_un_b.s_b4)
#endif

