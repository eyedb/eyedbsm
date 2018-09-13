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


#ifndef _EYEDBSM_SMD_H
#define _EYEDBSM_SMD_H

#define SMD_INIT         0x100
#define SMD_INIT_GETSEMS 0x102
#define SMD_RELEASE      0x104
#define SMD_DECL         0x106
#define SMD_UNDECL       0x107
#define SMD_STOP         0x108
#define SMD_STATUS       0x109

struct smdcli_conn_t {
  int sock_fd;
};

extern smdcli_conn_t *smdcli_open(const char *port);
extern void smdcli_close(smdcli_conn_t *conn);

extern int smdcli_init(smdcli_conn_t *conn, const char *dbfile);
extern int smdcli_init_getsems(smdcli_conn_t *conn, const char *dbfile, int sm[]);
extern int smdcli_release(smdcli_conn_t *conn, const char *dbfile);
extern int smdcli_declare(smdcli_conn_t *conn);
extern int smdcli_undeclare(smdcli_conn_t *conn);
extern int smdcli_status(smdcli_conn_t *conn);
extern int smdcli_stop(smdcli_conn_t *conn);
extern const char *smd_get_port();
extern void smd_set_port(const char *);

#endif
