/*
* Copyright (C) 2006,2012 Loic Pefferkorn <loic-pppoesk@loicp.eu>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; version 2 of the License.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef PPPOE_H
#define PPPOE_H

struct pppoe_hdr
{
    unsigned int version : 4;
    unsigned int type : 4;
    unsigned int code : 8;
    unsigned int sid : 16;
    unsigned int length : 16;
    unsigned int payload : 16;
} __attribute ((packed));



#endif
