/*
 * Copyright (C) 2019 Geon Technologies, LLC
 *
 * This file is part of wireshark-vrtgen.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PROLOGUE_H
#define PROLOGUE_H

/*% include "dissector.h" %*/

/*%- for struct in module.structs %*/

typedef struct {
/*%-    for field in struct.fields %*/
    {{field.type}} {{field.attr}};
/*%-    endfor %*/
} {{struct.name}}_t;
/*%-    if struct.unpack %*/

static void unpack_{{struct.name}}(tvbuff_t *tvb, int offset, {{struct.name}}_t *header, int encoding)
{
/*%-        for field in struct.fields %*/
    header->{{field.attr}} = tvb_get_bits(tvb, (offset*8) + {{field.offset}}, {{field.bits}}, encoding);
/*%-        endfor %*/
}
/*%-    endif %*/
/*%- endfor %*/

#endif
