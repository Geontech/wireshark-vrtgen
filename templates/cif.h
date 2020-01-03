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

/*% set guard = module.name.upper() + '_H' -%*/
#ifndef {{guard}}
#define {{guard}}

/*% include "dissector.h" %*/

static int
dissect_{{module.name}}_fields(tvbuff_t *tvb, proto_tree *tree, {{module.name}}_enables_t *enables, int offset, guint encoding)
{
    int start = offset;
/*%- for field in cifs if field.fixed %*/
    gint{{field.bits}} {{field.attr}}_val;
/*%- endfor %*/
/*%- for field in cifs %*/
    if (enables->{{field.attr}}) {
/*%-    if field.dissector %*/
        offset += {{field.dissector}}(tvb, tree, offset, encoding);
/*%-    else %*/
/*%-        if field.size < 4 %*/
        offset += {{4 - field.size}};
/*%-        endif %*/
/*%-        if field.fixed %*/
        {{field.attr}}_val = get_int{{field.bits}}(tvb, offset, encoding);
        proto_tree_add_double(tree, {{field.var}}, tvb, offset, {{field.size}}, fixed_to_double({{field.attr}}_val, {{field.radix}}));
/*%-        else %*/
        proto_tree_add_item(tree, {{field.var}}, tvb, offset, {{field.size}}, encoding);
/*%-        endif %*/
        offset += {{field.size}};
/*%-    endif %*/
    }
/*%- endfor %*/
    return offset - start;
}

#endif
