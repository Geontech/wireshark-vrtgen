/*#
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
#*/
#include "ext.h"

/* Wireshark fields */
/*%- for field in module.fields %*/
static int {{field.var}} = -1;
/*%- endfor %*/

/* Wireshark protocol subtrees */
/*%- for tree in module.trees %*/
static int {{tree}} = -1;
/*%- endfor %*/

static void register_{{module.name}}(int proto)
{
    static hf_register_info hf[] = {
/*%- for field in module.fields %*/
        { &{{field.var}},
            { "{{field.name}}", "{{field.abbrev}}",
            {{field.type}}, {{field.base}},
            {{field.vals}}, 0x{{'%02x'|format(field.flags)}},
            NULL, HFILL }
        },
/*%- endfor %*/
    };

    static gint* ett[] = {
/*%- for tree in module.trees %*/
        &{{tree}},
/*%- endfor %*/
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
/*%- for struct in module.dissectors %*/

static int
dissect_{{struct.name}}(tvbuff_t *tvb, proto_tree *tree, int offset, guint encoding)
{
    proto_item *item;
    proto_tree *struct_tree;
    item = proto_tree_add_item(tree, {{struct.var}}, tvb, offset, {{struct.size}}, ENC_NA);
    struct_tree = proto_item_add_subtree(item, {{struct.tree}});

/*%- for field in struct.fields %*/
/*%-    if field.packed %*/
/*%-        set field_offset = 31 - field.bitoffset %*/
    proto_tree_add_bits_item(struct_tree, {{field.var}}, tvb, (offset*8) + {{field_offset}}, {{field.bits}}, encoding);
/*%-    elif field.fixed %*/
    ext_proto_tree_add_fixed(struct_tree, {{field.var}}, tvb, offset, {{field.size}}, {{field.radix}}, encoding);
/*%-    else %*/
    proto_tree_add_item(struct_tree, {{field.var}}, tvb, offset + {{field.offset}}, {{field.size}}, encoding);
/*%-    endif %*/
/*%- endfor %*/
    return {{struct.size}};
}
/*%- endfor %*/
/*%- for struct in module.structs %*/

typedef struct {
/*%-    for field in struct.fields %*/
    {{field.type}} {{field.attr}};
/*%-    endfor %*/
} {{struct.name}}_t;
/*%-    if struct.unpack %*/

static void unpack_{{struct.name}}(tvbuff_t *tvb, int offset, {{struct.name}}_t *{{struct.name}}, int encoding)
{
/*%-        for field in struct.fields %*/
/*%-            set field_offset = 31 - field.offset %*/
    {{struct.name}}->{{field.attr}} = tvb_get_bits(tvb, (offset*8) + {{field_offset}}, {{field.bits}}, encoding);
/*%-        endfor %*/
}
/*%-    endif %*/
/*%- endfor %*/
