#include "fixed.h"

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
/*%- for struct in module.dissectors if struct.struct %*/

static int
dissect_{{struct.attr}}(tvbuff_t *tvb, proto_tree *tree, int offset, guint encoding)
{
    proto_item *item;
    proto_tree *struct_tree;
/*%- for field in struct.fields if field.fixed %*/
    gint{{field.bits}} {{field.attr}}_val;
/*%- endfor %*/

    item = proto_tree_add_item(tree, {{struct.var}}, tvb, offset, {{struct.size}}, ENC_NA);
    struct_tree = proto_item_add_subtree(item, {{struct.tree}});

/*%- for field in struct.fields %*/
/*%-    if field.packed %*/
    proto_tree_add_bits_item(struct_tree, {{field.var}}, tvb, (offset*8) + {{field.bitoffset}}, {{field.bits}}, encoding);
/*%-    elif field.fixed %*/
    {{field.attr}}_val = get_int{{field.bits}}(tvb, {{field.offset}}, encoding);
    proto_tree_add_double(struct_tree, {{field.var}}, tvb, offset + {{field.offset}}, {{field.size}}, fixed_to_double({{field.attr}}_val, {{field.radix}}));
/*%-    else %*/
    proto_tree_add_item(struct_tree, {{field.var}}, tvb, offset + {{field.offset}}, {{field.size}}, encoding);
/*%-    endif %*/
/*%- endfor %*/
    return {{struct.size}};
}
/*%- endfor %*/