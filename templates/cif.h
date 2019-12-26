/*%- set guard = cif.name.upper() + '_H' -%*/
#ifndef {{guard}}
#define {{guard}}

#include "fixed.h"

/* Wireshark fields */
static int hf_{{cif.name}}_enables = -1;
/*%- for field in cif.fields %*/
static int {{field.var}} = -1;
/*%- endfor %*/

static int ett_{{cif.name}} = -1;
/*%- for tree in cif.trees %*/
static int {{tree}} = -1;
/*%- endfor %*/

typedef struct {
/*%- for enable in cif.enables %*/
    int {{enable.attr}};
/*%- endfor %*/
} {{cif.name}}_enables;

static void register_{{cif.name}}(int proto)
{
   static hf_register_info hf[] = {
        { &hf_{{cif.name}}_enables,
            { "CIF 0", "{{package}}.{{cif.name}}",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
/*%- for field in cif.fields %*/
        { &{{field.var}},
            { "{{field.name}}", "{{package}}.{{field.abbrev}}",
            {{field.type}}, {{field.base}},
            NULL, 0x00,
            NULL, HFILL }
        },
/*%- endfor %*/
    };

    static gint* ett[] = {
        &ett_{{cif.name}},
/*%- for tree in cif.trees %*/
        &{{tree}},
/*%- endfor %*/
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
dissect_{{cif.name}}_enables(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, guint encoding)
{
    proto_item *item = proto_tree_add_item(tree, hf_{{cif.name}}_enables, tvb, 0, 4, encoding);
    proto_tree *sub_tree = proto_item_add_subtree(item, ett_{{cif.name}});
/*%- for enable in cif.enables %*/
    proto_tree_add_bits_item(sub_tree, {{enable.var}}, tvb, {{enable.offset}}, 1, encoding);
    enables->{{enable.attr}} = tvb_get_bits(tvb, {{enable.offset}}, 1, encoding);
/*%- endfor %*/
}
/*%- for struct in cif.dissectors if struct.struct %*/

static int
dissect_{{struct.attr}}(tvbuff_t *tvb, proto_tree *tree, guint encoding)
{
/*%- for field in struct.fields %*/
/*%-    if field.packed %*/
    proto_tree_add_bits_item(tree, {{field.var}}, tvb, {{field.bitoffset}}, {{field.bits}}, encoding);
/*%-    elif field.fixed %*/
    {
        gint{{field.bits}} val = get_int{{field.bits}}(tvb, {{field.offset}}, encoding);
        proto_tree_add_double(tree, {{field.var}}, tvb, {{field.offset}}, {{field.size}}, fixed_to_double(val, {{field.radix}}));
    }
/*%-    else %*/
    proto_tree_add_item(tree, {{field.var}}, tvb, {{field.offset}}, {{field.size}}, encoding);
/*%-    endif %*/
/*%- endfor %*/
    return {{struct.size}};
}
/*%- endfor %*/

static int
dissect_{{cif.name}}_fields(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, guint encoding)
{
    int offset = 0;
    proto_item *struct_item;
    proto_tree *struct_tree;
    tvbuff_t *struct_buf;
/*%- for field in cif.dissectors %*/
    if (enables->{{field.attr}}) {
/*%-    if field.size < 4 %*/
        offset += {{4 - field.size}};
/*%-    endif %*/
/*%-    if field.struct %*/
        struct_buf = tvb_new_subset(tvb, offset, {{field.size}}, -1);
        struct_item = proto_tree_add_item(tree, {{field.var}}, tvb, offset, {{field.size}}, ENC_NA);
        struct_tree = proto_item_add_subtree(struct_item, {{field.tree}});
        dissect_{{field.attr}}(struct_buf, struct_tree, encoding);
/*%-    elif field.fixed %*/
        gint{{field.bits}} val = get_int{{field.bits}}(tvb, offset, encoding);
        proto_tree_add_double(tree, {{field.var}}, tvb, offset, {{field.size}}, fixed_to_double(val, {{field.radix}}));
/*%-    else %*/
        proto_tree_add_item(tree, {{field.var}}, tvb, offset, {{field.size}}, encoding);
/*%-    endif %*/
        offset += {{field.size}};
    }
/*%- endfor %*/
    return offset;
}

#endif /* {{guard}} */
