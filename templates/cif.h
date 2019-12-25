/*%- set guard = name.upper() + '_H' -%*/
#ifndef {{guard}}
#define {{guard}}

#include "fixed.h"

/* Wireshark fields */
static int hf_{{name}}_enables = -1;
/*%- for field in fields %*/
static int {{field.var}} = -1;
/*%- endfor %*/

static int ett_{{name}} = -1;

typedef struct {
/*%- for enable in enables %*/
    int {{enable.attr}};
/*%- endfor %*/
} {{name}}_enables;

static void register_{{name}}(int proto)
{
   static hf_register_info hf[] = {
        { &hf_{{name}}_enables,
            { "CIF 0", "v49d2.{{name}}",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
/*%- for field in fields %*/
        { &{{field.var}},
            { "{{field.name}}", "v49d2.{{name}}.{{field.abbrev}}",
            {{field.type}}, {{field.base}},
            NULL, 0x00,
            NULL, HFILL }
        },
/*%- endfor %*/
    };

    static gint* ett[] = {
        &ett_{{name}},
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
dissect_{{name}}_enables(tvbuff_t *tvb, proto_tree *tree, {{name}}_enables *enables, guint encoding)
{
    proto_item *item = proto_tree_add_item(tree, hf_{{name}}_enables, tvb, 0, 4, encoding);
    proto_tree *sub_tree = proto_item_add_subtree(item, ett_{{name}});
/*%- for enable in enables %*/
    proto_tree_add_bits_item(sub_tree, {{enable.var}}, tvb, {{enable.offset}}, 1, encoding);
    enables->{{enable.attr}} = tvb_get_bits(tvb, {{enable.offset}}, 1, encoding);
/*%- endfor %*/
}

static int
dissect_{{name}}_fields(tvbuff_t *tvb, proto_tree *tree, {{name}}_enables *enables, guint encoding)
{
    int offset = 0;
/*%- for field in dissectors %*/
    if (enables->{{field.attr}}) {
/*%-    if field.size < 4 %*/
        offset += {{4 - field.size}};
/*%-    endif %*/
/*%-    if field.struct %*/
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
