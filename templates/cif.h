/*%- set guard = cif.name.upper() + '_H' -%*/
#ifndef {{guard}}
#define {{guard}}

/*% include "dissector.h" %*/

typedef struct {
/*%- for enable in cif.enables %*/
    int {{enable.attr}};
/*%- endfor %*/
} {{cif.name}}_enables;

static void
dissect_{{cif.name}}_enables(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, int offset, guint encoding)
{
    proto_item *item = proto_tree_add_item(tree, {{cif.enable_index}}, tvb, 0, 4, encoding);
    proto_tree *sub_tree = proto_item_add_subtree(item, {{cif.tree_index}});
/*%- for enable in cif.enables %*/
    proto_tree_add_bits_item(sub_tree, {{enable.var}}, tvb, (offset*8)+{{enable.offset}}, 1, encoding);
    enables->{{enable.attr}} = tvb_get_bits(tvb, (offset*8)+{{enable.offset}}, 1, encoding);
/*%- endfor %*/
}

static int
dissect_{{cif.name}}_fields(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, int offset, guint encoding)
{
    int start = offset;
/*%- for field in cif.dissectors if field.fixed %*/
    gint{{field.bits}} {{field.attr}}_val;
/*%- endfor %*/
/*%- for field in cif.dissectors %*/
    if (enables->{{field.attr}}) {
/*%-    if field.struct %*/
        offset += dissect_{{field.attr}}(tvb, tree, offset, encoding);
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
