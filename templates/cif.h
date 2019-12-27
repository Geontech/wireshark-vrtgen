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
dissect_{{cif.name}}_enables(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, guint encoding)
{
    proto_item *item = proto_tree_add_item(tree, {{cif.enable_index}}, tvb, 0, 4, encoding);
    proto_tree *sub_tree = proto_item_add_subtree(item, ett_{{cif.name}});
/*%- for enable in cif.enables %*/
    proto_tree_add_bits_item(sub_tree, {{enable.var}}, tvb, {{enable.offset}}, 1, encoding);
    enables->{{enable.attr}} = tvb_get_bits(tvb, {{enable.offset}}, 1, encoding);
/*%- endfor %*/
}

static int
dissect_{{cif.name}}_fields(tvbuff_t *tvb, proto_tree *tree, {{cif.name}}_enables *enables, guint encoding)
{
    int offset = 0;
    proto_item *struct_item;
    proto_tree *struct_tree;
    tvbuff_t *struct_buf;
/*%- for field in cif.dissectors %*/
    if (enables->{{field.attr}}) {
/*%-    if field.struct %*/
        struct_buf = tvb_new_subset(tvb, offset, {{field.size}}, -1);
        struct_item = proto_tree_add_item(tree, {{field.var}}, tvb, offset, {{field.size}}, ENC_NA);
        struct_tree = proto_item_add_subtree(struct_item, {{field.tree}});
        offset += dissect_{{field.attr}}(struct_buf, struct_tree, encoding);
/*%-    else %*/
/*%-        if field.size < 4 %*/
        offset += {{4 - field.size}};
/*%-        endif %*/
/*%-        if field.fixed %*/
        gint{{field.bits}} val = get_int{{field.bits}}(tvb, offset, encoding);
        proto_tree_add_double(tree, {{field.var}}, tvb, offset, {{field.size}}, fixed_to_double(val, {{field.radix}}));
/*%-        else %*/
        proto_tree_add_item(tree, {{field.var}}, tvb, offset, {{field.size}}, encoding);
/*%-        endif %*/
        offset += {{field.size}};
/*%-    endif %*/
    }
/*%- endfor %*/
    return offset;
}

#endif
