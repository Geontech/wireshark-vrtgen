/*%- set guard = name.upper() + '_H' -%*/
#ifndef {{guard}}
#define {{guard}}

/* Wireshark fields */
static int hf_{{name}}_enables = -1;
/*%- for field in fields %*/
static int hf_{{name}}_enables_{{field.attr}} = -1;
/*%- endfor %*/

static int ett_{{name}} = -1;

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
        { &hf_{{name}}_enables_{{field.attr}},
            { "{{field.name}}", "v49d2.{{name}}.{{field.attr}}_en",
            FT_BOOLEAN, BASE_NONE,
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
dissect_{{name}}_enables(tvbuff_t *tvb, proto_tree *tree, guint encoding)
{
    proto_item *item = proto_tree_add_item(tree, hf_{{name}}_enables, tvb, 0, 4, encoding);
    proto_tree *sub_tree = proto_item_add_subtree(item, ett_{{name}});
/*%- for field in fields %*/
    proto_tree_add_bits_item(sub_tree, hf_{{name}}_enables_{{field.attr}}, tvb, {{31 - field.offset}}, 1, encoding);
/*%- endfor %*/
}

#endif /* {{guard}} */
