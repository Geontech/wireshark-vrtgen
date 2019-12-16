#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_symbol_export.h>

typedef enum {
    SIGNAL_DATA = 0x0,
    SIGNAL_DATA_STREAM_ID = 0x1,
    EXTENSION_DATA = 0x2,
    EXTENSION_DATA_STREAM_ID = 0x3,
    CONTEXT = 0x4,
    EXTENSION_CONTEXT = 0x5,
    COMMAND = 0x6,
    EXTENSION_COMMAND = 0x7,
    RESERVED_8 = 0x8,
    RESERVED_9 = 0x9,
    RESERVED_10 = 0xa,
    RESERVED_11 = 0xb,
    RESERVED_12 = 0xc,
    RESERVED_13 = 0xd,
    RESERVED_14 = 0xe,
    RESERVED_15 = 0xf
} packet_type_e;

const gchar plugin_version[] = VERSION;

static int proto_vrtgen = -1;

static int hf_v49d2_header = -1;
static int hf_v49d2_sid = -1;

static gint ett_v49d2 = -1;

static const value_string packet_types[] = {
    {SIGNAL_DATA, "Signal data packet without stream ID"},
    {SIGNAL_DATA_STREAM_ID, "Signal data packet with stream ID"},
    {EXTENSION_DATA, "Extension data packet without stream ID"},
    {EXTENSION_DATA_STREAM_ID, "Extension data packet with stream ID"},
    {CONTEXT, "Context packet"},
    {EXTENSION_CONTEXT, "Extension context packet"},
    {COMMAND, "Command packet"},
    {EXTENSION_COMMAND, "Extension command packet"},
    {0, NULL}
};

static int
dissect_vrtgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    int bit_offset = 0;
    packet_type_e packet_type;
    int has_stream_id;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49.2");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* tree_item = proto_tree_add_item(tree, proto_vrtgen, tvb, 0, -1, ENC_NA);
    proto_tree* v49d2_tree = proto_item_add_subtree(tree_item, ett_v49d2);
    proto_tree_add_item(v49d2_tree, hf_v49d2_header, tvb, offset, 4, ENC_BIG_ENDIAN);

    packet_type = (packet_type_e) tvb_get_bits32(tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type, packet_types,  "Reserved packet type (0x%02x)"));

    offset = 4;
    switch (packet_type) {
    case SIGNAL_DATA:
    case EXTENSION_DATA:
        has_stream_id = FALSE;
    default:
        has_stream_id = TRUE;
    }
    if (has_stream_id) {
        //proto_tree_add_item(v49d2_tree, hf_v49d2_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_uint(v49d2_tree, hf_v49d2_sid, tvb, offset, 4, 0x12345678);
    }

    return tvb_captured_length(tvb);
}

void proto_register_vrtgen(void)
{
    static hf_register_info hf[] = {
        { &hf_v49d2_header,
            { "V49.2 header", "v49d2.hdr",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_sid,
            { "Stream ID", "v49d2.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },

    };

    static gint* ett[] = {
        &ett_v49d2
    };

    proto_vrtgen = proto_register_protocol(
        "VITA 49.2 Protocol",
        "VITA 49.2",
        "v49d2"
    );

    proto_register_field_array(proto_vrtgen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_vrtgen(void)
{
    static dissector_handle_t vrtgen_handle;

    vrtgen_handle = new_create_dissector_handle(dissect_vrtgen, proto_vrtgen);
    dissector_add_uint("udp.port", 13000, vrtgen_handle);
}
