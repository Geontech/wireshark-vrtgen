#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_symbol_export.h>

#include "moduleinfo.h"

#include "enums.h"

const gchar plugin_version[] = VERSION;

static int proto_vrtgen = -1;

static int hf_v49d2_header = -1;
static int hf_v49d2_tsi = -1;
static int hf_v49d2_tsf = -1;
static int hf_v49d2_packet_count = -1;
static int hf_v49d2_packet_size = -1;
static int hf_v49d2_stream_id = -1;
static int hf_v49d2_integer_timestamp = -1;
static int hf_v49d2_fractional_timestamp = -1;
static int hf_v49d2_payload = -1;
static int hf_v49d2_data = -1;

static gint ett_v49d2 = -1;
static gint ett_v49d2_prologue = -1;
static gint ett_v49d2_payload = -1;
static gint ett_v49d2_trailer = -1;

#include "cif0.h"
#include "cif1.h"

// Some devices are known to ignore the big endian requirement of the spec
static guint encoding = ENC_BIG_ENDIAN;

static int is_data_packet(packet_type_e type)
{
    switch(type) {
    case PACKET_TYPE_SIGNAL_DATA:
    case PACKET_TYPE_SIGNAL_DATA_STREAM_ID:
    case PACKET_TYPE_EXTENSION_DATA:
    case PACKET_TYPE_EXTENSION_DATA_STREAM_ID:
        return TRUE;
    default:
        return FALSE;
    }
}

static int
dissect_vrtgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    packet_type_e packet_type;
    int has_class_id;
    int not_v49d0;
    tsi_e tsi;
    tsf_e tsf;
    int has_stream_id;
    proto_item* tree_item;
    proto_tree *v49d2_tree;
    proto_tree* prologue_tree;
    proto_tree* payload_tree;
    int packet_size;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49.2");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_item = proto_tree_add_item(tree, proto_vrtgen, tvb, 0, -1, ENC_NA);
    v49d2_tree = proto_item_add_subtree(tree_item, ett_v49d2);
    prologue_tree = proto_item_add_subtree(v49d2_tree, ett_v49d2_prologue);
    proto_tree_add_item(prologue_tree, hf_v49d2_header, tvb, 0, 4, encoding);

    packet_type = (packet_type_e) tvb_get_bits8(tvb, 0, 4);
    has_class_id = tvb_get_bits8(tvb, 4, 1);

    tsi = (tsi_e) tvb_get_bits8(tvb, 8, 2);
    tsf = (tsf_e) tvb_get_bits8(tvb, 10, 2);

    col_add_str(pinfo->cinfo, COL_INFO, packet_type_str[packet_type]);

    proto_tree_add_string(prologue_tree, hf_v49d2_tsi, tvb, 1, 1, tsi_str[tsi]);
    proto_tree_add_string(prologue_tree, hf_v49d2_tsf, tvb, 1, 1, tsf_str[tsf]);
    proto_tree_add_bits_item(prologue_tree, hf_v49d2_packet_count, tvb, 12, 4, encoding);
    proto_tree_add_item(prologue_tree, hf_v49d2_packet_size, tvb, 2, 2, encoding);
    packet_size = 4 * tvb_get_bits(tvb, 16, 16, encoding);

    offset = 4;
    switch (packet_type) {
    case PACKET_TYPE_SIGNAL_DATA:
    case PACKET_TYPE_EXTENSION_DATA:
        has_stream_id = FALSE;
    default:
        has_stream_id = TRUE;
    }
    if (has_stream_id) {
        proto_tree_add_item(prologue_tree, hf_v49d2_stream_id, tvb, offset, 4, encoding);
        offset += 4;
    }
    if (has_class_id) {
        offset += 8;
    }
    if (tsi != TSI_NONE) {
        proto_item* item = proto_tree_add_item(prologue_tree, hf_v49d2_integer_timestamp, tvb, offset, 4, encoding);
        proto_item_append_text(item, " [%s]", tsi_str[tsi]);
        offset += 4;
    }
    if (tsf != TSI_NONE) {
        proto_item* item = proto_tree_add_item(prologue_tree, hf_v49d2_fractional_timestamp, tvb, offset, 8, encoding);
        proto_item_append_text(item, " [%s]", tsf_str[tsf]);
        offset += 8;
    }

    if (!is_data_packet(packet_type)) {
        tvbuff_t* cif0_buf = tvb_new_subset(tvb, offset, 4, -1);
        dissect_cif0_enables(cif0_buf, prologue_tree, encoding);
        offset += 4;
    }

    packet_size -= offset;
    // if trailer subtract 1 more
    tvbuff_t* payload_buf = tvb_new_subset(tvb, offset, packet_size, -1);
    proto_item* payload_item = proto_tree_add_item(tree_item, hf_v49d2_payload, payload_buf, 0, -1, ENC_NA);
    payload_tree = proto_item_add_subtree(payload_item, ett_v49d2_payload);
    if (is_data_packet(packet_type)) {
        proto_tree_add_item(payload_tree, hf_v49d2_data, payload_buf, 0, -1, ENC_NA);
    } else {
        proto_tree_add_item(payload_tree, hf_v49d2_data, payload_buf, 0, -1, ENC_NA);
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
        { &hf_v49d2_stream_id,
            { "Stream ID", "v49d2.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_tsi,
            { "TSI", "v49d2.tsi",
            FT_STRING, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_tsf,
            { "TSF", "v49d2.tsf",
            FT_STRING, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_packet_count,
            { "Packet Count", "v49d2.packet_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_packet_size,
            { "Packet Size", "v49d2.packet_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_integer_timestamp,
            { "Integer timestamp", "v49d2.integer_timestamp",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_fractional_timestamp,
            { "Fractional timestamp", "v49d2.fractional_timestamp",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_payload,
            { "Payload", "v49d2.payload",
            FT_NONE, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_data,
            { "Data", "v49d2.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint* ett[] = {
        &ett_v49d2,
        &ett_v49d2_prologue,
        &ett_v49d2_payload,
        &ett_v49d2_trailer,
    };

    proto_vrtgen = proto_register_protocol(
        "VITA 49.2 Protocol",
        "VITA 49.2",
        "v49d2"
    );

    proto_register_field_array(proto_vrtgen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_cif0(proto_vrtgen);
    register_cif1(proto_vrtgen);
}

void proto_reg_handoff_vrtgen(void)
{
    static dissector_handle_t vrtgen_handle;

    vrtgen_handle = new_create_dissector_handle(dissect_vrtgen, proto_vrtgen);
    dissector_add_uint("udp.port", 13000, vrtgen_handle);
}
