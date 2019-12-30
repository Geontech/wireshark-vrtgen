#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_symbol_export.h>

#include "moduleinfo.h"

#include "fixed.h"

#include "enums.h"
#include "cif0.h"
#include "cif1.h"
#include "prologue.h"

const gchar plugin_version[] = VERSION;

static int proto_vrtgen = -1;

static int hf_v49d2_integer_timestamp = -1;
static int hf_v49d2_fractional_timestamp = -1;
static int hf_v49d2_payload = -1;
static int hf_v49d2_data = -1;

static gint ett_v49d2 = -1;
static gint ett_v49d2_prologue = -1;
static gint ett_v49d2_payload = -1;
static gint ett_v49d2_trailer = -1;

/* Some devices are known to ignore the big endian requirement of the spec */
static guint encoding = ENC_BIG_ENDIAN;

static int has_stream_id(packet_type_e type)
{
    switch(type) {
    case PACKET_TYPE_SIGNAL_DATA:
    case PACKET_TYPE_EXTENSION_DATA:
        return FALSE;
    default:
        return TRUE;
    }

}

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

static int is_context_packet(packet_type_e type)
{
    switch(type) {
    case PACKET_TYPE_CONTEXT:
    case PACKET_TYPE_EXTENSION_CONTEXT:
        return TRUE;
    default:
        return FALSE;
    }
}

static int is_command_packet(packet_type_e type)
{
    switch(type) {
    case PACKET_TYPE_COMMAND:
    case PACKET_TYPE_EXTENSION_COMMAND:
        return TRUE;
    default:
        return FALSE;
    }
}

static int
dissect_vrtgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    header_t header;
    proto_item* tree_item;
    proto_tree *v49d2_tree;
    proto_tree* payload_tree;
    cif0_enables cif0;
    cif1_enables cif1;
    int payload_size;
    tvbuff_t* payload_buf;
    proto_item* payload_item;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49.2");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_item = proto_tree_add_item(tree, proto_vrtgen, tvb, 0, -1, ENC_NA);
    v49d2_tree = proto_item_add_subtree(tree_item, ett_v49d2);

    header.packet_type = (packet_type_e) tvb_get_bits8(tvb, 0, 4);
    header.class_id_enable = tvb_get_bits8(tvb, 4, 1);
    header.tsi = (tsi_e) tvb_get_bits8(tvb, 8, 2);
    header.tsf = (tsf_e) tvb_get_bits8(tvb, 10, 2);
    header.packet_size = 4 * tvb_get_bits(tvb, 16, 16, encoding);

    col_add_str(pinfo->cinfo, COL_INFO, packet_type_str[header.packet_type].strptr);

    if (is_data_packet(header.packet_type)) {
        dissect_data_header(tvb, v49d2_tree, offset, encoding);
    } else if (is_context_packet(header.packet_type)) {
        dissect_context_header(tvb, v49d2_tree, offset, encoding);
    } else if (is_command_packet(header.packet_type)) {
        dissect_command_header(tvb, v49d2_tree, offset, encoding);
    } else {
        /* Fallback: dissect as base header */
        dissect_header(tvb, v49d2_tree, offset, encoding);
    }

    offset = 4;
    if (has_stream_id(header.packet_type)) {
        proto_tree_add_item(v49d2_tree, hf_v49d2_stream_id, tvb, offset, 4, encoding);
        offset += 4;
    }
    if (header.class_id_enable) {
        offset += dissect_class_id(tvb, v49d2_tree, offset, encoding);
    }
    if (header.tsi != TSI_NONE) {
        proto_item* item = proto_tree_add_item(v49d2_tree, hf_v49d2_integer_timestamp, tvb, offset, 4, encoding);
        proto_item_append_text(item, " [%s]", tsi_str[header.tsi].strptr);
        offset += 4;
    }
    if (header.tsf != TSI_NONE) {
        proto_item* item = proto_tree_add_item(v49d2_tree, hf_v49d2_fractional_timestamp, tvb, offset, 8, encoding);
        proto_item_append_text(item, " [%s]", tsf_str[header.tsf].strptr);
        offset += 8;
    }

    if (is_command_packet(header.packet_type)) {
        offset += dissect_cam(tvb, v49d2_tree, offset, encoding);
        proto_tree_add_item(v49d2_tree, hf_v49d2_message_id, tvb, offset, 4, encoding);
        offset += 4;
    }

    if (!is_data_packet(header.packet_type)) {
        dissect_cif0_enables(tvb, v49d2_tree, &cif0, offset, encoding);
        offset += 4;
        if (cif0.cif1_enable) {
            dissect_cif1_enables(tvb, v49d2_tree, &cif1, offset, encoding);
            offset += 4;
        }
    }

    payload_size = header.packet_size - offset;
    /* TODO: if trailer subtract 1 more */
    payload_buf = tvb_new_subset_length(tvb, offset, payload_size);
    payload_item = proto_tree_add_item(tree_item, hf_v49d2_payload, payload_buf, 0, -1, ENC_NA);
    payload_tree = proto_item_add_subtree(payload_item, ett_v49d2_payload);
    if (is_data_packet(header.packet_type)) {
        proto_tree_add_item(payload_tree, hf_v49d2_data, payload_buf, 0, -1, ENC_NA);
    } else {
        int sub_offset = dissect_cif0_fields(payload_buf, payload_tree, &cif0, 0, encoding);
        if (cif0.cif1_enable) {
            sub_offset += dissect_cif1_fields(payload_buf, payload_tree, &cif1, sub_offset, encoding);
        }
    }

    return tvb_captured_length(tvb);
}

void proto_register_vrtgen(void)
{
    static hf_register_info hf[] = {
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

    register_prologue(proto_vrtgen);
    register_cif0(proto_vrtgen);
    register_cif1(proto_vrtgen);
}

void proto_reg_handoff_vrtgen(void)
{
    static dissector_handle_t vrtgen_handle;

    vrtgen_handle = new_create_dissector_handle(dissect_vrtgen, proto_vrtgen);
    dissector_add_uint("udp.port", 13000, vrtgen_handle);
}
