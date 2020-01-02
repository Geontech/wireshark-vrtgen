/*
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
 */

#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_symbol_export.h>

#include "moduleinfo.h"

#include "fixed.h"

#include "enums.h"
#include "cif0.h"
#include "cif1.h"
#include "prologue.h"
#include "trailer.h"

const gchar plugin_version[] = VERSION;

static int proto_vrtgen = -1;

static int hf_v49d2_integer_timestamp = -1;
static int hf_v49d2_fractional_timestamp = -1;
static int hf_v49d2_payload = -1;
static int hf_v49d2_data = -1;

/* Control packet controllee/controller UUID fields are not supported in vrtgen
 * yet, but we can handle them explicitly here */
static int hf_v49d2_controllee_uuid = -1;
static int hf_v49d2_controller_uuid = -1;

static gint ett_v49d2 = -1;
static gint ett_v49d2_prologue = -1;
static gint ett_v49d2_payload = -1;

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

static void
dissect_v49d2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int packet_size;
    header_t header;
    int has_trailer = 0;
    proto_item* tree_item;
    proto_tree *v49d2_tree;
    proto_tree* payload_tree;
    cif0_enables_t cif0;
    cif1_enables_t cif1;
    int payload_size;
    proto_item* payload_item;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49.2");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_item = proto_tree_add_item(tree, proto_vrtgen, tvb, 0, -1, ENC_NA);
    v49d2_tree = proto_item_add_subtree(tree_item, ett_v49d2);

    unpack_header(tvb, 0, &header, encoding);
    /* Convert packet size from words to bytes */
    packet_size = header.packet_size * 4;

    col_add_str(pinfo->cinfo, COL_INFO, packet_type_str[header.packet_type].strptr);

    if (is_data_packet(header.packet_type)) {
        dissect_data_header(tvb, v49d2_tree, offset, encoding);
        has_trailer = ((data_header_t*)&header)->trailer_included;
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
        cam_t cam;
        unpack_cam(tvb, offset, &cam, encoding);
        offset += dissect_cam(tvb, v49d2_tree, offset, encoding);
        proto_tree_add_item(v49d2_tree, hf_v49d2_message_id, tvb, offset, 4, encoding);
        offset += 4;
        if (cam.controllee_enable) {
            if (cam.controllee_format == IDENTIFIER_FORMAT_WORD) {
                proto_tree_add_item(v49d2_tree, hf_v49d2_controllee_id, tvb, offset, 4, encoding);
                offset += 4;
            } else {
                proto_tree_add_item(v49d2_tree, hf_v49d2_controllee_uuid, tvb, offset, 16, encoding);
                offset += 16;
            }
        }
        if (cam.controller_enable) {
            if (cam.controller_format == IDENTIFIER_FORMAT_WORD) {
                proto_tree_add_item(v49d2_tree, hf_v49d2_controller_id, tvb, offset, 4, encoding);
                offset += 4;
            } else {
                proto_tree_add_item(v49d2_tree, hf_v49d2_controller_uuid, tvb, offset, 16, encoding);
                offset += 16;
            }
        }
    }

    /*
     * Dump the CIF enables for context/command packets. In some cases (like
     * execute ack packets) there may not be any enables.
     */
    if (!is_data_packet(header.packet_type) && (offset < packet_size)) {
        unpack_cif0_enables(tvb, offset, &cif0, encoding);
        dissect_cif0_enables(tvb, v49d2_tree, offset, encoding);
        offset += 4;
        if (cif0.cif1_enable) {
            unpack_cif1_enables(tvb, offset, &cif1, encoding);
            dissect_cif1_enables(tvb, v49d2_tree, offset, encoding);
            offset += 4;
        }
    }

    payload_size = packet_size - offset;
    /* Exclude data packet trailer, if present, from the payload */
    if (has_trailer) {
        payload_size -= 4;
    }

    if (payload_size > 0) {
        payload_item = proto_tree_add_item(tree_item, hf_v49d2_payload, tvb, offset, payload_size, ENC_NA);
        payload_tree = proto_item_add_subtree(payload_item, ett_v49d2_payload);
        if (is_data_packet(header.packet_type)) {
            proto_tree_add_item(payload_tree, hf_v49d2_data, tvb, offset, payload_size, ENC_NA);
            offset += payload_size;
        } else {
            offset += dissect_cif0_fields(tvb, payload_tree, &cif0, offset, encoding);
            if (cif0.cif1_enable) {
                offset += dissect_cif1_fields(tvb, payload_tree, &cif1, offset, encoding);
            }
        }
    }

    if (has_trailer) {
        dissect_trailer(tvb, v49d2_tree, offset, encoding);
    }
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
        },
        { &hf_v49d2_controllee_uuid,
            { "Controllee UUID", "v49d2.controllee_id",
            FT_GUID, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_v49d2_controller_uuid,
            { "Controller UUID", "v49d2.controller_id",
            FT_GUID, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint* ett[] = {
        &ett_v49d2,
        &ett_v49d2_prologue,
        &ett_v49d2_payload,
    };

    proto_vrtgen = proto_register_protocol(
        "VITA 49.2 Protocol",
        "VITA 49.2",
        "v49d2"
    );

    proto_register_field_array(proto_vrtgen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_prologue(proto_vrtgen);
    register_trailer(proto_vrtgen);
    register_cif0(proto_vrtgen);
    register_cif1(proto_vrtgen);
}

void proto_reg_handoff_vrtgen(void)
{
    static dissector_handle_t vrtgen_handle;

    vrtgen_handle = create_dissector_handle(dissect_v49d2, proto_vrtgen);
    dissector_add_uint("udp.port", 13000, vrtgen_handle);
}
