#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_symbol_export.h>

#include <vrtgen/vrtgen.hpp>

const gchar plugin_version[] = VRTGEN_VERSION;

static int proto_vrtgen = -1;

static int
dissect_vrtgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree_add_protocol_format(tree, proto_vrtgen, tvb, 0, -1, "This is VITA 49.2 (vrtgen library version %s)", plugin_version);
    return tvb_captured_length(tvb);
}

extern "C"
void proto_register_vrtgen(void)
{
    proto_vrtgen = proto_register_protocol("VITA 49.2 Protocol (vrtgen)", "VITA 49.2", "vrtgen");
}

extern "C"
void proto_reg_handoff_vrtgen(void)
{
}
