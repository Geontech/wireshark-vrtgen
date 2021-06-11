/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from wireshark-3.4.4/tools/make-plugin-reg.py.
 */

#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"
#include <stdlib.h>

void proto_register_vrtgen(void);
void proto_reg_handoff_vrtgen(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = WIRESHARK_VERSION_MAJ_MIN;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_vrtgen;

    plug_vrtgen.register_protoinfo = proto_register_vrtgen;
    plug_vrtgen.register_handoff = proto_reg_handoff_vrtgen;
    proto_register_plugin(&plug_vrtgen);
}
