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

/**
 * Extension Wireshark proto_tree functions for common VITA 49.2 data types that
 * are not naturally supported.
 */
#ifndef EXT_H
#define EXT_H

#include "enums.h"

static proto_item *
ext_proto_tree_add_fixed(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint radix, const guint encoding)
{
    double scale = 1 << radix;
    double value = tvb_get_bits64(tvb, start*8, length*8, encoding) / scale;
    return proto_tree_add_double(tree, hfindex, tvb, start, 8, value);
}

static proto_item *
ext_proto_tree_add_int_ts(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const gint start, tsi_e format, const guint encoding)
{
    proto_item* item = proto_tree_add_item(tree, hfindex, tvb, start, 4, encoding);
    proto_item_append_text(item, " [%s]", tsi_str[format].strptr);
    return item;
}

static proto_item *
ext_proto_tree_add_frac_ts(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const gint start, tsf_e format, const guint encoding)
{
    proto_item* item = proto_tree_add_item(tree, hfindex, tvb, start, 8, encoding);
    proto_item_append_text(item, " [%s]", tsf_str[format].strptr);
    return item;
}

#endif
