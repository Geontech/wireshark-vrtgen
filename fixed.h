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

#ifndef FIXED_H
#define FIXED_H

double fixed_to_double(gint64 value, int radix)
{
    double scale = 1 << radix;
    return value / scale;
}

float fixed_to_float(gint32 value, int radix)
{
    float scale = 1 << radix;
    return value / scale;
}

gint64 get_int64(tvbuff_t *tvb, int offset, int encoding)
{
    if (encoding == ENC_BIG_ENDIAN) {
        return tvb_get_ntoh64(tvb, offset);
    } else {
        return tvb_get_letoh64(tvb, offset);
    }
}

gint32 get_int32(tvbuff_t *tvb, int offset, int encoding)
{
    if (encoding == ENC_BIG_ENDIAN) {
        return tvb_get_ntohl(tvb, offset);
    } else {
        return tvb_get_letohl(tvb, offset);
    }
}

gint16 get_int16(tvbuff_t *tvb, int offset, int encoding)
{
    if (encoding == ENC_BIG_ENDIAN) {
        return tvb_get_ntohs(tvb, offset);
    } else {
        return tvb_get_letohs(tvb, offset);
    }
}

#endif /* FIXED_H */
