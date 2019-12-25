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
