#include "signature_utils.h"

namespace StatusKeycard::SignatureUtils {

bool parseDERSignature(const QByteArray& der, QByteArray& outR, QByteArray& outS)
{
    int idx = 0;
    if (der.size() < 6 || static_cast<uint8_t>(der[idx++]) != 0x30) {
        return false;
    }
    idx++; // skip sequence length

    // R
    if (idx >= der.size() || static_cast<uint8_t>(der[idx++]) != 0x02) return false;
    int rLen = static_cast<uint8_t>(der[idx++]);
    if (idx + rLen > der.size()) return false;
    QByteArray r = der.mid(idx, rLen);
    idx += rLen;
    if (r.size() > 32) r = r.right(32);
    while (r.size() < 32) r.prepend('\0');

    // S
    if (idx >= der.size() || static_cast<uint8_t>(der[idx++]) != 0x02) return false;
    int sLen = static_cast<uint8_t>(der[idx++]);
    if (idx + sLen > der.size()) return false;
    QByteArray s = der.mid(idx, sLen);
    if (s.size() > 32) s = s.right(32);
    while (s.size() < 32) s.prepend('\0');

    outR = r;
    outS = s;
    return true;
}

QByteArray extractTemplateContent(const QByteArray& data)
{
    if (data.size() < 2) return data;
    uint8_t firstTag = static_cast<uint8_t>(data[0]);
    if (firstTag != 0xA0 && firstTag != 0xA1) return data;

    int idx = 1;
    uint8_t lenByte = static_cast<uint8_t>(data[idx++]);
    int templateLen = 0;
    if (lenByte & 0x80) {
        int numLenBytes = lenByte & 0x7F;
        if (numLenBytes > 3 || idx + numLenBytes > data.size()) return data;
        for (int i = 0; i < numLenBytes; i++) {
            templateLen = (templateLen << 8) | static_cast<uint8_t>(data[idx++]);
        }
    } else {
        templateLen = lenByte;
    }
    return data.mid(idx, templateLen);
}

QByteArray findDERSignature(const QByteArray& data)
{
    int idx = 0;
    while (idx < data.size() - 1) {
        uint8_t tag = static_cast<uint8_t>(data[idx]);
        int tagStart = idx;
        idx++;

        if (idx >= data.size()) break;
        uint8_t lenByte = static_cast<uint8_t>(data[idx++]);
        int length = 0;
        if (lenByte & 0x80) {
            int numLenBytes = lenByte & 0x7F;
            if (numLenBytes > 3 || idx + numLenBytes > data.size()) break;
            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | static_cast<uint8_t>(data[idx++]);
            }
        } else {
            length = lenByte;
        }

        if (length < 0 || idx + length > data.size()) break;

        if (tag == 0x30) {
            return data.mid(tagStart, (idx - tagStart) + length);
        }
        idx += length;
    }
    return QByteArray();
}

} // namespace StatusKeycard::SignatureUtils
