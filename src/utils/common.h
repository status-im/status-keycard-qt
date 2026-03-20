#pragma once

#include <QString>

namespace StatusKeycard {

    inline QString remove0xPrefix(const QString& str) {
        return str.startsWith("0x") ? str.mid(2) : str;
    }

    inline QString ensure0xPrefix(const QString& hex) {
        if (hex.isEmpty()) return hex;
        if (hex.length() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
            return hex;
        return QString("0x") + hex;
    }

} // namespace StatusKeycard
