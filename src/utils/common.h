#pragma once

#include <QString>

namespace StatusKeycard {

    inline QString remove0xPrefix(const QString& str) {
        return str.startsWith("0x") ? str.mid(2) : str;
    }

} // namespace StatusKeycard
