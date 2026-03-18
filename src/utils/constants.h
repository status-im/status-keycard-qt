#pragma once

#include <QString>

namespace StatusKeycard {

    inline const QString PathMaster = "m";
    inline const QString PathWalletRoot = "m/44'/60'/0'/0";
    inline const QString PathWallet = "m/44'/60'/0'/0/0";
    inline const QString PathEip1581 = "m/43'/60'/1581'";
    inline const QString PathWhisper = "m/43'/60'/1581'/0'/0";
    inline const QString PathEncryption = "m/43'/60'/1581'/1'/0";

    inline constexpr int PinLength = 6;
    inline constexpr int PukLength = 12;
    inline constexpr int KeyUidLengthWithout0x = 64;

} // namespace StatusKeycard
