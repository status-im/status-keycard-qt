#pragma once

#include <QJsonObject>
#include <QString>

namespace IntegrationTest {

// When INIT is given no alternate PIN, the applet also accepts a second PIN
// made from the first six digits of the PUK. Keep PUK prefixes distinct from
// every PIN below, or PIN checks start exercising that second slot instead.
inline constexpr const char* kDefaultPin = "111111";
inline constexpr const char* kWrongPin = "999999";
inline constexpr const char* kNewPin = "222222";
inline constexpr const char* kDefaultPuk = "000000000000";
inline constexpr const char* kWrongPuk = "888888888888";
inline constexpr const char* kNewPuk = "123456123456";
inline constexpr const char* kCustomPairingPassword = "CustomPairingPass";
inline constexpr const char* kWalletPath = "m/44'/60'/0'/0/0";
inline constexpr const char* kTxHash =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

inline constexpr const char* kMnemonicA =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// BIP-39 test vector: m/44'/60'/0'/0/0 for kMnemonicA
inline constexpr const char* kMnemonicAWalletAddress =
    "0x9858effd232b4033e47d90003d41ec34ecaeda94";

inline constexpr const char* kMnemonicB =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

inline constexpr int kSimulatorPort = 9025;
inline constexpr const char* kSimulatorHost = "127.0.0.1";

inline QString rpcErrorMessage(const QJsonObject& response)
{
    return response.value(QStringLiteral("error")).toObject().value(QStringLiteral("message")).toString();
}

inline bool rpcSucceeded(const QJsonObject& response)
{
    return !response.isEmpty() && response.value(QStringLiteral("error")).isNull();
}

inline QJsonObject rpcResult(const QJsonObject& response)
{
    return response.value(QStringLiteral("result")).toObject();
}

} // namespace IntegrationTest
