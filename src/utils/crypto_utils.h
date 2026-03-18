#pragma once

#include <QByteArray>
#include <QString>

namespace StatusKeycard::CryptoUtils {

QString publicKeyToAddress(const QByteArray& pubKey);

QByteArray derivePublicKeyFromPrivate(const QByteArray& privKey);

} // namespace StatusKeycard::CryptoUtils
