#pragma once

#include <QByteArray>
#include <QString>

namespace StatusKeycard::CryptoUtils {

QString publicKeyToAddress(const QByteArray& pubKey);

QByteArray derivePublicKeyFromPrivate(const QByteArray& privKey);

int calculateRecoveryId(const QByteArray& hash, const QByteArray& r, const QByteArray& s, const QByteArray& expectedPubKey);

} // namespace StatusKeycard::CryptoUtils
