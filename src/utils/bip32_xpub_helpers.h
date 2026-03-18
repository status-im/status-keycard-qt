#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>

namespace StatusKeycard::Bip32 {

struct PathInfo {
    int depth = 0;
    QVector<uint32_t> childIndexes;
    QString parentPath;
};

PathInfo parsePath(const QString& path);

QByteArray compressPublicKey(const QByteArray& uncompressedKey);

QByteArray hash160(const QByteArray& data);

QString serializeXpub(uint8_t depth, const QByteArray& parentFingerprint,
                      uint32_t childIndex, const QByteArray& chainCode,
                      const QByteArray& compressedPubKey);

} // namespace StatusKeycard::Bip32
