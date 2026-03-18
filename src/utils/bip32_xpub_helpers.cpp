#include "bip32_xpub_helpers.h"
#include <QCryptographicHash>
#include <QStringList>
#include <cstring>

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/evp.h>
#endif

namespace StatusKeycard::Bip32 {

PathInfo parsePath(const QString& path) {
    PathInfo info;

    if (path == "m" || path.isEmpty()) {
        return info;
    }

    QString remainder = path.startsWith("m/") ? path.mid(2) : path;
    QStringList components = remainder.split('/');
    info.depth = components.size();

    for (const QString& component : components) {
        QString comp = component;
        bool hardened = comp.endsWith('\'') || comp.endsWith('h');
        if (hardened) comp.chop(1);
        uint32_t index = comp.toUInt();
        if (hardened) index |= 0x80000000;
        info.childIndexes.append(index);
    }

    int lastSlash = path.lastIndexOf('/');
    info.parentPath = (lastSlash > 0) ? path.left(lastSlash) : QStringLiteral("m");

    return info;
}

QByteArray compressPublicKey(const QByteArray& uncompressedKey) {
    if (uncompressedKey.size() != 65 || static_cast<uint8_t>(uncompressedKey[0]) != 0x04) {
        return QByteArray();
    }
    QByteArray compressed(33, '\0');
    compressed[0] = (static_cast<uint8_t>(uncompressedKey[64]) & 1) ? '\x03' : '\x02';
    std::memcpy(compressed.data() + 1, uncompressedKey.constData() + 1, 32);
    return compressed;
}

QByteArray hash160(const QByteArray& data) {
#ifdef KEYCARD_QT_HAS_OPENSSL
    QByteArray sha256 = QCryptographicHash::hash(data, QCryptographicHash::Sha256);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(ctx, sha256.constData(), sha256.size());
    EVP_DigestFinal_ex(ctx, digest, &digestLen);
    EVP_MD_CTX_free(ctx);

    return QByteArray(reinterpret_cast<const char*>(digest), static_cast<int>(digestLen));
#else
    Q_UNUSED(data);
    return QByteArray();
#endif
}

namespace {

    const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    QString base58Encode(const QByteArray& data) {
        int zeros = 0;
        while (zeros < data.size() && data[zeros] == '\0') zeros++;

        QByteArray buf(data.size() * 138 / 100 + 1, '\0');
        int length = 0;

        for (int i = zeros; i < data.size(); i++) {
            int carry = static_cast<uint8_t>(data[i]);
            for (int j = 0; j < length || carry != 0; j++) {
                if (j == length) length++;
                carry += 256 * static_cast<uint8_t>(buf[j]);
                buf[j] = static_cast<char>(carry % 58);
                carry /= 58;
            }
        }

        QString result;
        result.reserve(zeros + length);
        for (int i = 0; i < zeros; i++) result.append('1');
        for (int i = length - 1; i >= 0; i--) result.append(BASE58_ALPHABET[static_cast<uint8_t>(buf[i])]);

        return result;
    }

    static QString base58CheckEncode(const QByteArray& payload) {
        QByteArray hash1 = QCryptographicHash::hash(payload, QCryptographicHash::Sha256);
        QByteArray hash2 = QCryptographicHash::hash(hash1, QCryptographicHash::Sha256);
        QByteArray data = payload + hash2.left(4);
        return base58Encode(data);
    }
}

QString serializeXpub(uint8_t depth, const QByteArray& parentFingerprint,
                      uint32_t childIndex, const QByteArray& chainCode,
                      const QByteArray& compressedPubKey) {
    if (chainCode.size() < 32 || compressedPubKey.size() < 33) {
        return QString();
    }

    QByteArray data(78, '\0');
    // Version: 0x0488B21E (xpub mainnet)
    data[0] = '\x04';
    data[1] = '\x88';
    data[2] = '\xB2';
    data[3] = '\x1E';
    // Depth
    data[4] = static_cast<char>(depth);
    // Parent fingerprint (4 bytes)
    if (parentFingerprint.size() >= 4) {
        std::memcpy(data.data() + 5, parentFingerprint.constData(), 4);
    }
    // Child index (big-endian)
    data[9]  = static_cast<char>((childIndex >> 24) & 0xFF);
    data[10] = static_cast<char>((childIndex >> 16) & 0xFF);
    data[11] = static_cast<char>((childIndex >> 8) & 0xFF);
    data[12] = static_cast<char>(childIndex & 0xFF);
    // Chain code (32 bytes)
    std::memcpy(data.data() + 13, chainCode.constData(), 32);
    // Compressed public key (33 bytes)
    std::memcpy(data.data() + 45, compressedPubKey.constData(), 33);

    return base58CheckEncode(data);
}

} // namespace StatusKeycard::Bip32
