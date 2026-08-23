#include "bip32_xpub_helpers.h"
#include <QCryptographicHash>
#include <QStringList>
#include <cstdint>
#include <cstring>

namespace StatusKeycard::Bip32 {

namespace {

// RIPEMD-160 (COSIC). Software HASH160 avoids OpenSSL 3 EVP_ripemd160(),
// which lives in the unloaded legacy provider and aborts in EVP_DigestInit_ex.
constexpr uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

constexpr uint32_t kLeft[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
constexpr uint32_t kRight[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

constexpr uint8_t rLeft[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};
constexpr uint8_t rRight[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};
constexpr uint8_t sLeft[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};
constexpr uint8_t sRight[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

void transform(uint32_t h[5], const unsigned char* chunk) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        const unsigned char* p = chunk + i * 4;
        x[i] = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }

    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;

    for (int j = 0; j < 80; ++j) {
        uint32_t tl = rol(al + f(j, bl, cl, dl) + x[rLeft[j]] + kLeft[j / 16], sLeft[j]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = tl;

        uint32_t tr = rol(ar + f(79 - j, br, cr, dr) + x[rRight[j]] + kRight[j / 16], sRight[j]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }

    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

} // namespace

QByteArray ripemd160(const QByteArray& data) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    const auto* bytes = reinterpret_cast<const unsigned char*>(data.constData());
    const size_t size = static_cast<size_t>(data.size());
    size_t offset = 0;
    while (offset + 64 <= size) {
        transform(state, bytes + offset);
        offset += 64;
    }

    unsigned char block[64] = {};
    const size_t remaining = size - offset;
    if (remaining > 0) {
        std::memcpy(block, bytes + offset, remaining);
    }
    block[remaining] = 0x80;

    if (remaining >= 56) {
        transform(state, block);
        std::memset(block, 0, sizeof(block));
    }

    const uint64_t bitLen = static_cast<uint64_t>(size) * 8;
    for (int i = 0; i < 8; ++i) {
        block[56 + i] = static_cast<unsigned char>((bitLen >> (8 * i)) & 0xFF);
    }
    transform(state, block);

    QByteArray out(20, '\0');
    auto* dest = reinterpret_cast<unsigned char*>(out.data());
    for (int i = 0; i < 5; ++i) {
        dest[i * 4] = static_cast<unsigned char>(state[i] & 0xFF);
        dest[i * 4 + 1] = static_cast<unsigned char>((state[i] >> 8) & 0xFF);
        dest[i * 4 + 2] = static_cast<unsigned char>((state[i] >> 16) & 0xFF);
        dest[i * 4 + 3] = static_cast<unsigned char>((state[i] >> 24) & 0xFF);
    }
    return out;
}

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
    return ripemd160(QCryptographicHash::hash(data, QCryptographicHash::Sha256));
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
