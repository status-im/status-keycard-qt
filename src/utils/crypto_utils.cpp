#include "crypto_utils.h"
#include <QCryptographicHash>
#include <QDebug>

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#endif

namespace StatusKeycard::CryptoUtils {

QString publicKeyToAddress(const QByteArray& pubKey) {
    if (pubKey.size() != 65 || pubKey[0] != 0x04) {
        qWarning() << "publicKeyToAddress: Invalid public key format";
        return QString();
    }

    QByteArray pubKeyData = pubKey.mid(1);
    QByteArray hash = QCryptographicHash::hash(pubKeyData, QCryptographicHash::Keccak_256);
    QByteArray address = hash.right(20);

    return QString("0x") + address.toHex();
}

QByteArray derivePublicKeyFromPrivate(const QByteArray& privKey) {
#ifdef KEYCARD_QT_HAS_OPENSSL
    if (privKey.size() != 32) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid private key size:" << privKey.size();
        return QByteArray();
    }

    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to create EC_KEY";
        return QByteArray();
    }

    BIGNUM* priv_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(privKey.data()), privKey.size(), nullptr);
    if (!priv_bn || !EC_KEY_set_private_key(eckey, priv_bn)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to set private key";
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return QByteArray();
    }

    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to compute public key";
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return QByteArray();
    }

    EC_KEY_set_public_key(eckey, pub_point);

    unsigned char pub_key_bytes[65];
    size_t pub_key_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                            pub_key_bytes, sizeof(pub_key_bytes), nullptr);

    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);

    if (pub_key_len != 65) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid public key length:" << pub_key_len;
        return QByteArray();
    }

    return QByteArray(reinterpret_cast<const char*>(pub_key_bytes), pub_key_len);
#else
    Q_UNUSED(privKey);
    qWarning() << "derivePublicKeyFromPrivate: OpenSSL not available";
    return QByteArray();
#endif
}

} // namespace StatusKeycard::CryptoUtils
