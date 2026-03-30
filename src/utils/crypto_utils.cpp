#include "crypto_utils.h"
#include <QCryptographicHash>
#include <QDebug>

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
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

int calculateRecoveryId(const QByteArray& hash, const QByteArray& r, const QByteArray& s, const QByteArray& expectedPubKey)
{
#ifdef KEYCARD_QT_HAS_OPENSSL
    if (hash.size() != 32 || r.size() != 32 || s.size() != 32 || expectedPubKey.size() != 65) {
        return -1;
    }

    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        return -1;
    }

    const EC_GROUP* group = EC_KEY_get0_group(eckey);

    EC_POINT* expected_point = EC_POINT_new(group);
    if (!expected_point || !EC_POINT_oct2point(group, expected_point,
            reinterpret_cast<const unsigned char*>(expectedPubKey.data()), 65, nullptr)) {
        if (expected_point) EC_POINT_free(expected_point);
        EC_KEY_free(eckey);
        return -1;
    }

    BIGNUM* r_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(r.data()), 32, nullptr);
    BN_CTX* ctx = BN_CTX_new();

    int result = -1;

    for (int rec_id = 0; rec_id <= 1; rec_id++) {
        EC_POINT* R = EC_POINT_new(group);
        if (!R) continue;

        if (EC_POINT_set_compressed_coordinates(group, R, r_bn, rec_id, ctx) == 1) {
            BIGNUM* s_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()), 32, nullptr);
            BIGNUM* e_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(hash.data()), 32, nullptr);
            BIGNUM* order = BN_new();
            BIGNUM* r_inv = BN_new();

            EC_GROUP_get_order(group, order, ctx);

            if (BN_mod_inverse(r_inv, r_bn, order, ctx)) {
                EC_POINT* sR = EC_POINT_new(group);
                EC_POINT_mul(group, sR, nullptr, R, s_bn, ctx);

                EC_POINT* eG = EC_POINT_new(group);
                EC_POINT_mul(group, eG, e_bn, nullptr, nullptr, ctx);

                EC_POINT_invert(group, eG, ctx);
                EC_POINT_add(group, sR, sR, eG, ctx);

                EC_POINT* Q = EC_POINT_new(group);
                EC_POINT_mul(group, Q, nullptr, sR, r_inv, ctx);

                if (EC_POINT_cmp(group, Q, expected_point, ctx) == 0) {
                    result = rec_id;
                }

                EC_POINT_free(Q);
                EC_POINT_free(eG);
                EC_POINT_free(sR);
            }

            BN_free(r_inv);
            BN_free(order);
            BN_free(e_bn);
            BN_free(s_bn);
        }

        EC_POINT_free(R);

        if (result != -1) break;
    }

    BN_CTX_free(ctx);
    BN_free(r_bn);
    EC_POINT_free(expected_point);
    EC_KEY_free(eckey);

    return result;
#else
    Q_UNUSED(hash);
    Q_UNUSED(r);
    Q_UNUSED(s);
    Q_UNUSED(expectedPubKey);
    qWarning() << "calculateRecoveryId: OpenSSL not available";
    return -1;
#endif
}

} // namespace StatusKeycard::CryptoUtils
