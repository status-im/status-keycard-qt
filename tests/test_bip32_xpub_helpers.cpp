#include <QtTest>

#include "utils/bip32_xpub_helpers.h"

using namespace StatusKeycard::Bip32;

class TestBip32XpubHelpers : public QObject
{
    Q_OBJECT

private slots:
    void testRipemd160EmptySpecVector()
    {
        QCOMPARE(ripemd160(QByteArray()).toHex(),
                 QByteArray("9c1185a5c5e9fc54612808977ee8f548b2258d31"));
    }

    void testRipemd160AbcSpecVector()
    {
        QCOMPARE(ripemd160(QByteArray("abc")).toHex(),
                 QByteArray("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
    }

    void testHash160Empty()
    {
        // HASH160("") = RIPEMD160(SHA256(""))
        QCOMPARE(hash160(QByteArray()).toHex(),
                 QByteArray("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"));
    }

    void testHash160CompressedPubkey()
    {
        QByteArray compressed(33, '\x11');
        compressed[0] = '\x02';
        const QByteArray digest = hash160(compressed);
        QCOMPARE(digest.size(), 20);
        QCOMPARE(digest.toHex(), QByteArray("adfce54f529b2154e3c361bbe3f7d41db0635717"));
    }
};

QTEST_MAIN(TestBip32XpubHelpers)
#include "test_bip32_xpub_helpers.moc"
