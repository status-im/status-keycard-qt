#include "fixtures/integration_test_base.h"
#include "fixtures/simulator_client.h"
#include "fixtures/test_constants.h"

#include "utils/crypto_utils.h"

#include <QtTest/QtTest>
#include <QJsonArray>
#include <QJsonObject>

using namespace IntegrationTest;
using StatusKeycard::CryptoUtils::calculateRecoveryId;
using StatusKeycard::CryptoUtils::publicKeyToAddress;

static QByteArray hexBytes(const QString& value)
{
    QString hex = value;
    if (hex.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        hex = hex.mid(2);
    }
    return QByteArray::fromHex(hex.toLatin1());
}

class TestSignExport : public IntegrationTestBase {
    Q_OBJECT

private:
    QJsonObject baseParams(const QString& keyUid, const QString& pin) const
    {
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("keyUid"), keyUid);
        params.insert(QStringLiteral("pin"), pin);
        return params;
    }

private slots:
    void initTestCase()
    {
        QVERIFY2(initSimulator(), "keycard simulator must be running");
    }

    void cleanupTestCase()
    {
        shutdownSimulator();
    }

    void init()
    {
        m_rpc.stop();
        m_rpc.clearSignals();
    }

    void test_signReturnsRsv()
    {
        const QString cardId = freshCardId(QStringLiteral("sign"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QJsonObject walletKey = rpcResult(load).value(QStringLiteral("keys")).toObject()
                                          .value(QStringLiteral("walletKey")).toObject();
        const QString walletAddress = walletKey.value(QStringLiteral("address")).toString().toLower();
        QCOMPARE(walletAddress, QString::fromUtf8(kMnemonicAWalletAddress).toLower());
        const QByteArray walletPublicKey = hexBytes(walletKey.value(QStringLiteral("publicKey")).toString());
        QVERIFY2(walletPublicKey.size() == 65, "Load must return an uncompressed wallet public key");
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject params = baseParams(keyUid, QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("txHash"), QString::fromUtf8(kTxHash));
        params.insert(QStringLiteral("path"), QString::fromUtf8(kWalletPath));

        const QJsonObject response = m_rpc.callRpc(QStringLiteral("keycard.Sign"), params);
        QVERIFY2(rpcSucceeded(response), qPrintable(rpcErrorMessage(response)));

        const QJsonObject result = rpcResult(response);
        QVERIFY(result.value(QStringLiteral("r")).toString().startsWith(QStringLiteral("0x")));
        QVERIFY(result.value(QStringLiteral("s")).toString().startsWith(QStringLiteral("0x")));
        QVERIFY(result.contains(QStringLiteral("v")));
        QVERIFY(result.value(QStringLiteral("r")).toString().size() >= 66);
        QVERIFY(result.value(QStringLiteral("s")).toString().size() >= 66);
        const int v = result.value(QStringLiteral("v")).toInt();
        QVERIFY(v == 27 || v == 28);

        const QByteArray r = hexBytes(result.value(QStringLiteral("r")).toString());
        const QByteArray s = hexBytes(result.value(QStringLiteral("s")).toString());
        QCOMPARE(r.size(), 32);
        QCOMPARE(s.size(), 32);
        const int recoveryId = calculateRecoveryId(hexBytes(QString::fromUtf8(kTxHash)), r, s, walletPublicKey);
        QVERIFY2(recoveryId >= 0, "signature must recover the wallet public key from Load");
        QCOMPARE(recoveryId + 27, v);
        QCOMPARE(publicKeyToAddress(walletPublicKey).toLower(),
                 QString::fromUtf8(kMnemonicAWalletAddress).toLower());
    }

    void test_exportExtendedAndPublicKeyShape()
    {
        const QString cardId = freshCardId(QStringLiteral("export"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject xpubParams = baseParams(keyUid, QString::fromUtf8(kDefaultPin));
        xpubParams.insert(QStringLiteral("path"), QString::fromUtf8(kWalletPath));
        const QJsonObject xpub = m_rpc.callRpc(QStringLiteral("keycard.ExportExtendedPublicKey"), xpubParams);
        QVERIFY2(rpcSucceeded(xpub), qPrintable(rpcErrorMessage(xpub)));

        const QJsonObject extended = rpcResult(xpub).value(QStringLiteral("extendedPublicKey")).toObject();
        QCOMPARE(extended.value(QStringLiteral("address")).toString().toLower(),
                 QString::fromUtf8(kMnemonicAWalletAddress).toLower());
        QVERIFY(extended.value(QStringLiteral("publicKey")).toString().startsWith(QStringLiteral("0x")));
        QVERIFY(extended.value(QStringLiteral("chainCode")).toString().startsWith(QStringLiteral("0x")));
        QVERIFY(!extended.value(QStringLiteral("xpub")).toString().isEmpty());

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject singleParams = baseParams(keyUid, QString::fromUtf8(kDefaultPin));
        singleParams.insert(QStringLiteral("path"), QString::fromUtf8(kWalletPath));
        const QJsonObject single = m_rpc.callRpc(QStringLiteral("keycard.ExportPublicKey"), singleParams);
        QVERIFY2(rpcSucceeded(single), qPrintable(rpcErrorMessage(single)));
        QVERIFY(rpcResult(single).contains(QStringLiteral("exportedKey")));
        QVERIFY(rpcResult(single).value(QStringLiteral("exportedKey")).toObject()
                    .value(QStringLiteral("publicKey")).toString().startsWith(QStringLiteral("0x")));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject multiParams = baseParams(keyUid, QString::fromUtf8(kDefaultPin));
        QJsonArray paths;
        paths.append(QString::fromUtf8(kWalletPath));
        paths.append(QStringLiteral("m/44'/60'/0'/0/1"));
        multiParams.insert(QStringLiteral("paths"), paths);
        const QJsonObject multi = m_rpc.callRpc(QStringLiteral("keycard.ExportPublicKey"), multiParams);
        QVERIFY2(rpcSucceeded(multi), qPrintable(rpcErrorMessage(multi)));
        QCOMPARE(rpcResult(multi).value(QStringLiteral("exportedKeys")).toArray().size(), 2);
    }

    void test_storeAndGetMetadata()
    {
        const QString cardId = freshCardId(QStringLiteral("meta"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject store;
        store.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        store.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        store.insert(QStringLiteral("name"), QStringLiteral("qa-wallet"));
        QJsonArray metaPaths;
        metaPaths.append(QString::fromUtf8(kWalletPath));
        store.insert(QStringLiteral("paths"), metaPaths);
        const QJsonObject stored = m_rpc.callRpc(QStringLiteral("keycard.StoreKeycardMetadata"), store);
        QVERIFY2(rpcSucceeded(stored), qPrintable(rpcErrorMessage(stored)));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        QJsonObject get = baseParams(keyUid, QString::fromUtf8(kDefaultPin));
        const QJsonObject fetched = m_rpc.callRpc(QStringLiteral("keycard.GetKeycardMetadata"), get);
        QVERIFY2(rpcSucceeded(fetched), qPrintable(rpcErrorMessage(fetched)));
        QCOMPARE(rpcResult(fetched).value(QStringLiteral("name")).toString(), QStringLiteral("qa-wallet"));
        const QJsonArray wallets = rpcResult(fetched).value(QStringLiteral("wallets")).toArray();
        QVERIFY(!wallets.isEmpty());
        QCOMPARE(wallets.at(0).toObject().value(QStringLiteral("path")).toString(),
                 QString::fromUtf8(kWalletPath));
    }

    void test_notKeycard()
    {
        const QString cardId = freshCardId(QStringLiteral("empty"));
        SimulatorClient simulator(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
        QVERIFY2(simulator.createEmptyCard(cardId), "CREATE_EMPTY must succeed");

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject login = m_rpc.login(QString::fromUtf8(kDefaultPin));
        QVERIFY(!rpcSucceeded(login));
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("not-keycard"));
    }
};

QTEST_MAIN(TestSignExport)
#include "test_sign_export.moc"
