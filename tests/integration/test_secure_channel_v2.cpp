#include "fixtures/integration_test_base.h"
#include "fixtures/simulator_client.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

// Applet 4.x (SecureChannelV2) only: no pairing, certificate-authenticated cards.
class TestSecureChannelV2 : public IntegrationTestBase {
    Q_OBJECT

private:
    bool sawState(const QString& state) const
    {
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.state == state) {
                return true;
            }
        }
        return false;
    }

    StatusSignal lastSignalWithCardInfo() const
    {
        const QVector<StatusSignal> signalList = m_rpc.statusSignals();
        for (auto it = signalList.crbegin(); it != signalList.crend(); ++it) {
            if (!it->instanceUid.isEmpty()) {
                return *it;
            }
        }
        return {};
    }

private slots:
    void initTestCase()
    {
        if (!simulatorUsesSecureChannelV2()) {
            QSKIP("applet 4.x only");
        }
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
        m_rpc.clearPairings();
    }

    void test_statusReportsSecureChannelV2()
    {
        const QString cardId = freshCardId(QStringLiteral("scv2-status"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const StatusSignal status = lastSignalWithCardInfo();
        QCOMPARE(status.secureChannelVersion, 2);
        QCOMPARE(status.version, QStringLiteral("4.0"));
        QCOMPARE(status.instanceUid.size(), 32);  // 16-byte UID derived from the identity key
        QVERIFY(!status.keyUid.isEmpty());
        QVERIFY(!sawState(QStringLiteral("pairing-error")));
    }

    void test_pairingPasswordIsIgnored()
    {
        const QString cardId = freshCardId(QStringLiteral("scv2-nopair"));
        const QJsonObject load = m_rpc.loadCard(
            cardId, QString::fromUtf8(kMnemonicA), QString::fromUtf8(kDefaultPin),
            QString::fromUtf8(kDefaultPuk), QString::fromUtf8(kCustomPairingPassword));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        // On applet 3.x this login would need the custom pairing password
        m_rpc.stop();
        m_rpc.clearPairings();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject login = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(rpcSucceeded(login), qPrintable(rpcErrorMessage(login)));
        QVERIFY(!sawState(QStringLiteral("pairing-error")));
    }

    void test_instanceUidIsStableAcrossPowerCycleAndFactoryReset()
    {
        const QString cardId = freshCardId(QStringLiteral("scv2-uid"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        QVERIFY(!keycardUid.isEmpty());

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        QVERIFY(rpcSucceeded(m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid)));
        QCOMPARE(m_rpc.keycardUidFromLastStatus(), keycardUid);

        m_rpc.plugInsertCard(cardId);
        QJsonObject resetParams;
        resetParams.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        resetParams.insert(QStringLiteral("keycardUid"), keycardUid);
        const QJsonObject reset = m_rpc.callRpc(QStringLiteral("keycard.FactoryResetKeycard"), resetParams);
        QVERIFY2(rpcSucceeded(reset), qPrintable(rpcErrorMessage(reset)));
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("empty-keycard"));
        QCOMPARE(m_rpc.keycardUidFromLastStatus(), keycardUid);

        // A different card has a different identity
        const QString otherId = freshCardId(QStringLiteral("scv2-uid-other"));
        QVERIFY(rpcSucceeded(m_rpc.loadCard(otherId, QString::fromUtf8(kMnemonicB))));
        QVERIFY(m_rpc.keycardUidFromLastStatus() != keycardUid);
    }

    void test_untrustedCardIsRefused()
    {
        const QString cardId = freshCardId(QStringLiteral("scv2-untrusted"));
        SimulatorClient simulator(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
        QVERIFY(simulator.createUntrustedCard(cardId));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();

        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("puk"), QString::fromUtf8(kDefaultPuk));
        params.insert(QStringLiteral("mnemonic"), QString::fromUtf8(kMnemonicA));
        const QJsonObject load = m_rpc.callRpc(QStringLiteral("keycard.Load"), params);
        QVERIFY(!rpcSucceeded(load));
        QVERIFY2(sawState(QStringLiteral("untrusted-keycard")),
                 qPrintable(QStringLiteral("last state: %1").arg(m_rpc.lastStatusSignal().state)));
    }
};

QTEST_MAIN(TestSecureChannelV2)
#include "test_secure_channel_v2.moc"
