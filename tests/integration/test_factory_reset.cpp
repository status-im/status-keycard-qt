#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

class TestFactoryReset : public IntegrationTestBase {
    Q_OBJECT

private:
    QJsonObject reloadSeedWithoutSimulatorReset(const QString& cardId)
    {
        m_rpc.stop();
        m_rpc.clearSignals();
        m_rpc.plugInsertCard(cardId);
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("puk"), QString::fromUtf8(kDefaultPuk));
        params.insert(QStringLiteral("mnemonic"), QString::fromUtf8(kMnemonicB));
        return m_rpc.callRpc(QStringLiteral("keycard.Load"), params);
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

    void test_factoryResetFromReady()
    {
        const QString cardId = freshCardId(QStringLiteral("reset-ready"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        m_rpc.plugInsertCard(cardId);

        QJsonObject resetParams;
        resetParams.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        resetParams.insert(QStringLiteral("keycardUid"), keycardUid);
        const QJsonObject reset = m_rpc.callRpc(QStringLiteral("keycard.FactoryResetKeycard"), resetParams);
        QVERIFY2(rpcSucceeded(reset), qPrintable(rpcErrorMessage(reset)));
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("empty-keycard"));

        // Load is refused while a key is still on the card. A reset that only
        // reported empty-keycard without wiping the applet fails here.
        const QJsonObject reload = reloadSeedWithoutSimulatorReset(cardId);
        QVERIFY2(rpcSucceeded(reload), qPrintable(rpcErrorMessage(reload)));
    }

    void test_factoryResetFromBlockedPin()
    {
        const QString cardId = freshCardId(QStringLiteral("reset-blocked"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        QCOMPARE(m_rpc.blockPin(cardId, keyUid, 3).last(), 0);
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("blocked-pin"));

        m_rpc.plugInsertCard(cardId);
        QJsonObject resetParams;
        resetParams.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        resetParams.insert(QStringLiteral("keycardUid"), keycardUid);
        const QJsonObject reset = m_rpc.callRpc(QStringLiteral("keycard.FactoryResetKeycard"), resetParams);
        QVERIFY2(rpcSucceeded(reset), qPrintable(rpcErrorMessage(reset)));
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("empty-keycard"));

        const QJsonObject reload = reloadSeedWithoutSimulatorReset(cardId);
        QVERIFY2(rpcSucceeded(reload), qPrintable(rpcErrorMessage(reload)));
    }
};

QTEST_MAIN(TestFactoryReset)
#include "test_factory_reset.moc"
