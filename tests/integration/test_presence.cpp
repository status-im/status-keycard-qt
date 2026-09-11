#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>
#include <QThread>

using namespace IntegrationTest;

class TestPresence : public IntegrationTestBase {
    Q_OBJECT

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

    void test_waitingForCardThenUnplug()
    {
        m_rpc.plugReader();
        m_rpc.clearSignals();

        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));

        QElapsedTimer elapsed;
        elapsed.start();
        const InterruptedRpcCall result = m_rpc.callRpcAfterStatus(
            QStringLiteral("keycard.Login"),
            params,
            QStringLiteral("waiting-for-card"),
            [this]() {
                m_rpc.unplugReader();
                QElapsedTimer wait;
                wait.start();
                while (wait.elapsed() < 1000
                       && m_rpc.lastStatusSignal().state != QStringLiteral("waiting-for-reader")) {
                    QThread::msleep(20);
                }
                m_rpc.cancelCurrentOperation();
            },
            5000);

        QVERIFY(result.actionTriggered);
        QVERIFY(!rpcSucceeded(result.response));
        bool sawWaitingForReader = false;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.state == QStringLiteral("waiting-for-reader")) {
                sawWaitingForReader = true;
                break;
            }
        }
        QVERIFY(sawWaitingForReader);
        QVERIFY2(elapsed.elapsed() < 2000, "unplug + cancel must unblock Login promptly");
    }

    void test_insertRemoveStates()
    {
        const QString cardId = freshCardId(QStringLiteral("presence"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugReader();
        m_rpc.clearSignals();

        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("keyUid"), m_rpc.keyUidFromLastStatus());

        const InterruptedRpcCall waiting = m_rpc.callRpcAfterStatus(
            QStringLiteral("keycard.Login"),
            params,
            QStringLiteral("waiting-for-card"),
            [this, cardId]() { m_rpc.plugInsertCard(cardId); },
            10000);

        QVERIFY(waiting.actionTriggered);
        QVERIFY2(rpcSucceeded(waiting.response), qPrintable(rpcErrorMessage(waiting.response)));

        bool sawReady = false;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.state == QStringLiteral("ready")) {
                sawReady = true;
                break;
            }
        }
        QVERIFY(sawReady);

        m_rpc.removeCard();
        QTRY_VERIFY(m_rpc.lastStatusSignal().state == QStringLiteral("waiting-for-card"));
    }

    void test_insertBeforeLoginSucceeds()
    {
        const QString cardId = freshCardId(QStringLiteral("preinsert"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();

        const QJsonObject login = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(rpcSucceeded(login), qPrintable(rpcErrorMessage(login)));
    }
};

QTEST_MAIN(TestPresence)
#include "test_presence.moc"
