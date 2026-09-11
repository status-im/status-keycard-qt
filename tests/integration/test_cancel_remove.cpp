#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>

using namespace IntegrationTest;

class TestCancelRemove : public IntegrationTestBase {
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

    void test_cancelBlockingLogin()
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
            [this]() { m_rpc.cancelCurrentOperation(); },
            5000);

        QVERIFY(result.actionTriggered);
        QVERIFY(!rpcSucceeded(result.response));
        QVERIFY(rpcErrorMessage(result.response).contains(QStringLiteral("cancel"), Qt::CaseInsensitive));
        QVERIFY2(elapsed.elapsed() < 2000,
                 "CancelCurrentOperation must unblock Login promptly");
    }

    void test_removeCardDuringOperation()
    {
        const QString cardId = freshCardId(QStringLiteral("remove"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keyUid = m_rpc.keyUidFromLastStatus();
        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();

        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("keyUid"), keyUid);

        QElapsedTimer elapsed;
        elapsed.start();
        const InterruptedRpcCall result = m_rpc.callRpcAfterStatus(
            QStringLiteral("keycard.Login"),
            params,
            QStringLiteral("ready"),
            [this]() { m_rpc.removeCard(); },
            5000);

        QVERIFY(result.actionTriggered);
        QVERIFY2(!rpcSucceeded(result.response),
                 qPrintable(QStringLiteral("Login succeeded after card removal: %1")
                                .arg(QString::fromUtf8(
                                    QJsonDocument(result.response).toJson(QJsonDocument::Compact)))));
        const QString error = rpcErrorMessage(result.response);
        QVERIFY2(!error.isEmpty(), "card removal must return an RPC error");
        QVERIFY2(error.contains(QStringLiteral("Card removed"))
                     || error.contains(QStringLiteral("no simulated card present")),
                 qPrintable(error));
        QVERIFY2(elapsed.elapsed() < 2000,
                 qPrintable(QStringLiteral("removing the card must fail Login promptly, took %1 ms (%2)")
                                .arg(elapsed.elapsed())
                                .arg(error)));
    }
};

QTEST_MAIN(TestCancelRemove)
#include "test_cancel_remove.moc"
