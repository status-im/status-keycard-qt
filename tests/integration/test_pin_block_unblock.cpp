#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>
#include <QVector>

using namespace IntegrationTest;

class TestPinBlockUnblock : public IntegrationTestBase {
    Q_OBJECT

private:
    QJsonObject unblockParams(const QString& keyUid, const QString& keycardUid,
                              const QString& puk, const QString& newPin) const
    {
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("keyUid"), keyUid);
        params.insert(QStringLiteral("keycardUid"), keycardUid);
        params.insert(QStringLiteral("puk"), puk);
        params.insert(QStringLiteral("newPin"), newPin);
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

    void test_wrongPinDecrementsAndBlocks()
    {
        const QString cardId = freshCardId(QStringLiteral("pin-block"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keyUid = m_rpc.keyUidFromLastStatus();
        m_rpc.clearSignals();
        const QVector<int> remaining = m_rpc.blockPin(cardId, keyUid, 3);
        QCOMPARE(remaining, (QVector<int>{2, 1, 0}));

        const StatusSignal last = m_rpc.lastStatusSignal();
        QCOMPARE(last.state, QStringLiteral("blocked-pin"));
        QCOMPARE(last.remainingPinAttempts, 0);
    }

    void test_unblockWithPukSuccess()
    {
        const QString cardId = freshCardId(QStringLiteral("puk-success"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        QCOMPARE(m_rpc.blockPin(cardId, keyUid, 3).last(), 0);

        m_rpc.plugInsertCard(cardId);
        const QJsonObject unblock = m_rpc.callRpc(
            QStringLiteral("keycard.UnblockUsingPUK"),
            unblockParams(keyUid, keycardUid, QString::fromUtf8(kDefaultPuk), QString::fromUtf8(kNewPin)));
        QVERIFY2(rpcSucceeded(unblock), qPrintable(rpcErrorMessage(unblock)));
        QCOMPARE(m_rpc.lastStatusSignal().state, QStringLiteral("ready"));

        m_rpc.plugInsertCard(cardId);
        const QJsonObject goodLogin = m_rpc.login(QString::fromUtf8(kNewPin), keyUid);
        QVERIFY2(rpcSucceeded(goodLogin), qPrintable(rpcErrorMessage(goodLogin)));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject badLogin = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY(!rpcSucceeded(badLogin));
    }

    void test_wrongPukDecrementsAndBlocksPuk()
    {
        const QString cardId = freshCardId(QStringLiteral("puk-block"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));

        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        QCOMPARE(m_rpc.blockPin(cardId, keyUid, 3).last(), 0);

        QVector<int> remainingPuk;
        m_rpc.plugInsertCard(cardId);
        for (int attempt = 0; attempt < 5; ++attempt) {
            m_rpc.callRpc(
                QStringLiteral("keycard.UnblockUsingPUK"),
                unblockParams(keyUid, keycardUid, QString::fromUtf8(kWrongPuk), QString::fromUtf8(kNewPin)));
            remainingPuk.append(m_rpc.lastStatusSignal().remainingPukAttempts);
            m_rpc.stop();
            m_rpc.plugInsertCard(cardId);
        }

        QCOMPARE(remainingPuk, (QVector<int>{4, 3, 2, 1, 0}));
        bool sawBlockedPuk = false;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.state == QStringLiteral("blocked-puk")) {
                sawBlockedPuk = true;
                break;
            }
        }
        QVERIFY(sawBlockedPuk || m_rpc.lastStatusSignal().state == QStringLiteral("blocked-puk"));

        const QJsonObject blockedPukAttempt = m_rpc.callRpc(
            QStringLiteral("keycard.UnblockUsingPUK"),
            unblockParams(keyUid, keycardUid, QString::fromUtf8(kDefaultPuk), QString::fromUtf8(kNewPin)));
        QVERIFY(!rpcSucceeded(blockedPukAttempt));
    }
};

QTEST_MAIN(TestPinBlockUnblock)
#include "test_pin_block_unblock.moc"
