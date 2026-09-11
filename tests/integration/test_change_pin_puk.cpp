#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

class TestChangePinPuk : public IntegrationTestBase {
    Q_OBJECT

private:
    QJsonObject changePinParams(const QString& keyUid, const QString& keycardUid,
                                  const QString& pin, const QString& newPin) const
    {
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("keyUid"), keyUid);
        params.insert(QStringLiteral("keycardUid"), keycardUid);
        params.insert(QStringLiteral("pin"), pin);
        params.insert(QStringLiteral("newPin"), newPin);
        return params;
    }

    QJsonObject changePukParams(const QString& keyUid, const QString& keycardUid,
                                 const QString& pin, const QString& newPuk) const
    {
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("keyUid"), keyUid);
        params.insert(QStringLiteral("keycardUid"), keycardUid);
        params.insert(QStringLiteral("pin"), pin);
        params.insert(QStringLiteral("newPuk"), newPuk);
        return params;
    }

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

    void test_changePinWorksAfterReconnect()
    {
        const QString cardId = freshCardId(QStringLiteral("chg-pin"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject changed = m_rpc.callRpc(
            QStringLiteral("keycard.ChangeKeycardPIN"),
            changePinParams(keyUid, keycardUid, QString::fromUtf8(kDefaultPin), QString::fromUtf8(kNewPin)));
        QVERIFY2(rpcSucceeded(changed), qPrintable(rpcErrorMessage(changed)));

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject good = m_rpc.login(QString::fromUtf8(kNewPin), keyUid);
        QVERIFY2(rpcSucceeded(good), qPrintable(rpcErrorMessage(good)));

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject bad = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY(!rpcSucceeded(bad));
    }

    void test_changePukWorksAfterReconnect()
    {
        const QString cardId = freshCardId(QStringLiteral("chg-puk"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject changed = m_rpc.callRpc(
            QStringLiteral("keycard.ChangeKeycardPUK"),
            changePukParams(keyUid, keycardUid, QString::fromUtf8(kDefaultPin), QString::fromUtf8(kNewPuk)));
        QVERIFY2(rpcSucceeded(changed), qPrintable(rpcErrorMessage(changed)));

        QCOMPARE(m_rpc.blockPin(cardId, keyUid, 3).last(), 0);

        m_rpc.plugInsertCard(cardId);
        const QJsonObject unblock = m_rpc.callRpc(
            QStringLiteral("keycard.UnblockUsingPUK"),
            unblockParams(keyUid, keycardUid, QString::fromUtf8(kNewPuk), QString::fromUtf8(kNewPin)));
        QVERIFY2(rpcSucceeded(unblock), qPrintable(rpcErrorMessage(unblock)));

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject good = m_rpc.login(QString::fromUtf8(kNewPin), keyUid);
        QVERIFY2(rpcSucceeded(good), qPrintable(rpcErrorMessage(good)));
    }

    void test_uidMismatchRejected()
    {
        const QString cardId = freshCardId(QStringLiteral("chg-uid"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const QString keycardUid = m_rpc.keycardUidFromLastStatus();
        const QString wrongKeyUid =
            QStringLiteral("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject badKey = m_rpc.callRpc(
            QStringLiteral("keycard.ChangeKeycardPIN"),
            changePinParams(wrongKeyUid, keycardUid, QString::fromUtf8(kDefaultPin), QString::fromUtf8(kNewPin)));
        QVERIFY(!rpcSucceeded(badKey));
        QVERIFY(rpcErrorMessage(badKey).contains(QStringLiteral("keyUid"), Qt::CaseInsensitive));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject badCard = m_rpc.callRpc(
            QStringLiteral("keycard.ChangeKeycardPIN"),
            changePinParams(keyUid, QStringLiteral("deadbeefdeadbeefdeadbeefdeadbeef"),
                            QString::fromUtf8(kDefaultPin), QString::fromUtf8(kNewPin)));
        QVERIFY(!rpcSucceeded(badCard));
        QVERIFY(rpcErrorMessage(badCard).contains(QStringLiteral("keycard"), Qt::CaseInsensitive)
                || rpcErrorMessage(badCard).contains(QStringLiteral("instance"), Qt::CaseInsensitive));
    }
};

QTEST_MAIN(TestChangePinPuk)
#include "test_change_pin_puk.moc"
