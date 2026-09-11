#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

class TestLoadRecover : public IntegrationTestBase {
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

    void test_loadOnEmptyCardSucceeds()
    {
        const QString cardId = freshCardId(QStringLiteral("load-empty"));
        const QJsonObject response = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(response), qPrintable(rpcErrorMessage(response)));
        QVERIFY(!m_rpc.keyUidFromLastStatus().isEmpty());
    }

    void test_loadOnKeyedCardFails()
    {
        const QString cardId = freshCardId(QStringLiteral("load-twice"));
        const QJsonObject first = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(first), qPrintable(rpcErrorMessage(first)));

        m_rpc.plugInsertCard(cardId);
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("puk"), QString::fromUtf8(kDefaultPuk));
        params.insert(QStringLiteral("mnemonic"), QString::fromUtf8(kMnemonicB));

        const QJsonObject second = m_rpc.callRpc(QStringLiteral("keycard.Load"), params);
        QVERIFY(!rpcSucceeded(second));
        QVERIFY(rpcErrorMessage(second).contains(QStringLiteral("Recover"), Qt::CaseInsensitive));
    }

    void test_recoverOverwritesKeyedCard()
    {
        const QString cardId = freshCardId(QStringLiteral("recover"));
        const QJsonObject first = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(first), qPrintable(rpcErrorMessage(first)));
        const QString firstKeyUid = m_rpc.keyUidFromLastStatus();
        QVERIFY(!firstKeyUid.isEmpty());

        m_rpc.plugInsertCard(cardId);
        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("puk"), QString::fromUtf8(kDefaultPuk));
        params.insert(QStringLiteral("mnemonic"), QString::fromUtf8(kMnemonicB));
        params.insert(QStringLiteral("keycardUid"), m_rpc.keycardUidFromLastStatus());

        const QJsonObject recover = m_rpc.callRpc(QStringLiteral("keycard.Recover"), params);
        QVERIFY2(rpcSucceeded(recover), qPrintable(rpcErrorMessage(recover)));

        const QString secondKeyUid = m_rpc.keyUidFromLastStatus();
        QVERIFY(!secondKeyUid.isEmpty());
        QVERIFY(firstKeyUid != secondKeyUid);
    }
};

QTEST_MAIN(TestLoadRecover)
#include "test_load_recover.moc"
