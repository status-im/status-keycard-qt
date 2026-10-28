#include "fixtures/integration_test_base.h"
#include "fixtures/simulator_client.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

// Both applet generations: a card whose identity certificate no trusted CA signed (development or
// custom-made card) is reported with certificateTrusted = false and stays fully usable. Applet 4.x
// reports the certificate in SELECT, 3.x answers IDENTIFY. A blank 3.x card has no instance UID, so
// its card info (and trust) is reported only once it is initialized.
class TestCardCertificate : public IntegrationTestBase {
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

    /// Loads @p cardId, already created by the caller, then logs in again with it and returns the keyUid
    QString loadAndLogin(const QString& cardId)
    {
        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();

        QJsonObject params;
        params.insert(QStringLiteral("storageFilePath"), m_rpc.storagePath());
        params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
        params.insert(QStringLiteral("puk"), QString::fromUtf8(kDefaultPuk));
        params.insert(QStringLiteral("mnemonic"), QString::fromUtf8(kMnemonicA));
        const QJsonObject load = m_rpc.callRpc(QStringLiteral("keycard.Load"), params);
        if (!rpcSucceeded(load)) {
            qWarning("Load failed: %s", qPrintable(rpcErrorMessage(load)));
            return {};
        }
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject login = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        if (!rpcSucceeded(login)) {
            qWarning("Login failed: %s", qPrintable(rpcErrorMessage(login)));
            return {};
        }
        return keyUid;
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
        m_rpc.clearPairings();
    }

    void test_unknownCaCardIsUsable()
    {
        const QString cardId = freshCardId(QStringLiteral("cert-unknown-ca"));
        SimulatorClient simulator(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
        QVERIFY(simulator.createUntrustedCard(cardId));

        QVERIFY(!loadAndLogin(cardId).isEmpty());
        QVERIFY(!sawState(QStringLiteral("untrusted-keycard")));
        QVERIFY(!lastSignalWithCardInfo().certificateTrusted);
    }

    void test_trustedCaCardIsReportedTrusted()
    {
        const QString cardId = freshCardId(QStringLiteral("cert-trusted-ca"));
        SimulatorClient simulator(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
        QVERIFY(simulator.resetCard(cardId));

        QVERIFY(!loadAndLogin(cardId).isEmpty());
        QVERIFY(lastSignalWithCardInfo().certificateTrusted);
    }
};

QTEST_MAIN(TestCardCertificate)
#include "test_card_certificate.moc"
