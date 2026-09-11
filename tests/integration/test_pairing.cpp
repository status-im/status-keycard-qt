#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

class TestPairing : public IntegrationTestBase {
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
        m_rpc.clearPairings();
    }

    void test_wrongPairingPasswordThenRetry()
    {
        const QString cardId = freshCardId(QStringLiteral("pair-custom"));
        const QJsonObject load = m_rpc.loadCard(
            cardId, QString::fromUtf8(kMnemonicA),
            QString::fromUtf8(kDefaultPin), QString::fromUtf8(kDefaultPuk),
            QString::fromUtf8(kCustomPairingPassword));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        QVERIFY(!keyUid.isEmpty());

        m_rpc.stop();
        m_rpc.clearPairings();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();

        const QJsonObject wrong = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(!rpcSucceeded(wrong), qPrintable(rpcErrorMessage(wrong)));
        bool sawPairingError = false;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.state == QStringLiteral("pairing-error")) {
                sawPairingError = true;
                break;
            }
        }
        QVERIFY2(sawPairingError,
                 qPrintable(QStringLiteral("expected pairing-error, last state was %1 (%2)")
                                .arg(m_rpc.lastStatusSignal().state, rpcErrorMessage(wrong))));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject ok = m_rpc.login(
            QString::fromUtf8(kDefaultPin), keyUid, QString::fromUtf8(kCustomPairingPassword));
        QVERIFY2(rpcSucceeded(ok), qPrintable(rpcErrorMessage(ok)));

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        const QJsonObject persisted = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(rpcSucceeded(persisted), qPrintable(rpcErrorMessage(persisted)));
    }

    void test_noAvailablePairingSlots()
    {
        const QString cardId = freshCardId(QStringLiteral("pair-slots"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();
        const int slotsAfterLoad = m_rpc.lastStatusSignal().availableSlots;
        QVERIFY2(slotsAfterLoad >= 0,
                 "SELECT should report remaining pairing slots after Load");

        // Applet 3.2 has 10 persistent slots. Do not POWER/remove between Logins:
        // SimulatedChannelBackend::removeCard() power-cycles the simulator and can
        // drop pairing EEPROM, so slots never exhaust.
        QString lastState;
        bool sawNoSlots = false;
        const int attempts = slotsAfterLoad + 2;
        for (int i = 0; i < attempts; ++i) {
            m_rpc.stop();
            m_rpc.clearPairings();
            m_rpc.plugInsertCard(cardId);
            m_rpc.clearSignals();

            QJsonObject params;
            params.insert(QStringLiteral("storageFilePath"),
                          m_rpc.storagePath() + QStringLiteral(".slot-%1").arg(i));
            params.insert(QStringLiteral("pin"), QString::fromUtf8(kDefaultPin));
            params.insert(QStringLiteral("keyUid"), keyUid);
            m_rpc.callRpc(QStringLiteral("keycard.Login"), params);
            lastState = m_rpc.lastStatusSignal().state;
            if (lastState == QStringLiteral("no-available-pairing-slots")) {
                sawNoSlots = true;
                break;
            }
        }

        QVERIFY2(sawNoSlots,
                 qPrintable(QStringLiteral("expected no-available-pairing-slots after %1 extra pairs "
                                         "(slots after Load=%2), last state was %3")
                                .arg(attempts)
                                .arg(slotsAfterLoad)
                                .arg(lastState)));
        QVERIFY(lastState != QStringLiteral("pairing-error"));
    }
};

QTEST_MAIN(TestPairing)
#include "test_pairing.moc"
