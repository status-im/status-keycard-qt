#include "fixtures/integration_test_base.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>
#include <QJsonObject>

using namespace IntegrationTest;

// removeCard() power-cycles the simulated card. A real card keeps pairings and
// the PIN retry counter in EEPROM across a power cycle.
class TestSimulatorPower : public IntegrationTestBase {
    Q_OBJECT

private:
    int lowestRemainingPinAttempts() const
    {
        int remaining = -1;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.remainingPinAttempts >= 0
                && (remaining < 0 || signal.remainingPinAttempts < remaining)) {
                remaining = signal.remainingPinAttempts;
            }
        }
        return remaining;
    }

    int lastAvailableSlots() const
    {
        int available = -1;
        for (const StatusSignal& signal : m_rpc.statusSignals()) {
            if (signal.availableSlots >= 0) {
                available = signal.availableSlots;
            }
        }
        return available;
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

    void test_pinRetryCounterSurvivesCardRemoval()
    {
        const QString cardId = freshCardId(QStringLiteral("power-pin"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        QVERIFY(!rpcSucceeded(m_rpc.login(QString::fromUtf8(kWrongPin), keyUid)));
        QCOMPARE(lowestRemainingPinAttempts(), 2);

        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        QVERIFY(!rpcSucceeded(m_rpc.login(QString::fromUtf8(kWrongPin), keyUid)));
        QCOMPARE(lowestRemainingPinAttempts(), 1);
    }

    void test_pairingSurvivesCardRemoval()
    {
        const QString cardId = freshCardId(QStringLiteral("power-pair"));
        const QJsonObject load = m_rpc.loadCard(cardId, QString::fromUtf8(kMnemonicA));
        QVERIFY2(rpcSucceeded(load), qPrintable(rpcErrorMessage(load)));
        const QString keyUid = m_rpc.keyUidFromLastStatus();

        m_rpc.stop();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject first = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(rpcSucceeded(first), qPrintable(rpcErrorMessage(first)));
        const int slotsBefore = lastAvailableSlots();
        QVERIFY(slotsBefore >= 0);

        // The stored pairing is reused, so a surviving pairing leaves the free
        // slot count unchanged.
        m_rpc.stop();
        m_rpc.removeCard();
        m_rpc.plugInsertCard(cardId);
        m_rpc.clearSignals();
        const QJsonObject second = m_rpc.login(QString::fromUtf8(kDefaultPin), keyUid);
        QVERIFY2(rpcSucceeded(second), qPrintable(rpcErrorMessage(second)));
        QCOMPARE(lastAvailableSlots(), slotsBefore);
    }
};

QTEST_MAIN(TestSimulatorPower)
#include "test_simulator_power.moc"
