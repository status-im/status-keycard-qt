#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QtConcurrent>
#include <QElapsedTimer>
#include "session/session_manager.h"
#include "session/session_state.h"
#include "mocks/mock_communication_manager.h"
#include "mocks/mock_backend.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/keycard_channel.h>
#include <keycard-qt/communication_manager.h>
#include <QSemaphore>
#include <QThread>
#include <memory>
#include <atomic>

using namespace StatusKeycard;
using namespace StatusKeycardTest;

// Pauses inside startDetection() until released: a start descheduled while a stop comes in.
class PausingCommunicationManager : public Keycard::CommunicationManager {
public:
    std::atomic<bool> armed{false};
    QSemaphore paused;
    QSemaphore release;

    bool startDetection() override {
        if (armed.exchange(false)) {
            paused.release();
            release.acquire();
        }
        return Keycard::CommunicationManager::startDetection();
    }
};

// Notifies when a stop reached the communication manager - the stopping thread posts its
// native stop right after.
class StopNotifyingCommunicationManager : public Keycard::CommunicationManager {
public:
    QSemaphore stopping;

    void stopDetection() override {
        Keycard::CommunicationManager::stopDetection();
        stopping.release();
    }
};

class TestSessionManager : public QObject
{
    Q_OBJECT

private:
    SessionManager* m_manager;
    std::shared_ptr<MockCommunicationManager> m_mockComm;
    QTemporaryDir* m_tempDir;
    QVector<QPair<SessionState, SessionState>> m_stateChanges;

    void onStateChanged(SessionState newState, SessionState oldState)
    {
        m_stateChanges.append(qMakePair(newState, oldState));
    }

private slots:
    void init()
    {
        m_tempDir = new QTemporaryDir();
        QVERIFY(m_tempDir->isValid());

        m_manager = new SessionManager();
        m_stateChanges.clear();

        connect(m_manager, &SessionManager::stateChanged,
                this, &TestSessionManager::onStateChanged);

        // Create mock CommunicationManager (no real infrastructure needed!)
        m_mockComm = std::make_shared<MockCommunicationManager>();

        // SessionManager now accepts ICommunicationManager interface - no casting needed!
        m_manager->setCommunicationManager(m_mockComm);
    }

    void cleanup()
    {
        if (m_manager) {
            m_manager->stop();
            delete m_manager;
            m_manager = nullptr;
        }

        delete m_tempDir;
        m_tempDir = nullptr;

        m_stateChanges.clear();
    }

    void testInitialState()
    {
        QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
        QVERIFY(!m_manager->isStarted());
        QVERIFY(m_manager->lastError().isEmpty());
    }

    void testStart()
    {
        bool result = m_manager->start();
        QVERIFY(result);
        QVERIFY(m_manager->isStarted());

        // Should be waiting for card after start
        QCOMPARE(m_manager->currentState(), SessionState::WaitingForCard);

        // Simulate card detection (synchronous in mock)
        m_mockComm->simulateCardDetected("test-card-uid");

        // Now should be in Ready or EmptyKeycard state
        SessionState state = m_manager->currentState();
        QVERIFY(state == SessionState::Ready || state == SessionState::EmptyKeycard);
    }

    void testStartAlreadyStarted()
    {
        m_manager->start();

        bool result = m_manager->start();
        QVERIFY(result);
        QVERIFY(m_manager->lastError().isEmpty());
    }

    void testStop()
    {
        m_manager->start();

        // Simulate card to get into Ready state
        m_mockComm->simulateCardDetected("test-uid");

        m_manager->stop();

        QVERIFY(!m_manager->isStarted());
        QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
    }

    // A client that stops the session (logging out) and moves on must not receive card
    // events of the stopped session. Detection has to be off when stop() returns: card
    // detection that is only queued to stop keeps listening, and an NFC intent arriving
    // meanwhile is reported after the caller moved on.
    void testStopStopsDetectionBeforeReturning()
    {
        auto* backend = new Keycard::Test::MockBackend();
        auto channel = std::make_shared<Keycard::KeycardChannel>(backend);
        auto commandSet = std::make_shared<Keycard::CommandSet>(channel, nullptr,
            [](const QString&) { return QString(); });
        m_mockComm->setCommandSet(commandSet);

        QVERIFY(m_manager->start());
        backend->setState(Keycard::ChannelState::WaitingForCard);

        m_manager->stop();

        // No event processing in between: the stop already reached the channel.
        QCOMPARE(backend->state(), Keycard::ChannelState::Idle);
        m_mockComm->setCommandSet(nullptr);
    }

    // start() queues the detection start to the command set. A stop() that runs before
    // that start is delivered - the client stopping the session while a composite
    // operation started it from a worker - must not be overtaken by it: detection stays
    // off once the queued events are processed.
    void testStopDropsADetectionStartQueuedBeforeIt()
    {
        auto* backend = new Keycard::Test::MockBackend();
        backend->setReconnectWhenWaiting(false);
        auto channel = std::make_shared<Keycard::KeycardChannel>(backend);
        auto commandSet = std::make_shared<Keycard::CommandSet>(channel, nullptr,
            [](const QString&) { return QString(); });
        auto commMgr = std::make_shared<Keycard::CommunicationManager>();
        QVERIFY(commMgr->init(commandSet));
        m_manager->setCommunicationManager(commMgr);

        QVERIFY(m_manager->start());  // queues the detection start
        m_manager->stop();            // before the queued start is delivered
        QCoreApplication::processEvents();
        QCoreApplication::processEvents();

        QCOMPARE(backend->state(), Keycard::ChannelState::Idle);
    }

    // A stop that comes in while a start runs (on a worker) - past its checks, before the
    // communication manager started detection - stops what that start started.
    void testStopDuringAStartStopsWhatItStarted()
    {
        auto* backend = new Keycard::Test::MockBackend();
        backend->setReconnectWhenWaiting(false);
        auto channel = std::make_shared<Keycard::KeycardChannel>(backend);
        auto commandSet = std::make_shared<Keycard::CommandSet>(channel, nullptr,
            [](const QString&) { return QString(); });
        auto commMgr = std::make_shared<PausingCommunicationManager>();
        QVERIFY(commMgr->init(commandSet));
        m_manager->setCommunicationManager(commMgr);

        commMgr->armed = true;
        std::unique_ptr<QThread> starter(QThread::create([this]() { m_manager->start(); }));
        starter->start();
        QVERIFY(commMgr->paused.tryAcquire(1, 5000));

        std::unique_ptr<QThread> stopper(QThread::create([this]() { m_manager->stopForClient(); }));
        stopper->start();
        QThread::msleep(50);  // the stop waits for the start
        commMgr->release.release();
        while (!starter->isFinished() || !stopper->isFinished()) {
            QCoreApplication::processEvents();
            QThread::msleep(1);
        }
        for (int i = 0; i < 10; ++i) {
            QCoreApplication::processEvents();
        }

        QVERIFY(!m_manager->isStarted());
        QCOMPARE(backend->state(), Keycard::ChannelState::Idle);
    }

    // A stop on a worker waits for the GUI thread (where the command set lives) to stop
    // detection. A client stop on the GUI meanwhile must neither wait for that worker nor
    // return before detection is off.
    void testClientStopOnTheGuiWhileAWorkerStopWaitsForIt()
    {
        auto* backend = new Keycard::Test::MockBackend();
        backend->setReconnectWhenWaiting(false);
        auto channel = std::make_shared<Keycard::KeycardChannel>(backend);
        auto commandSet = std::make_shared<Keycard::CommandSet>(channel, nullptr,
            [](const QString&) { return QString(); });
        auto commMgr = std::make_shared<StopNotifyingCommunicationManager>();
        QVERIFY(commMgr->init(commandSet));
        m_manager->setCommunicationManager(commMgr);

        QVERIFY(m_manager->start());
        QTRY_COMPARE(backend->state(), Keycard::ChannelState::WaitingForCard);

        std::unique_ptr<QThread> worker(QThread::create([this]() { m_manager->stop(); }));
        worker->start();
        QVERIFY(commMgr->stopping.tryAcquire(1, 5000));
        QThread::msleep(20);  // the worker posted its native stop and waits for this thread

        QElapsedTimer elapsed;
        elapsed.start();
        m_manager->stopForClient();
        QVERIFY2(elapsed.elapsed() < 500, "the client stop waited for the worker");
        QCOMPARE(backend->state(), Keycard::ChannelState::Idle);

        while (!worker->isFinished()) {
            QCoreApplication::processEvents();
            QThread::msleep(1);
        }
    }

    // A composite operation that began before the client stopped the session can't start
    // detection afterwards; one that begins after it can.
    void testOperationBegunBeforeAClientStopDoesNotStart()
    {
        m_manager->stopForClient();
        QVERIFY(!m_manager->start(false, QString(), quint64(0)));
        QVERIFY(!m_manager->isStarted());

        QVERIFY(m_manager->start(false, QString(), quint64(1)));
        QVERIFY(m_manager->isStarted());
    }

    void testStopNotStarted()
    {
        m_manager->stop();
        QVERIFY(!m_manager->isStarted());
    }

    void testStateTransitions()
    {
        m_stateChanges.clear();

        m_manager->start();

        // Should transition to WaitingForCard
        QVERIFY(m_stateChanges.size() >= 1);
        QCOMPARE(m_stateChanges.last().first, SessionState::WaitingForCard);

        // Simulate card detected
        m_mockComm->simulateCardDetected("test-uid");

        // Should have transitioned to Ready or EmptyKeycard
        SessionState lastState = m_stateChanges.last().first;
        QVERIFY(lastState == SessionState::Ready || lastState == SessionState::EmptyKeycard);

        m_manager->stop();

        // Should transition back to UnknownReaderState
        QCOMPARE(m_stateChanges.last().first, SessionState::UnknownReaderState);
    }

    void testGetStatus()
    {
        SessionManager::Status status = m_manager->getStatus();

        QVERIFY(!status.state.isEmpty());
        QCOMPARE(status.state, sessionStateToString(m_manager->currentState()));

        QVERIFY(status.keycardInfo == nullptr);
        QVERIFY(status.keycardStatus == nullptr);
        QVERIFY(status.metadata == nullptr);
    }

    void testStateStrings()
    {
        QCOMPARE(sessionStateToString(SessionState::UnknownReaderState), QString("unknown-reader-state"));
        QCOMPARE(sessionStateToString(SessionState::NoReadersFound), QString("no-readers-found"));
        QCOMPARE(sessionStateToString(SessionState::WaitingForReader), QString("waiting-for-reader"));
        QCOMPARE(sessionStateToString(SessionState::WaitingForCard), QString("waiting-for-card"));
        QCOMPARE(sessionStateToString(SessionState::ConnectingCard), QString("connecting-card"));
        QCOMPARE(sessionStateToString(SessionState::EmptyKeycard), QString("empty-keycard"));
        QCOMPARE(sessionStateToString(SessionState::Ready), QString("ready"));
        QCOMPARE(sessionStateToString(SessionState::Authorized), QString("authorized"));
        QCOMPARE(sessionStateToString(SessionState::BlockedPIN), QString("blocked-pin"));
        QCOMPARE(sessionStateToString(SessionState::BlockedPUK), QString("blocked-puk"));
        QCOMPARE(sessionStateToString(SessionState::PairingError), QString("pairing-error"));
        QCOMPARE(sessionStateToString(SessionState::NoAvailablePairingSlots), QString("no-available-pairing-slots"));
        QCOMPARE(sessionStateToString(SessionState::UntrustedKeycard), QString("untrusted-keycard"));
    }

    void testLastError()
    {
        QVERIFY(m_manager->lastError().isEmpty());

        bool result = m_manager->authorize("123456");
        QVERIFY(!result);

        QVERIFY(!m_manager->lastError().isEmpty());
    }

    void testOperationWithoutStart()
    {
        QVERIFY(!m_manager->initialize("123456", "123456123456", ""));
        QVERIFY(!m_manager->authorize("123456"));
        QVERIFY(!m_manager->changePIN("654321"));
        QVERIFY(!m_manager->changePUK("098765432109"));
        QVERIFY(!m_manager->unblockPIN("123456123456", "654321"));
        QVERIFY(!m_manager->factoryReset());

        QString keyUID = m_manager->loadMnemonic("test mnemonic", "");
        QVERIFY(keyUID.isEmpty());
    }

    void testStateChangedSignal()
    {
        m_stateChanges.clear();

        m_manager->start();

        // Should have state change to WaitingForCard
        QVERIFY(m_stateChanges.size() >= 1);

        // Simulate card
        m_mockComm->simulateCardDetected("test-uid");

        // Should have more state changes
        QVERIFY(m_stateChanges.size() >= 2);

        // All state changes should be to different states
        for (const auto& change : m_stateChanges) {
            QVERIFY(change.first != change.second);
        }
    }

    // ========================================================================
    // Threading and CommunicationManager Integration Tests (New)
    // ========================================================================

    void testConcurrentStateAccess()
    {
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        // Multiple threads reading state concurrently - validates thread safety
        std::atomic<int> readCount{0};
        QList<QFuture<void>> futures;

        for (int i = 0; i < 5; i++) {
            auto future = QtConcurrent::run([this, &readCount]() {
                for (int j = 0; j < 20; j++) {
                    SessionState state = m_manager->currentState();
                    Q_UNUSED(state);
                    readCount++;
                }
            });
            futures.append(future);
        }

        for (auto& future : futures) {
            future.waitForFinished();
            QVERIFY(future.isFinished());
        }

        QCOMPARE(readCount.load(), 100);
    }

    void testMultipleStartCalls()
    {
        // Multiple start calls should be idempotent
        for (int i = 0; i < 3; i++) {
            bool result = m_manager->start();
            QVERIFY(result);
        }

        QVERIFY(m_manager->isStarted());
    }

    void testStopDuringOperation()
    {
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        // Stop should be safe even during state transitions
        m_manager->stop();

        QVERIFY(!m_manager->isStarted());
    }

    // ========================================================================
    // Enhanced Tests Using MockCommunicationManager (New)
    // ========================================================================

    void testCardRemovedDuringSession()
    {
        // Start and detect card
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        QVERIFY(m_manager->currentState() == SessionState::Ready ||
                m_manager->currentState() == SessionState::EmptyKeycard);

        // Simulate card removal
        m_mockComm->simulateCardRemoved();

        // Should transition back to WaitingForCard
        QCOMPARE(m_manager->currentState(), SessionState::WaitingForCard);
    }

    void testAuthorizeFailed()
    {
        // Setup card in ready state
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        // Set mock to return failure for next command (authorize = VERIFY_PIN)
        Keycard::CommandResult failureResult =
            Keycard::CommandResult::fromError("Wrong PIN");
        m_mockComm->setNextCommandResult(failureResult);

        // Queue result for GetStatusCommand (called by authorize to refresh app status)
        QVariantMap statusData;
        statusData["pinRetryCount"] = 2;
        statusData["pukRetryCount"] = 5;
        m_mockComm->setNextCommandResult(Keycard::CommandResult::fromSuccess(statusData));

        // Try to authorize with wrong PIN
        bool result = m_manager->authorize("wrong-pin");

        QVERIFY(!result);
        QVERIFY(!m_manager->lastError().isEmpty());
    }

    void testAuthorizeSuccess()
    {
        // Setup card in ready state
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        // Set mock to return success for VERIFY_PIN command
        Keycard::CommandResult successResult = Keycard::CommandResult::fromSuccess();
        m_mockComm->setNextCommandResult(successResult);

        // Queue result for GetStatusCommand (called by authorize to refresh app status)
        QVariantMap statusData;
        statusData["pinRetryCount"] = 3;
        statusData["pukRetryCount"] = 5;
        m_mockComm->setNextCommandResult(Keycard::CommandResult::fromSuccess(statusData));

        // Authorize should succeed
        bool result = m_manager->authorize("123456");

        QVERIFY(result);
        QCOMPARE(m_manager->currentState(), SessionState::Authorized);
    }

    void testCardRemovalDuringCompositeEmitsCancelledOnce()
    {
        m_mockComm->setAutoDetectUid(QStringLiteral("test-uid"));

        QVariantMap statusData;
        statusData.insert(QStringLiteral("pinRetryCount"), 3);
        statusData.insert(QStringLiteral("pukRetryCount"), 5);
        m_mockComm->setDefaultCommandResult(Keycard::CommandResult::fromSuccess(statusData));

        m_stateChanges.clear();
        bool removalSimulated = false;
        m_mockComm->setAfterCommandHook([this, &removalSimulated](const QString& name) {
            if (removalSimulated || name != QLatin1String("GET_STATUS")) {
                return;
            }
            removalSimulated = true;
            m_mockComm->simulateCardRemoved();
            m_mockComm->simulateCardRemoved();
        });

        m_manager->login(QString(), QStringLiteral("123456"));

        int cancelledTransitions = 0;
        for (const auto& change : m_stateChanges) {
            if (change.first == SessionState::Cancelled) {
                cancelledTransitions++;
            }
        }
        QCOMPARE(cancelledTransitions, 1);
    }

    void testLoginKeepsCardRemovedAfterAuthorizeYank()
    {
        m_mockComm->setAutoDetectUid(QStringLiteral("test-uid"));

        QVariantMap statusData;
        statusData.insert(QStringLiteral("pinRetryCount"), 3);
        statusData.insert(QStringLiteral("pukRetryCount"), 5);
        m_mockComm->setDefaultCommandResult(Keycard::CommandResult::fromSuccess(statusData));

        m_mockComm->setAfterCommandHook([this](const QString& name) {
            if (name == QLatin1String("GET_STATUS")) {
                m_mockComm->simulateCardRemoved();
            }
        });

        const SessionManager::RecoverKeys keys = m_manager->login(
            QString(), QStringLiteral("123456"));
        Q_UNUSED(keys);

        QCOMPARE(m_manager->lastError(), QStringLiteral("Card removed"));
    }

    void testMultipleCardDetections()
    {
        m_manager->start();

        // Detect first card
        m_mockComm->simulateCardDetected("card-1");
        QVERIFY(m_manager->currentState() == SessionState::Ready ||
                m_manager->currentState() == SessionState::EmptyKeycard);

        // Remove card
        m_mockComm->simulateCardRemoved();
        QCOMPARE(m_manager->currentState(), SessionState::WaitingForCard);

        // Detect second card
        m_mockComm->simulateCardDetected("card-2");
        QVERIFY(m_manager->currentState() == SessionState::Ready ||
                m_manager->currentState() == SessionState::EmptyKeycard);
    }

    void testBatchOperations()
    {
        m_manager->start();
        m_mockComm->simulateCardDetected("test-uid");

        // Authorize first
        m_mockComm->setDefaultCommandResult(Keycard::CommandResult::fromSuccess());
        m_manager->authorize("123456");

        // exportRecoverKeys calls startBatchOperations internally
        // Mock will track this
        int initialBatchCount = m_mockComm->batchOperationCount();

        // Note: exportRecoverKeys would normally require proper key data
        // but with mock we can just verify the batch operation behavior
        // We'll just verify the mock is being called properly
        QVERIFY(initialBatchCount == 0);  // No batch operations yet
    }

    void testDeterministicTiming()
    {
        // One of the key benefits: tests run fast and deterministic
        QElapsedTimer timer;
        timer.start();

        for (int i = 0; i < 10; i++) {
            m_manager->start();
            m_mockComm->simulateCardDetected("test-uid");
            m_manager->stop();
        }

        qint64 elapsed = timer.elapsed();

        // With mock, 10 iterations should take < 100ms
        // (vs 5-10 seconds with real CommunicationManager and waits)
        qDebug() << "StatusKeycardQt::10 iterations took:" << elapsed << "ms";
        QVERIFY(elapsed < 100);  // Should be extremely fast with synchronous mock
    }
};

QTEST_MAIN(TestSessionManager)
#include "test_session_manager.moc"
