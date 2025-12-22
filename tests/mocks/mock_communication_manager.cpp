#include "mock_communication_manager.h"
#include <QDebug>
#include <QMetaObject>
#include <QCoreApplication>

namespace StatusKeycardTest {

MockCommunicationManager::MockCommunicationManager(QObject* parent)
    : ICommunicationManager(parent)
    , m_detectionStarted(false)
    , m_batchOperationCount(0)
    , m_hasDefaultResult(false)
    , m_commandExecutionCount(0)
{
    // Initialize mock data with sensible defaults
    m_mockAppInfo.installed = true;
    m_mockAppInfo.initialized = true;
    m_mockAppInfo.availableSlots = 3;
    m_mockAppInfo.appVersion = 3;
    m_mockAppInfo.appVersionMinor = 0;
    m_mockAppInfo.instanceUID = QByteArray::fromHex("FEDCBA9876543210FEDCBA9876543210");
    m_mockAppInfo.keyUID = QByteArray::fromHex("0123456789ABCDEF0123456789ABCDEF");
    
    m_mockAppStatus.pinRetryCount = 3;
    m_mockAppStatus.pukRetryCount = 5;
    m_mockAppStatus.keyInitialized = true;
    m_mockAppStatus.valid = true;
    
    qDebug() << "[MockCommunicationManager] Created";
}

MockCommunicationManager::~MockCommunicationManager()
{
    qDebug() << "[MockCommunicationManager] Destroyed";
}

// ============================================================================
// Test Control Methods
// ============================================================================

void MockCommunicationManager::simulateCardDetected(const QString& uid)
{
    qDebug() << "[MockCommunicationManager] Simulating card detected:" << uid;
    
    m_currentCardUID = uid;
    
    // Create successful initialization result
    Keycard::CardInitializationResult result = 
        Keycard::CardInitializationResult::fromSuccess(uid, m_mockAppInfo, m_mockAppStatus);
    
    // For unit tests, emit synchronously for deterministic behavior
    // Real CommunicationManager emits from its thread, but for tests
    // we want immediate, predictable signal delivery
    qDebug() << "[MockCommunicationManager] Emitting cardInitialized signal";
    emit cardInitialized(result);
}

void MockCommunicationManager::simulateCardRemoved()
{
    qDebug() << "[MockCommunicationManager] Simulating card removed";
    
    m_currentCardUID.clear();
    
    // For unit tests, emit synchronously for deterministic behavior
    qDebug() << "[MockCommunicationManager] Emitting cardLost signal";
    emit cardLost();
}

void MockCommunicationManager::setMockApplicationInfo(const Keycard::ApplicationInfo& info)
{
    m_mockAppInfo = info;
    qDebug() << "[MockCommunicationManager] Application info updated";
}

void MockCommunicationManager::setMockApplicationStatus(const Keycard::ApplicationStatus& status)
{
    m_mockAppStatus = status;
    qDebug() << "[MockCommunicationManager] Application status updated";
}

void MockCommunicationManager::setNextCommandResult(const Keycard::CommandResult& result)
{
    m_commandResults.push(result);
    qDebug() << "[MockCommunicationManager] Queued command result, queue size:" << m_commandResults.size();
}

void MockCommunicationManager::setDefaultCommandResult(const Keycard::CommandResult& result)
{
    m_defaultCommandResult = result;
    m_hasDefaultResult = true;
    qDebug() << "[MockCommunicationManager] Default command result set";
}

void MockCommunicationManager::clearCommandResults()
{
    while (!m_commandResults.empty()) {
        m_commandResults.pop();
    }
    qDebug() << "[MockCommunicationManager] Command results cleared";
}

void MockCommunicationManager::resetStatistics()
{
    m_lastCommandName.clear();
    m_commandExecutionCount = 0;
    qDebug() << "[MockCommunicationManager] Statistics reset";
}

// ============================================================================
// ICommunicationManager Interface Implementation
// ============================================================================

bool MockCommunicationManager::startDetection()
{
    qDebug() << "[MockCommunicationManager] startDetection() called";
    m_detectionStarted = true;
    return true;
}

void MockCommunicationManager::stopDetection()
{
    qDebug() << "[MockCommunicationManager] stopDetection() called";
    m_detectionStarted = false;
}

Keycard::CommandResult MockCommunicationManager::executeCommandSync(
    std::unique_ptr<Keycard::CardCommand> cmd, int timeoutMs)
{
    Q_UNUSED(timeoutMs);
    
    if (!cmd) {
        qWarning() << "[MockCommunicationManager] executeCommandSync called with null command";
        return Keycard::CommandResult::fromError("Null command");
    }
    
    m_lastCommandName = cmd->name();
    m_commandExecutionCount++;
    
    qDebug() << "[MockCommunicationManager] executeCommandSync:" << m_lastCommandName 
             << "count:" << m_commandExecutionCount;
    
    // Return next queued result, or default result, or generic success
    Keycard::CommandResult result;
    
    if (!m_commandResults.empty()) {
        result = m_commandResults.front();
        m_commandResults.pop();
        qDebug() << "[MockCommunicationManager] Returning queued result, remaining:" 
                 << m_commandResults.size();
    } else if (m_hasDefaultResult) {
        result = m_defaultCommandResult;
        qDebug() << "[MockCommunicationManager] Returning default result";
    } else {
        // Return success with no data by default
        result = Keycard::CommandResult::fromSuccess();
        qDebug() << "[MockCommunicationManager] Returning generic success";
    }
    
    return result;
}

Keycard::ApplicationInfo MockCommunicationManager::applicationInfo() const
{
    return m_mockAppInfo;
}

Keycard::ApplicationStatus MockCommunicationManager::applicationStatus() const
{
    return m_mockAppStatus;
}

void MockCommunicationManager::startBatchOperations()
{
    m_batchOperationCount++;
    qDebug() << "[MockCommunicationManager] startBatchOperations, count:" << m_batchOperationCount;
}

void MockCommunicationManager::endBatchOperations()
{
    if (m_batchOperationCount > 0) {
        m_batchOperationCount--;
    }
    qDebug() << "[MockCommunicationManager] endBatchOperations, count:" << m_batchOperationCount;
}

} // namespace StatusKeycardTest
