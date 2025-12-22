#ifndef MOCK_COMMUNICATION_MANAGER_H
#define MOCK_COMMUNICATION_MANAGER_H

#include <keycard-qt/i_communication_manager.h>
#include <keycard-qt/types.h>
#include <keycard-qt/card_command.h>
#include <QObject>
#include <memory>
#include <queue>

namespace StatusKeycardTest {

/**
 * @brief Mock CommunicationManager for testing without real hardware or threading
 * 
 * This mock eliminates:
 * - Communication threads
 * - Event loop dependencies
 * - QTimer timing issues
 * - Channel/backend infrastructure
 * - Race conditions
 * 
 * It provides deterministic, synchronous behavior for unit testing SessionManager logic.
 */
class MockCommunicationManager : public Keycard::ICommunicationManager {
    Q_OBJECT
    
public:
    explicit MockCommunicationManager(QObject* parent = nullptr);
    ~MockCommunicationManager() override;
    
    // ========================================================================
    // Test Control Methods
    // ========================================================================
    
    /**
     * @brief Simulate card detection
     * @param uid Card UID
     * 
     * This will emit cardInitialized signal asynchronously (via QMetaObject::invokeMethod).
     * Call QCoreApplication::processEvents() after this to deliver the signal.
     */
    void simulateCardDetected(const QString& uid);
    
    /**
     * @brief Simulate card removal
     * 
     * This will emit cardLost signal asynchronously.
     */
    void simulateCardRemoved();
    
    /**
     * @brief Set mock application info to be returned
     */
    void setMockApplicationInfo(const Keycard::ApplicationInfo& info);
    
    /**
     * @brief Set mock application status to be returned
     */
    void setMockApplicationStatus(const Keycard::ApplicationStatus& status);
    
    /**
     * @brief Set the result for the next executeCommandSync call
     * 
     * Commands are processed in FIFO order. If no result is queued,
     * a default success result is returned.
     */
    void setNextCommandResult(const Keycard::CommandResult& result);
    
    /**
     * @brief Set a default command result that will be used when no specific result is queued
     */
    void setDefaultCommandResult(const Keycard::CommandResult& result);
    
    /**
     * @brief Clear all queued command results
     */
    void clearCommandResults();
    
    /**
     * @brief Get the last executed command (for verification)
     */
    QString lastCommandName() const { return m_lastCommandName; }
    
    /**
     * @brief Get number of commands executed
     */
    int commandExecutionCount() const { return m_commandExecutionCount; }
    
    /**
     * @brief Reset statistics
     */
    void resetStatistics();
    
    // ========================================================================
    // ICommunicationManager Interface Implementation
    // ========================================================================
    
    bool startDetection() override;
    void stopDetection() override;
    Keycard::CommandResult executeCommandSync(std::unique_ptr<Keycard::CardCommand> cmd, int timeoutMs = -1) override;
    Keycard::ApplicationInfo applicationInfo() const override;
    Keycard::ApplicationStatus applicationStatus() const override;
    void startBatchOperations() override;
    void endBatchOperations() override;
    std::shared_ptr<Keycard::CommandSet> commandSet() const override { return nullptr; }
    
    // ========================================================================
    // Verification Methods
    // ========================================================================
    
    bool isDetectionStarted() const { return m_detectionStarted; }
    int batchOperationCount() const { return m_batchOperationCount; }
    
private:
    // State
    bool m_detectionStarted;
    int m_batchOperationCount;
    
    // Mock data
    Keycard::ApplicationInfo m_mockAppInfo;
    Keycard::ApplicationStatus m_mockAppStatus;
    QString m_currentCardUID;
    
    // Command results
    std::queue<Keycard::CommandResult> m_commandResults;
    Keycard::CommandResult m_defaultCommandResult;
    bool m_hasDefaultResult;
    
    // Statistics
    QString m_lastCommandName;
    int m_commandExecutionCount;
};

} // namespace StatusKeycardTest

#endif // MOCK_COMMUNICATION_MANAGER_H
