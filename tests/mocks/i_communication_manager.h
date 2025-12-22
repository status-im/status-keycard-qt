#ifndef I_COMMUNICATION_MANAGER_H
#define I_COMMUNICATION_MANAGER_H

#include <keycard-qt/types.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/command_set.h>
#include <QObject>
#include <QUuid>
#include <memory>

namespace Keycard {

/**
 * @brief Interface for CommunicationManager
 * 
 * This interface defines the subset of CommunicationManager methods
 * that are used by SessionManager and other components. This allows
 * for easier mocking and testing without requiring the full threading
 * infrastructure of the real CommunicationManager.
 */
class ICommunicationManager {
public:
    virtual ~ICommunicationManager() = default;
    
    // Detection management
    virtual bool startDetection() = 0;
    virtual void stopDetection() = 0;
    
    // Command execution
    virtual CommandResult executeCommandSync(std::unique_ptr<CardCommand> cmd, int timeoutMs = -1) = 0;
    
    // Card information
    virtual ApplicationInfo applicationInfo() const = 0;
    virtual ApplicationStatus applicationStatus() const = 0;
    
    // Batch operations
    virtual void startBatchOperations() = 0;
    virtual void endBatchOperations() = 0;
    
    // Access to command set (may return nullptr for mocks)
    virtual std::shared_ptr<CommandSet> commandSet() const = 0;
};

} // namespace Keycard

// Declare metatype for signals
Q_DECLARE_METATYPE(Keycard::CardInitializationResult)

#endif // I_COMMUNICATION_MANAGER_H

