#include "change_pin_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>

namespace StatusKeycard {

ChangePINFlow::ChangePINFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePIN, params, parent) {}

QJsonObject ChangePINFlow::execute()
{
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPIN = params()[FlowParams::NEW_PIN].toString();
    if (newPIN.isEmpty()) {
        // Request new PIN (empty error means normal request, not an error condition)
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "changing-credentials");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPIN = params()[FlowParams::NEW_PIN].toString();
    }
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "ChangePINFlow: CommunicationManager not available";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    auto cmd = std::make_unique<Keycard::ChangePINCommand>(newPIN);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    qDebug() << "ChangePINFlow: PIN changed successfully";
    return buildCardInfoJson();
}

} // namespace StatusKeycard

