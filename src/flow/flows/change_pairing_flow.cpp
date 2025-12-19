#include "change_pairing_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>

namespace StatusKeycard {

ChangePairingFlow::ChangePairingFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePairing, params, parent) {}

QJsonObject ChangePairingFlow::execute()
{
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPairing = params()[FlowParams::NEW_PAIRING].toString();
    if (newPairing.isEmpty()) {
        // Request new pairing code (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_NEW_PAIRING, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPairing = params()[FlowParams::NEW_PAIRING].toString();
    }
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "ChangePairingFlow: CommunicationManager not available";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    auto cmd = std::make_unique<Keycard::ChangePairingCommand>(newPairing);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    qDebug() << "ChangePairingFlow: Pairing changed successfully";
    return buildCardInfoJson();
}

} // namespace StatusKeycard

