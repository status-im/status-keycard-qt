#include "change_puk_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>

namespace StatusKeycard {

ChangePUKFlow::ChangePUKFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePUK, params, parent) {}

QJsonObject ChangePUKFlow::execute()
{
    if (!selectKeycard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPUK = params()[FlowParams::NEW_PUK].toString();
    if (newPUK.isEmpty()) {
        // Request new PUK (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_NEW_PUK, "changing-credentials");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPUK = params()[FlowParams::NEW_PUK].toString();
    }
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "ChangePUKFlow: CommunicationManager not available";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    auto cmd = std::make_unique<Keycard::ChangePUKCommand>(newPUK);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    qDebug() << "ChangePUKFlow: PUK changed successfully";
    return buildCardInfoJson();
}

} // namespace StatusKeycard

