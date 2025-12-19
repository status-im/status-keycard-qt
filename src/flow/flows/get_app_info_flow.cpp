#include "get_app_info_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/types.h>
#include <keycard-qt/keycard_channel.h>
#include <QDebug>

namespace StatusKeycard {

GetAppInfoFlow::GetAppInfoFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::GetAppInfo, params, parent)
{
}

GetAppInfoFlow::~GetAppInfoFlow()
{
}

QJsonObject GetAppInfoFlow::execute()
{
    qDebug() << "GetAppInfoFlow: Starting execution";
    
    // Check if factory reset is requested
    bool factoryReset = params().value("factory reset").toBool();
    if (factoryReset) {
        qDebug() << "GetAppInfoFlow: Factory reset requested";
    }
    
    // 1. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "GetAppInfoFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 2. If factory reset requested, execute it BEFORE checking card state
    if (factoryReset && cardInfo().initialized) {
        qDebug() << "GetAppInfoFlow: Executing factory reset";
        
        // Factory reset does NOT require authentication or PIN
        // (matches status-keycard-go behavior - only requires SELECT)
        
        // Phase 6: CommunicationManager is always available
        auto commMgr = communicationManager();
        if (!commMgr) {
            qCritical() << "GetAppInfoFlow: CommunicationManager not available";
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }
        
        auto cmd = std::make_unique<Keycard::FactoryResetCommand>();
        Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 60000);
        
        if (!result.success) {
            qWarning() << "GetAppInfoFlow: Factory reset failed:" << result.error;
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }
        
        qDebug() << "GetAppInfoFlow: Factory reset SUCCESS";

        // Verify factory reset worked
        if (cardInfo().initialized) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }

        selectKeycard();
    }
    
    // 3. Build basic app info result
    QJsonObject appInfo;
    appInfo[FlowParams::INSTANCE_UID] = cardInfo().instanceUID;
    appInfo[FlowParams::KEY_UID] = cardInfo().keyUID;
    appInfo["initialized"] = cardInfo().initialized;
    appInfo["key-initialized"] = cardInfo().keyInitialized;
    appInfo["available-slots"] = cardInfo().freeSlots;
    appInfo["version"] = QString("%1.%2")
        .arg((cardInfo().version >> 8) & 0xFF)
        .arg(cardInfo().version & 0xFF);
    
    QJsonObject result;
    result[FlowParams::ERROR_KEY] = "ok";
    result[FlowParams::APP_INFO] = appInfo;

    if (!cardInfo().initialized) {
        return result;
    }
    
    // 4. Try to authenticate (to check if paired)
    //    This may pause for pairing password or PIN
    //    If user cancels, that's OK - we just mark as not paired
    if (!verifyPIN(true)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        error[FlowParams::PAIRED] = false;
        return error;
    }
    
    result[FlowParams::PAIRED] = true;
    qDebug() << "GetAppInfoFlow: Execution completed successfully";
    return result;
}

} // namespace StatusKeycard

