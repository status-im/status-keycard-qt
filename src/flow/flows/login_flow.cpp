#include "login_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/types.h>
#include <QDebug>

namespace StatusKeycard {

// BIP44 paths (matching status-keycard-go exactly)
const QString LoginFlow::EIP1581_PATH = "m/43'/60'/1581'";
const QString LoginFlow::WHISPER_PATH = "m/43'/60'/1581'/0'/0";
const QString LoginFlow::ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";

LoginFlow::LoginFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::Login, params, parent)
{
}

LoginFlow::~LoginFlow()
{
}

QJsonObject LoginFlow::execute()
{
    qDebug() << "LoginFlow: Starting execution";
    
    // 1. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "LoginFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 2. Check card has keys
    if (!requireKeys()) {
        qWarning() << "LoginFlow: Card has no keys";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "no-keys";
        return error;
    }
    
    // 3. Open secure channel and authenticate (verify PIN)
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // 4. Export encryption key (with private key)
    qDebug() << "LoginFlow: Exporting encryption key...";
    QJsonObject encKey = exportKey(ENCRYPTION_PATH, true);
    if (encKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export encryption key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-encryption-failed";
        return error;
    }
    
    // 5. Export whisper key (with private key)
    qDebug() << "LoginFlow: Exporting whisper key...";
    QJsonObject whisperKey = exportKey(WHISPER_PATH, true);
    if (whisperKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export whisper key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-whisper-failed";
        return error;
    }
    
    // 6. Build result
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::ENC_KEY] = encKey;
    result[FlowParams::WHISPER_KEY] = whisperKey;
    
    qDebug() << "LoginFlow: Execution completed successfully";
    return result;
}

QJsonObject LoginFlow::exportKey(const QString& path, bool includePrivate)
{
    // Check if cancelled
    if (isCancelled()) {
        qWarning() << "LoginFlow: Export cancelled";
        return QJsonObject();
    }
    
    // derive=true, makeCurrent=(path=="m"), exportType=private or public
    bool makeCurrent = (path == "m"); // Only for master path
    uint8_t exportType = includePrivate ? 
        Keycard::APDU::P2ExportKeyPrivateAndPublic :
        Keycard::APDU::P2ExportKeyPublicOnly;
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "LoginFlow: CommunicationManager not available";
        return QJsonObject();
    }
    
    auto cmd = std::make_unique<Keycard::ExportKeyCommand>(true, makeCurrent, path, exportType);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        qCritical() << "LoginFlow: Export key failed:" << result.error;
        return QJsonObject();
    }
    
    // Extract key data from result
    QVariantMap data = result.data.toMap();
    QByteArray keyData = data["keyData"].toByteArray();
    
    qDebug() << "LoginFlow::exportKey() - Export SUCCESS for path:" << path;
    
    // Parse and validate key data
    if (keyData.isEmpty()) {
        qCritical() << "LoginFlow: Export key returned empty data!";
        return QJsonObject();
    }
    
    // Parse TLV-encoded key data
    QByteArray publicKey, privateKey;
    if (!parseExportedKey(keyData, publicKey, privateKey)) {
        qCritical() << "LoginFlow: Failed to parse exported key data";
        return QJsonObject();
    }
    
    // Build result JSON
    QJsonObject keyPair;
    keyPair["publicKey"] = QString("0x") + publicKey.toHex();
    keyPair["address"] = FlowBase::publicKeyToAddress(publicKey);
    
    if (includePrivate && !privateKey.isEmpty()) {
        keyPair["privateKey"] = QString("0x") + privateKey.toHex();
    } else if (includePrivate) {
        qCritical() << "LoginFlow: Private key requested but not found in exported data";
        return QJsonObject();
    }
    
    qDebug() << "LoginFlow::exportKey() - Successfully exported key at path:" << path;
    return keyPair;
}

} // namespace StatusKeycard

