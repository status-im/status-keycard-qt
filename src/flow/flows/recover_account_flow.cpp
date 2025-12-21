#include "recover_account_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/types.h>
#include <QDebug>

namespace StatusKeycard {

// BIP44 paths (matching status-keycard-go exactly)
const QString RecoverAccountFlow::EIP1581_PATH = "m/43'/60'/1581'";
const QString RecoverAccountFlow::WHISPER_PATH = "m/43'/60'/1581'/0'/0";
const QString RecoverAccountFlow::ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";
const QString RecoverAccountFlow::WALLET_ROOT_PATH = "m/44'/60'/0'";
const QString RecoverAccountFlow::WALLET_PATH = "m/44'/60'/0'/0";
const QString RecoverAccountFlow::MASTER_PATH = "m";

RecoverAccountFlow::RecoverAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::RecoverAccount, params, parent)
{
}

RecoverAccountFlow::~RecoverAccountFlow()
{
}

QJsonObject RecoverAccountFlow::execute()
{
    qDebug() << "RecoverAccountFlow: Starting execution";
    
    // 1. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "RecoverAccountFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 2. Check card has keys
    if (!requireKeys()) {
        qWarning() << "RecoverAccountFlow: Card has no keys";
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
    
    // Start batch operations to keep channel open during all 6 exports
    auto commMgr = communicationManager();
    if (commMgr) {
        commMgr->startBatchOperations();
    }
    
    // RAII guard ensures batch operations are ended on all exit paths
    auto batchGuard = [commMgr](void*) {
        if (commMgr) {
            commMgr->endBatchOperations();
        }
    };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);
    
    // 6. Export encryption key (with private key) - FIRST to match status-keycard-go order
    qDebug() << "RecoverAccountFlow: Exporting encryption key...";
    QJsonObject encKey = exportKey(ENCRYPTION_PATH, true);
    if (encKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export encryption key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-encryption-failed";
        return error;
    }
    
    // 7. Export whisper key (with private key) - SECOND to match status-keycard-go order
    qDebug() << "RecoverAccountFlow: Exporting whisper key...";
    QJsonObject whisperKey = exportKey(WHISPER_PATH, true);
    if (whisperKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export whisper key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-whisper-failed";
        return error;
    }
    
    // 8. Export EIP1581 key (public only)
    qDebug() << "RecoverAccountFlow: Exporting EIP1581 key...";
    QJsonObject eip1581Key = exportKey(EIP1581_PATH, false);
    if (eip1581Key.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export EIP1581 key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-eip1581-failed";
        return error;
    }
    
    // 9. Export wallet root key (extended public - for now just public)
    qDebug() << "RecoverAccountFlow: Exporting wallet root key...";
    QJsonObject walletRootKey = exportKey(WALLET_ROOT_PATH, false);
    if (walletRootKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export wallet root key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-wallet-root-failed";
        return error;
    }
    
    // 10. Export wallet key (public only)
    qDebug() << "RecoverAccountFlow: Exporting wallet key...";
    QJsonObject walletKey = exportKey(WALLET_PATH, false);
    if (walletKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export wallet key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-wallet-failed";
        return error;
    }
    
    // 11. Export master key (public only)
    qDebug() << "RecoverAccountFlow: Exporting master key...";
    QJsonObject masterKey = exportKey(MASTER_PATH, false);
    if (masterKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export master key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-master-failed";
        return error;
    }
    
    // 12. Build result
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::ENC_KEY] = encKey;
    result[FlowParams::WHISPER_KEY] = whisperKey;
    result[FlowParams::EIP1581_KEY] = eip1581Key;
    result[FlowParams::WALLET_ROOT_KEY] = walletRootKey;
    result[FlowParams::WALLET_KEY] = walletKey;
    result[FlowParams::MASTER_KEY] = masterKey;
    
    qDebug() << "RecoverAccountFlow: Execution completed successfully";
    return result;
}

QJsonObject RecoverAccountFlow::exportKey(const QString& path, bool includePrivate)
{   
    // Check if cancelled
    if (isCancelled()) {
        qWarning() << "RecoverAccountFlow: Export cancelled";
        return QJsonObject();
    }
    
    // Export key
    bool makeCurrent = (path == MASTER_PATH); // Only for master path
    uint8_t exportType = includePrivate ? 
        Keycard::APDU::P2ExportKeyPrivateAndPublic :
        Keycard::APDU::P2ExportKeyPublicOnly;
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "RecoverAccountFlow: CommunicationManager not available";
        return QJsonObject();
    }
    
    auto cmd = std::make_unique<Keycard::ExportKeyCommand>(true, makeCurrent, path, exportType);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        qCritical() << "RecoverAccountFlow: Export key failed:" << result.error;
        return QJsonObject();
    }
    
    // Extract key data from result
    QVariantMap data = result.data.toMap();
    QByteArray keyData = data["keyData"].toByteArray();
    
    qDebug() << "RecoverAccountFlow::exportKey() - Export SUCCESS for path:" << path;
    
    // Parse and validate key data
    if (keyData.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Export key returned empty data!";
        return QJsonObject();
    }
    
    // Parse TLV-encoded key data
    QByteArray publicKey, privateKey;
    if (!parseExportedKey(keyData, publicKey, privateKey)) {
        qCritical() << "RecoverAccountFlow: Failed to parse exported key data";
        return QJsonObject();
    }
    
    // Build result JSON
    QJsonObject keyPair;
    keyPair["publicKey"] = QString("0x") + publicKey.toHex();
    keyPair["address"] = FlowBase::publicKeyToAddress(publicKey);
    
    if (includePrivate && !privateKey.isEmpty()) {
        keyPair["privateKey"] = QString("0x") + privateKey.toHex();
    } else if (includePrivate) {
        qCritical() << "RecoverAccountFlow: Private key requested but not found";
        return QJsonObject();
    }
    
    qDebug() << "RecoverAccountFlow: Key exported successfully for path:" << path;
    return keyPair;
}

} // namespace StatusKeycard

