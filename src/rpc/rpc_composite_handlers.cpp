#include "rpc_service.h"
#include "../utils/constants.h"
#include "../utils/common.h"
#include "../session/session_manager.h"
#include <QJsonObject>

namespace StatusKeycard {

QJsonObject RpcService::handleLogin(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::LoginKeys keys = m_sessionManager->login(keyUidWithout0x, pin, logEnabled, logFilePath);
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, loginKeysToJson(keys));
}

QJsonObject RpcService::handleRecover(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString pin = params["pin"].toString();
    QString puk = params["puk"].toString();
    QString pairingPassword = params["pairingPassword"].toString();
    QString mnemonic = params["mnemonic"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    if (puk.length() != PukLength) {
        return createErrorResponse(id, -32602, "PUK must be " + QString::number(PukLength) + " digits");
    }

    if (mnemonic.isEmpty()) {
        return createErrorResponse(id, -32602, "mnemonic is required");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::RecoverKeys keys = m_sessionManager->recover(pin, puk, pairingPassword, mnemonic, logEnabled, logFilePath);
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, recoverKeysToJson(keys));
}

} // namespace StatusKeycard
