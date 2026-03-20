#include "rpc_service.h"
#include "../utils/constants.h"
#include "../utils/common.h"
#include "../session/session_manager.h"
#include <QJsonObject>
#include <QJsonArray>

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

QJsonObject RpcService::handleExportExtendedPublicKey(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    QString path = params["path"].toString();
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

    if (path.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: path");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::ExtendedPublicKey key = m_sessionManager->exportExtendedPublicKey(keyUidWithout0x, pin, path, storagePath, logEnabled, logFilePath);
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonObject keyObj;
    keyObj["address"] = ensure0xPrefix(key.address);
    keyObj["publicKey"] = ensure0xPrefix(key.publicKey);
    keyObj["chainCode"] = ensure0xPrefix(key.chainCode);
    keyObj["xpub"] = key.xpub;

    return createSuccessResponse(id, keyObj);
}

// exports private key only if the derivation path is under `m/43'/60'/1581'/0'/` tree
// in case of multiple derivation paths, the ordrer in the response is the same as the order in the input paths
QJsonObject RpcService::handleExportPublicKey(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    bool exportPrivate = params["exportPrivate"].toBool(false);
    bool exportMasterAddress = params["exportMasterAddress"].toBool(false);
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

    QStringList paths;
    bool inputWasArray = false;
    if (params.contains("paths") && params["paths"].isArray()) {
        inputWasArray = true;
        const QJsonArray pathArray = params["paths"].toArray();
        for (const QJsonValue& val : pathArray) {
            paths.append(val.toString());
        }
    } else if (params.contains("path")) {
        paths.append(params["path"].toString());
    } else {
        return createErrorResponse(id, -32602, "Missing required parameter: path or paths");
    }

    if (paths.isEmpty()) {
        return createErrorResponse(id, -32602, "path or paths must not be empty");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::ExportPublicKeyResult result = m_sessionManager->exportPublicKey(keyUidWithout0x, pin, paths,
        exportPrivate, exportMasterAddress, storagePath, logEnabled, logFilePath);

    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonObject response;
    if (!result.masterKeyAddress.isEmpty()) {
        response["masterKeyAddress"] = ensure0xPrefix(result.masterKeyAddress);
    }
    if (inputWasArray) {
        QJsonArray exportedArray;
        for (const auto& kp : result.exportedKeys) {
            QJsonObject keyObj;
            keyObj["address"] = ensure0xPrefix(kp.address);
            keyObj["publicKey"] = ensure0xPrefix(kp.publicKey);
            if (!kp.privateKey.isEmpty()) {
                keyObj["privateKey"] = ensure0xPrefix(kp.privateKey);
            }
            if (!kp.chainCode.isEmpty()) {
                keyObj["chainCode"] = ensure0xPrefix(kp.chainCode);
            }
            exportedArray.append(keyObj);
        }
        response["exportedKeys"] = exportedArray;
    } else {
        if (result.exportedKeys.isEmpty()) {
            response["exportedKey"] = QJsonObject();
        } else {
            const auto& kp = result.exportedKeys.first();
            QJsonObject keyObj;
            keyObj["address"] = ensure0xPrefix(kp.address);
            keyObj["publicKey"] = ensure0xPrefix(kp.publicKey);
            if (!kp.privateKey.isEmpty()) {
                keyObj["privateKey"] = ensure0xPrefix(kp.privateKey);
            }
            if (!kp.chainCode.isEmpty()) {
                keyObj["chainCode"] = ensure0xPrefix(kp.chainCode);
            }
            response["exportedKey"] = keyObj;
        }
    }

    return createSuccessResponse(id, response);
}

} // namespace StatusKeycard
