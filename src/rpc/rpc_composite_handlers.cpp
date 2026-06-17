#include "rpc_service.h"
#include "../signal_manager.h"
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
    QString xPubPath = params["xPubPath"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::LoginKeys keys = m_sessionManager->login(keyUidWithout0x, pin, xPubPath, logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
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
    QString metadataName = params["metadataName"].toString();
    QString keycardUid = remove0xPrefix(params["keycardUid"].toString());
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

    QStringList metadataPaths;
    if (params.contains("metadataPaths") && params["metadataPaths"].isArray()) {
        const QJsonArray pathsArray = params["metadataPaths"].toArray();
        for (const QJsonValue& val : pathsArray) {
            metadataPaths.append(val.toString());
        }
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::RecoverKeys keys = m_sessionManager->recover(pin, puk, pairingPassword, mnemonic,
        metadataName, metadataPaths, logEnabled, logFilePath, keycardUid);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, recoverKeysToJson(keys));
}

QJsonObject RpcService::handleLoad(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString pin = params["pin"].toString();
    QString puk = params["puk"].toString();
    QString pairingPassword = params["pairingPassword"].toString();
    QString mnemonic = params["mnemonic"].toString();
    QString metadataName = params["metadataName"].toString();
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

    QStringList metadataPaths;
    if (params.contains("metadataPaths") && params["metadataPaths"].isArray()) {
        const QJsonArray pathsArray = params["metadataPaths"].toArray();
        for (const QJsonValue& val : pathsArray) {
            metadataPaths.append(val.toString());
        }
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::RecoverKeys keys = m_sessionManager->load(pin, puk, pairingPassword, mnemonic,
        metadataName, metadataPaths, logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
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
    bool exportMasterAddress = params["exportMasterAddr"].toBool(false);
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
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

    SessionManager::ExportExtendedPublicKeyResult result = m_sessionManager->exportExtendedPublicKey(keyUidWithout0x,
        pin, path, exportMasterAddress, storagePath, logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    const SessionManager::ExtendedPublicKey& key = result.extendedPublicKey;
    QJsonObject keyObj;
    keyObj["address"] = ensure0xPrefix(key.address);
    keyObj["publicKey"] = ensure0xPrefix(key.publicKey);
    keyObj["chainCode"] = ensure0xPrefix(key.chainCode);
    keyObj["xpub"] = key.xpub;

    QJsonObject response;
    response["extendedPublicKey"] = keyObj;
    if (!result.masterKeyAddress.isEmpty()) {
        response["masterKeyAddress"] = ensure0xPrefix(result.masterKeyAddress);
    }

    return createSuccessResponse(id, response);
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
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
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
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
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

QJsonObject RpcService::handleChangeKeycardPIN(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    QString newPin = params["newPin"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    QString keycardUid = remove0xPrefix(params["keycardUid"].toString());

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    if (newPin.length() != PinLength) {
        return createErrorResponse(id, -32602, "New PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    bool success = m_sessionManager->changeKeycardPIN(keyUidWithout0x, pin, newPin, storagePath, logEnabled, logFilePath,
        keycardUid);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleChangeKeycardPUK(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    QString newPuk = params["newPuk"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    QString keycardUid = remove0xPrefix(params["keycardUid"].toString());

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    if (newPuk.length() != PukLength) {
        return createErrorResponse(id, -32602, "New PUK must be " + QString::number(PukLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    bool success = m_sessionManager->changeKeycardPUK(keyUidWithout0x, pin, newPuk, storagePath, logEnabled, logFilePath,
        keycardUid);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleUnblockUsingPUK(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString puk = params["puk"].toString();
    QString newPin = params["newPin"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    QString keycardUid = remove0xPrefix(params["keycardUid"].toString());

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (puk.length() != PukLength) {
        return createErrorResponse(id, -32602, "PUK must be " + QString::number(PukLength) + " digits");
    }

    if (newPin.length() != PinLength) {
        return createErrorResponse(id, -32602, "New PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    bool success = m_sessionManager->unblockUsingPUK(keyUidWithout0x, puk, newPin, storagePath, logEnabled, logFilePath,
        keycardUid);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleGetKeycardMetadata(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString pin = params["pin"].toString();  // Optional — if provided, resolves wallet addresses/publicKeys
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    if (!pin.isEmpty() && pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::Metadata metadata = m_sessionManager->getKeycardMetadata(pin, storagePath, logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonObject meta;
    meta["name"] = metadata.name;

    QJsonArray walletsArray;
    for (const auto& wallet : metadata.wallets) {
        QJsonObject w;
        w["path"] = wallet.path;
        w["address"] = wallet.address;
        w["publicKey"] = wallet.publicKey;
        walletsArray.append(w);
    }
    meta["wallets"] = walletsArray;

    return createSuccessResponse(id, meta);
}

QJsonObject RpcService::handleStoreKeycardMetadata(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString pin = params["pin"].toString();
    QString name = params["name"].toString();
    QJsonArray pathsArray = params["paths"].toArray();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    QStringList paths;
    for (const QJsonValue& val : pathsArray) {
        paths.append(val.toString());
    }

    bool success = m_sessionManager->storeKeycardMetadata(pin, name, paths, storagePath, logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleSign(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    QString keyUid = params["keyUid"].toString();
    QString pin = params["pin"].toString();
    QString txHash = params["txHash"].toString();
    QString path = params["path"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    const QString keyUidWithout0x = remove0xPrefix(keyUid);
    if (!keyUidWithout0x.isEmpty() && keyUidWithout0x.length() != KeyUidLengthWithout0x) {
        return createErrorResponse(id, -32602, "keyUid must be " + QString::number(KeyUidLengthWithout0x) + " characters in hex, without 0x prefix");
    }

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    const QString txHashClean = remove0xPrefix(txHash);
    if (txHashClean.length() != 64) {
        return createErrorResponse(id, -32602, "txHash must be 32 bytes (64 hex characters)");
    }

    if (path.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: path");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    SessionManager::SignResult result = m_sessionManager->sign(keyUidWithout0x, pin, txHashClean, path, storagePath,
        logEnabled, logFilePath);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonObject sigObj;
    sigObj["r"] = ensure0xPrefix(result.r);
    sigObj["s"] = ensure0xPrefix(result.s);
    sigObj["v"] = result.v;

    return createSuccessResponse(id, sigObj);
}

QJsonObject RpcService::handleFactoryResetKeycard(quint64 id, const QJsonObject& params) {
    QString storagePath = params["storageFilePath"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();
    QString keycardUid = remove0xPrefix(params["keycardUid"].toString());

    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "Missing required parameter: storageFilePath");
    }

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    bool success = m_sessionManager->factoryResetKeycard(storagePath, logEnabled, logFilePath, keycardUid);
    SignalManager::instance()->emitStatusChanged(m_sessionManager->getStatus());
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

} // namespace StatusKeycard
