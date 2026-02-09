#include "rpc_service.h"
#include "../session/session_manager.h"
#include "../storage/file_pairing_storage.h"
#include "keycard-qt/communication_manager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

namespace StatusKeycard {

    const int PinLength = 6; // 6 digits
    const int PukLength = 12; // 12 digits
    const int KeyUidLengthWithout0x = 64; // 64 characters in hex, without 0x prefix

RpcService::RpcService(QObject* parent)
    : QObject(parent)
    , m_sessionManager(std::make_unique<SessionManager>())
{
}

RpcService::~RpcService() = default;

void RpcService::setCommunicationManager(std::shared_ptr<Keycard::ICommunicationManager> commMgr) {
    qDebug() << "StatusKeycardQt::RpcService: Setting CommunicationManager for SessionManager";
    m_commMgr = commMgr;
    if (m_sessionManager) {
        m_sessionManager->setCommunicationManager(commMgr);
    }
}

QString RpcService::processRequest(const QString& requestJson) {
    // Parse the request
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(requestJson.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        QJsonObject errorResp = createErrorResponse(
            0,
            -32700,
            QString("Parse error: %1").arg(parseError.errorString())
        );
        return QJsonDocument(errorResp).toJson(QJsonDocument::Compact);
    }

    QJsonObject request = doc.object();
    quint64 id = request["id"].toVariant().toULongLong();
    QString method = request["method"].toString();
    QJsonValue paramsValue = request["params"];
    QJsonObject params;

    // Params can be an array with a single object, or an empty array
    if (paramsValue.isArray()) {
        QJsonArray paramsArray = paramsValue.toArray();
        if (!paramsArray.isEmpty()) {
            params = paramsArray[0].toObject();
        }
    } else if (paramsValue.isObject()) {
        params = paramsValue.toObject();
    }

    qDebug() << "StatusKeycardQt::RpcService::processRequest() id:" << id;
    qDebug() << "StatusKeycardQt::RpcService::processRequest() method:" << method;
    qDebug() << "StatusKeycardQt::RpcService::processRequest() params:" << QJsonDocument(params).toJson(QJsonDocument::Compact);;

    // Route to handler
    QJsonObject response;

    void startCardOperation();
    void operationCompleted();
    if (method == "keycard.Start") {
        response = handleStart(id, params);
    } else if (method == "keycard.Stop") {
        response = handleStop(id, params);
    } else if (method == "keycard.GetStatus") {
        response = handleGetStatus(id, params);
    } else if (method == "keycard.Initialize") {
        response = handleInitialize(id, params);
    } else if (method == "keycard.Authorize") {
        response = handleAuthorize(id, params);
    } else if (method == "keycard.ChangePIN") {
        response = handleChangePIN(id, params);
    } else if (method == "keycard.ChangePUK") {
        response = handleChangePUK(id, params);
    } else if (method == "keycard.Unblock") {
        response = handleUnblock(id, params);
    } else if (method == "keycard.GenerateMnemonic") {
        response = handleGenerateMnemonic(id, params);
    } else if (method == "keycard.LoadMnemonic") {
        response = handleLoadMnemonic(id, params);
    } else if (method == "keycard.FactoryReset") {
        response = handleFactoryReset(id, params);
    } else if (method == "keycard.GetMetadata") {
        response = handleGetMetadata(id, params);
    } else if (method == "keycard.StoreMetadata") {
        response = handleStoreMetadata(id, params);
    } else if (method == "keycard.ExportLoginKeys") {
        response = handleExportLoginKeys(id, params);
    } else if (method == "keycard.ExportRecoverKeys") {
        response = handleExportRecoverKeys(id, params);
    } else if (method == "keycard.Login") {
        response = handleLogin(id, params);
    } else {
        response = createErrorResponse(id, -32601, QString("Method not found: %1").arg(method));
    }

    return QJsonDocument(response).toJson(QJsonDocument::Compact);
}

QJsonObject RpcService::createSuccessResponse(quint64 id, const QJsonValue& result) {
    QJsonObject response;
    response["jsonrpc"] = "2.0";
    response["id"] = (qint64)id;
    response["result"] = result;
    response["error"] = QJsonValue::Null;
    return response;
}

QJsonObject RpcService::createErrorResponse(quint64 id, int code, const QString& message) {
    QJsonObject error;
    error["code"] = code;
    error["message"] = message;

    QJsonObject response;
    response["jsonrpc"] = "2.0";
    response["id"] = (qint64)id;
    response["result"] = QJsonValue::Null;
    response["error"] = error;
    return response;
}

QJsonObject RpcService::statusToJson(const SessionManager::Status& status) {
    QJsonObject json;
    json["state"] = status.state;

    // keycardInfo (nullable)
    if (status.keycardInfo) {
        QJsonObject info;
        info["installed"] = status.keycardInfo->installed;
        info["initialized"] = status.keycardInfo->initialized;
        info["instanceUID"] = status.keycardInfo->instanceUID;
        info["version"] = status.keycardInfo->version;
        info["availableSlots"] = status.keycardInfo->availableSlots;
        info["keyUID"] = status.keycardInfo->keyUID;
        json["keycardInfo"] = info;
    } else {
        json["keycardInfo"] = QJsonValue::Null;
    }

    // keycardStatus (nullable)
    if (status.keycardStatus) {
        QJsonObject cardStatus;
        cardStatus["remainingAttemptsPIN"] = status.keycardStatus->remainingAttemptsPIN;
        cardStatus["remainingAttemptsPUK"] = status.keycardStatus->remainingAttemptsPUK;
        cardStatus["keyInitialized"] = status.keycardStatus->keyInitialized;
        cardStatus["path"] = status.keycardStatus->path;
        json["keycardStatus"] = cardStatus;
    } else {
        json["keycardStatus"] = QJsonValue::Null;
    }

    // metadata (nullable)
    if (status.metadata) {
        QJsonObject meta;
        meta["name"] = status.metadata->name;

        QJsonArray walletsArray;
        for (const auto& wallet : status.metadata->wallets) {
            QJsonObject w;
            w["path"] = wallet.path;
            w["address"] = wallet.address;
            w["publicKey"] = wallet.publicKey;
            walletsArray.append(w);
        }
        meta["wallets"] = walletsArray;
        json["metadata"] = meta;
    } else {
        json["metadata"] = QJsonValue::Null;
    }

    return json;
}

// ============================================================================
// Common helpers
// ============================================================================

QString remove0xPrefix(const QString& str) {
    if (str.startsWith("0x")) {
        return str.mid(2);
    }
    return str;
}

QJsonObject RpcService::validateAndConfigureStorage(quint64 id, const QString& storagePath) {
    if (storagePath.isEmpty()) {
        return createErrorResponse(id, -32602, "storageFilePath is required");
    }
    if (!m_sessionManager) {
        return createErrorResponse(id, -32000, "SessionManager not set");
    }
    if (!m_commMgr) {
        return createErrorResponse(id, -32000, "CommunicationManager not set");
    }
    if (!m_commMgr->commandSet()) {
        return createErrorResponse(id, -32000, "CommandSet not set");
    }

    // Creates the parent directory and an empty {} json pairings file if doesn't exist, matching Go's NewStore() function
    if (auto pairingStorage = m_commMgr->commandSet()->pairingStorage()) {
        if (auto filePairingStorage = std::dynamic_pointer_cast<StatusKeycard::FilePairingStorage>(pairingStorage)) {
            if (!filePairingStorage->setPath(storagePath)) {
                return createErrorResponse(id, -32000, "Failed to create pairing storage at: " + storagePath);
            }
        }
    }

    return QJsonObject();
}

QJsonObject RpcService::loginKeysToJson(const SessionManager::LoginKeys& keys) {
    QJsonObject whisperKey;
    whisperKey["address"] = keys.whisperPrivateKey.address;
    whisperKey["publicKey"] = keys.whisperPrivateKey.publicKey;
    whisperKey["privateKey"] = keys.whisperPrivateKey.privateKey;

    QJsonObject encryptionKey;
    encryptionKey["address"] = keys.encryptionPrivateKey.address;
    encryptionKey["publicKey"] = keys.encryptionPrivateKey.publicKey;
    encryptionKey["privateKey"] = keys.encryptionPrivateKey.privateKey;

    QJsonObject keysObject;
    keysObject["whisperPrivateKey"] = whisperKey;
    keysObject["encryptionPrivateKey"] = encryptionKey;

    QJsonObject result;
    result["keys"] = keysObject;

    return result;
}

// ============================================================================
// RPC Method Handlers
// ============================================================================

QJsonObject RpcService::handleStart(quint64 id, const QJsonObject& params) {
    qDebug() << "StatusKeycardQt::RpcService::handleStart() called on RpcService at:" << (void*)this;
    qDebug() << "StatusKeycardQt::SessionManager at:" << (void*)m_sessionManager.get();

    QString storagePath = params["storageFilePath"].toString();
    bool logEnabled = params["logEnabled"].toBool(false);
    QString logFilePath = params["logFilePath"].toString();

    QJsonObject validationError = validateAndConfigureStorage(id, storagePath);
    if (!validationError.isEmpty()) {
        return validationError;
    }

    bool success = m_sessionManager->start(logEnabled, logFilePath);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    qDebug() << "StatusKeycardQt::RpcService::handleStart() completed. SessionManager started successfully.";
    qDebug() << "StatusKeycardQt::CommunicationManager at:" << (void*)m_commMgr.get();

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleStop(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);
    m_sessionManager->stop();
    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleGetStatus(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);
    SessionManager::Status status = m_sessionManager->getStatus();
    return createSuccessResponse(id, statusToJson(status));
}

QJsonObject RpcService::handleInitialize(quint64 id, const QJsonObject& params) {
    QString pin = params["pin"].toString();
    QString puk = params["puk"].toString();
    QString pairingPassword = params["pairingPassword"].toString();

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }
    if (puk.length() != PukLength) {
        return createErrorResponse(id, -32602, "PUK must be " + QString::number(PukLength) + " digits");
    }

    bool success = m_sessionManager->initialize(pin, puk, pairingPassword);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleAuthorize(quint64 id, const QJsonObject& params) {
    QString pin = params["pin"].toString();

    if (pin.length() != PinLength) {
        return createErrorResponse(id, -32602, "PIN must be " + QString::number(PinLength) + " digits");
    }

    bool authorized = m_sessionManager->authorize(pin);

    QJsonObject result;
    result["authorized"] = authorized;

    return createSuccessResponse(id, result);
}

QJsonObject RpcService::handleChangePIN(quint64 id, const QJsonObject& params) {
    QString newPin = params["newPin"].toString();

    if (newPin.length() != PinLength) {
        return createErrorResponse(id, -32602, "New PIN must be 6 digits");
    }

    bool success = m_sessionManager->changePIN(newPin);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleChangePUK(quint64 id, const QJsonObject& params) {
    QString newPuk = params["newPuk"].toString();

    if (newPuk.length() != PukLength) {
        return createErrorResponse(id, -32602, "New PUK must be " + QString::number(PukLength) + " digits");
    }

    bool success = m_sessionManager->changePUK(newPuk);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleUnblock(quint64 id, const QJsonObject& params) {
    QString puk = params["puk"].toString();
    QString newPin = params["newPin"].toString();

    if (puk.length() != PukLength) {
        return createErrorResponse(id, -32602, "PUK must be " + QString::number(PukLength) + " digits");
    }
    if (newPin.length() != PinLength) {
        return createErrorResponse(id, -32602, "New PIN must be " + QString::number(PinLength) + " digits");
    }

    bool success = m_sessionManager->unblockPIN(puk, newPin);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleGenerateMnemonic(quint64 id, const QJsonObject& params) {
    int length = params["length"].toInt(12);

    QVector<int> indexes = m_sessionManager->generateMnemonic(length);
    if (indexes.isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonArray indexesArray;
    for (int idx : indexes) {
        indexesArray.append(idx);
    }

    QJsonObject result;
    result["indexes"] = indexesArray;

    return createSuccessResponse(id, result);
}

QJsonObject RpcService::handleLoadMnemonic(quint64 id, const QJsonObject& params) {
    QString mnemonic = params["mnemonic"].toString();
    QString passphrase = params["passphrase"].toString();

    if (mnemonic.isEmpty()) {
        return createErrorResponse(id, -32602, "mnemonic is required");
    }

    QString keyUID = m_sessionManager->loadMnemonic(mnemonic, passphrase);
    if (keyUID.isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    QJsonObject result;
    result["keyUID"] = keyUID;

    return createSuccessResponse(id, result);
}

QJsonObject RpcService::handleFactoryReset(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);

    bool success = m_sessionManager->factoryReset();
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleGetMetadata(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);

    SessionManager::Metadata metadata = m_sessionManager->getMetadata();

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

    QJsonObject result;
    result["metadata"] = meta;

    return createSuccessResponse(id, result);
}

QJsonObject RpcService::handleStoreMetadata(quint64 id, const QJsonObject& params) {
    QString name = params["name"].toString();
    QJsonArray pathsArray = params["paths"].toArray();

    QStringList paths;
    for (const QJsonValue& val : pathsArray) {
        paths.append(val.toString());
    }

    bool success = m_sessionManager->storeMetadata(name, paths);
    if (!success) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, QJsonObject());
}

QJsonObject RpcService::handleExportLoginKeys(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);

    SessionManager::LoginKeys keys = m_sessionManager->exportLoginKeys();
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    return createSuccessResponse(id, loginKeysToJson(keys));
}

QJsonObject RpcService::handleExportRecoverKeys(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);

    SessionManager::RecoverKeys keys = m_sessionManager->exportRecoverKeys();
    if (!m_sessionManager->lastError().isEmpty()) {
        return createErrorResponse(id, -32000, m_sessionManager->lastError());
    }

    // Helper to convert KeyPair to JSON
    auto keyPairToJson = [](const SessionManager::KeyPair& kp) {
        QJsonObject obj;
        obj["address"] = kp.address;
        obj["publicKey"] = kp.publicKey;
        if (!kp.privateKey.isEmpty()) {
            obj["privateKey"] = kp.privateKey;
        }
        if (!kp.chainCode.isEmpty()) {
            obj["chainCode"] = kp.chainCode;
        }
        return obj;
    };

    // Build response matching status-keycard-go format
    QJsonObject keysObj;
    keysObj["whisperPrivateKey"] = keyPairToJson(keys.loginKeys.whisperPrivateKey);
    keysObj["encryptionPrivateKey"] = keyPairToJson(keys.loginKeys.encryptionPrivateKey);
    keysObj["eip1581"] = keyPairToJson(keys.eip1581);
    keysObj["walletRootKey"] = keyPairToJson(keys.walletRootKey);
    keysObj["walletKey"] = keyPairToJson(keys.walletKey);
    keysObj["masterKey"] = keyPairToJson(keys.masterKey);

    QJsonObject result;
    result["keys"] = keysObj;

    return createSuccessResponse(id, result);
}

// ============================================================================
// RPC Composite Method Handlers
// ============================================================================

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

} // namespace StatusKeycard

