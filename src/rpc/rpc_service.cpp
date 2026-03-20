#include "rpc_service.h"
#include "../utils/constants.h"
#include "../utils/common.h"
#include "../session/session_manager.h"
#include "../storage/file_pairing_storage.h"
#include "keycard-qt/communication_manager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <exception>

namespace StatusKeycard {

    using HandlerFunction = QJsonObject (RpcService::*)(quint64, const QJsonObject&);

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

QJsonObject extractParams(const QJsonValue& paramsValue) {
    // Params can be an array with a single object, or an empty array
    if (paramsValue.isObject()) {
        return paramsValue.toObject();
    }

    if (paramsValue.isArray()) {
        const QJsonArray paramsArray = paramsValue.toArray();
        if (!paramsArray.isEmpty() && paramsArray.first().isObject()) {
            return paramsArray.first().toObject();
        }
    }

    return {};
}

QString toCompactJson(const QJsonObject& obj) {
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString RpcService::processRequest(const QString& requestJson) {
    // Parse the request
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(requestJson.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        return toCompactJson(createErrorResponse(
            0,
            -32700,
            QString("Parse error: %1").arg(parseError.errorString())
        ));
    }

    if (!doc.isObject()) {
        return toCompactJson(createErrorResponse(
            0,
            -32600,
            "Invalid Request: JSON-RPC request must be an object"
        ));
    }

    const QJsonObject request = doc.object();
    const quint64 id = request.value("id").toVariant().toULongLong();
    const QString method = request.value("method").toString();
    const QJsonObject params = extractParams(request.value("params"));

    qDebug() << "StatusKeycardQt::RpcService::processRequest() id:" << id;
    qDebug() << "StatusKeycardQt::RpcService::processRequest() method:" << method;
    qDebug() << "StatusKeycardQt::RpcService::processRequest() params:" << toCompactJson(params);

    if (!m_commMgr) {
        return toCompactJson(createErrorResponse(id, -32000, "CommunicationManager not set"));
    }

    const QHash<QString, HandlerFunction> lifeCycleHandlers = {
        {"keycard.Start", &RpcService::handleStart},
        {"keycard.Stop", &RpcService::handleStop},
        {"keycard.CancelCurrentOperation", &RpcService::handleCancelCurrentOperation},
    };

    const QHash<QString, HandlerFunction> compositeHandlers = {
        {"keycard.Login", &RpcService::handleLogin},
        {"keycard.Recover", &RpcService::handleRecover},
        {"keycard.ExportExtendedPublicKey", &RpcService::handleExportExtendedPublicKey},
        {"keycard.ExportPublicKey", &RpcService::handleExportPublicKey},
    };

    const QHash<QString, HandlerFunction> singleStepHandlers = {
        {"keycard.GetStatus", &RpcService::handleGetStatus},
        {"keycard.Initialize", &RpcService::handleInitialize},
        {"keycard.Authorize", &RpcService::handleAuthorize},
        {"keycard.ChangePIN", &RpcService::handleChangePIN},
        {"keycard.ChangePUK", &RpcService::handleChangePUK},
        {"keycard.Unblock", &RpcService::handleUnblock},
        {"keycard.GenerateMnemonic", &RpcService::handleGenerateMnemonic},
        {"keycard.LoadMnemonic", &RpcService::handleLoadMnemonic},
        {"keycard.FactoryReset", &RpcService::handleFactoryReset},
        {"keycard.GetMetadata", &RpcService::handleGetMetadata},
        {"keycard.StoreMetadata", &RpcService::handleStoreMetadata},
        {"keycard.ExportLoginKeys", &RpcService::handleExportLoginKeys},
        {"keycard.ExportRecoverKeys", &RpcService::handleExportRecoverKeys},
    };

    QJsonObject response;
    if (lifeCycleHandlers.contains(method)) {
        response = (this->*lifeCycleHandlers[method])(id, params);
    } else if (compositeHandlers.contains(method)) {
        response = (this->*compositeHandlers[method])(id, params);
    } else if (singleStepHandlers.contains(method)) {
        // Enable batch mode BEFORE starting detection so the NFC session stays alive
        m_commMgr->startBatchOperations();
        auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
        std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

        response = (this->*singleStepHandlers[method])(id, params);
    } else {
        return toCompactJson(createErrorResponse(id, -32601, QString("Method not found: %1").arg(method)));
    }

    return toCompactJson(response);
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
    whisperKey["address"] = ensure0xPrefix(keys.whisperPrivateKey.address);
    whisperKey["publicKey"] = ensure0xPrefix(keys.whisperPrivateKey.publicKey);
    whisperKey["privateKey"] = ensure0xPrefix(keys.whisperPrivateKey.privateKey);

    QJsonObject encryptionKey;
    encryptionKey["address"] = ensure0xPrefix(keys.encryptionPrivateKey.address);
    encryptionKey["publicKey"] = ensure0xPrefix(keys.encryptionPrivateKey.publicKey);
    encryptionKey["privateKey"] = ensure0xPrefix(keys.encryptionPrivateKey.privateKey);

    QJsonObject keysObject;
    keysObject["whisperPrivateKey"] = whisperKey;
    keysObject["encryptionPrivateKey"] = encryptionKey;

    QJsonObject result;
    result["keys"] = keysObject;

    return result;
}

QJsonObject RpcService::recoverKeysToJson(const SessionManager::RecoverKeys& keys) {
    // Helper to convert KeyPair to JSON (hex values with 0x prefix)
    auto keyPairToJson = [](const SessionManager::KeyPair& kp) {
        QJsonObject obj;
        obj["address"] = ensure0xPrefix(kp.address);
        obj["publicKey"] = ensure0xPrefix(kp.publicKey);
        if (!kp.privateKey.isEmpty()) {
            obj["privateKey"] = ensure0xPrefix(kp.privateKey);
        }
        if (!kp.chainCode.isEmpty()) {
            obj["chainCode"] = ensure0xPrefix(kp.chainCode);
        }
        return obj;
    };

    QJsonObject keysObj;
    keysObj["whisperPrivateKey"] = keyPairToJson(keys.loginKeys.whisperPrivateKey);
    keysObj["encryptionPrivateKey"] = keyPairToJson(keys.loginKeys.encryptionPrivateKey);
    keysObj["eip1581"] = keyPairToJson(keys.eip1581);
    keysObj["walletRootKey"] = keyPairToJson(keys.walletRootKey);
    keysObj["walletKey"] = keyPairToJson(keys.walletKey);
    keysObj["masterKey"] = keyPairToJson(keys.masterKey);

    QJsonObject result;
    result["keys"] = keysObj;

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

    return createSuccessResponse(id, recoverKeysToJson(keys));
}

QJsonObject RpcService::handleCancelCurrentOperation(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);

    try {
        m_commMgr->cancelPendingOperations("User cancelled NFC");

        return createSuccessResponse(id, QJsonObject());
    } catch (const std::exception& e) {
        return createErrorResponse(id, -32000, QString::fromUtf8(e.what()));
    } catch (...) {
        return createErrorResponse(id, -32000, "Unknown error");
    }
}

} // namespace StatusKeycard

