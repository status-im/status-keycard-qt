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
        {"keycard.Stop", &RpcService::handleStop},
        {"keycard.CancelCurrentOperation", &RpcService::handleCancelCurrentOperation},
    };

    const QHash<QString, HandlerFunction> compositeHandlers = {
        {"keycard.Login", &RpcService::handleLogin},
        {"keycard.Recover", &RpcService::handleRecover},
        {"keycard.Load", &RpcService::handleLoad},
        {"keycard.ExportExtendedPublicKey", &RpcService::handleExportExtendedPublicKey},
        {"keycard.ExportPublicKey", &RpcService::handleExportPublicKey},
        {"keycard.ChangeKeycardPIN", &RpcService::handleChangeKeycardPIN},
        {"keycard.ChangeKeycardPUK", &RpcService::handleChangeKeycardPUK},
        {"keycard.UnblockUsingPUK", &RpcService::handleUnblockUsingPUK},
        {"keycard.GetKeycardMetadata", &RpcService::handleGetKeycardMetadata},
        {"keycard.StoreKeycardMetadata", &RpcService::handleStoreKeycardMetadata},
        {"keycard.Sign", &RpcService::handleSign},
        {"keycard.FactoryResetKeycard", &RpcService::handleFactoryResetKeycard},
    };

    QJsonObject response;
    if (lifeCycleHandlers.contains(method)) {
        response = (this->*lifeCycleHandlers[method])(id, params);
    } else if (compositeHandlers.contains(method)) {
        response = (this->*compositeHandlers[method])(id, params);
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

    if (!keys.extendedPublicKey.xpub.isEmpty()) {
        QJsonObject epk;
        epk["address"] = ensure0xPrefix(keys.extendedPublicKey.address);
        epk["publicKey"] = ensure0xPrefix(keys.extendedPublicKey.publicKey);
        epk["chainCode"] = ensure0xPrefix(keys.extendedPublicKey.chainCode);
        epk["xpub"] = keys.extendedPublicKey.xpub;
        keysObject["extendedPublicKey"] = epk;
    }

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

    // Present only when an extended public key was derived (xPubPath provided to login()).
    if (!keys.loginKeys.extendedPublicKey.xpub.isEmpty()) {
        QJsonObject epk;
        epk["address"] = ensure0xPrefix(keys.loginKeys.extendedPublicKey.address);
        epk["publicKey"] = ensure0xPrefix(keys.loginKeys.extendedPublicKey.publicKey);
        epk["chainCode"] = ensure0xPrefix(keys.loginKeys.extendedPublicKey.chainCode);
        epk["xpub"] = keys.loginKeys.extendedPublicKey.xpub;
        keysObj["extendedPublicKey"] = epk;
    }

    QJsonObject result;
    result["keys"] = keysObj;

    return result;
}

// ============================================================================
// RPC Method Handlers
// ============================================================================

QJsonObject RpcService::handleStop(quint64 id, const QJsonObject& params) {
    Q_UNUSED(params);
    m_sessionManager->stop();
    return createSuccessResponse(id, QJsonObject());
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

