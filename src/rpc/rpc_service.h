#pragma once

#include <QObject>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <memory>
#include "session/session_manager.h"

namespace Keycard {
    class ICommunicationManager;
}

namespace StatusKeycard {

/**
 * @brief JSON-RPC service for Keycard operations
 *
 * Implements the exact JSON-RPC interface expected by nim-keycard-go.
 * All methods match status-keycard-go's Session API.
 */
class RpcService : public QObject {
    Q_OBJECT

public:
    explicit RpcService(QObject* parent = nullptr);
    ~RpcService();

    /**
     * @brief Process a JSON-RPC request and return JSON response
     *
     * @param requestJson JSON-RPC request string
     * @return JSON-RPC response string (must be freed by caller with Free())
     */
    QString processRequest(const QString& requestJson);

    /**
     * @brief Get the session manager
     */
    SessionManager* sessionManager() { return m_sessionManager.get(); }

    /**
     * @brief Get the communication manager
     */
    std::shared_ptr<Keycard::ICommunicationManager> communicationManager() { return m_commMgr; }

    /**
     * @brief Set the communication manager
     * @param commMgr Communication manager instance (accepts interface for flexibility)
     */
    void setCommunicationManager(std::shared_ptr<Keycard::ICommunicationManager> commMgr);

private:
    /**
     * @brief Create a JSON-RPC success response
     */
    QJsonObject createSuccessResponse(quint64 id, const QJsonValue& result);

    /**
     * @brief Create a JSON-RPC error response
     */
    QJsonObject createErrorResponse(quint64 id, int code, const QString& message);

    /**
     * @brief Convert SessionManager::Status to JSON
     */
    QJsonObject statusToJson(const SessionManager::Status& status);

    /**
     * @brief Validate infrastructure and configure pairing storage
     * @return empty QJsonObject on success, or error response on failure
     */
    QJsonObject validateAndConfigureStorage(quint64 id, const QString& storagePath);

    /**
     * @brief Convert LoginKeys to JSON-RPC result
     */
    QJsonObject loginKeysToJson(const SessionManager::LoginKeys& keys);
    /**
     * @brief Convert RecoverKeys to JSON-RPC result
     */
    QJsonObject recoverKeysToJson(const SessionManager::RecoverKeys& keys);

    // RPC method handlers
    QJsonObject handleStart(quint64 id, const QJsonObject& params);
    QJsonObject handleStop(quint64 id, const QJsonObject& params);
    QJsonObject handleGetStatus(quint64 id, const QJsonObject& params);
    QJsonObject handleInitialize(quint64 id, const QJsonObject& params);
    QJsonObject handleAuthorize(quint64 id, const QJsonObject& params);
    QJsonObject handleChangePIN(quint64 id, const QJsonObject& params);
    QJsonObject handleChangePUK(quint64 id, const QJsonObject& params);
    QJsonObject handleUnblock(quint64 id, const QJsonObject& params);
    QJsonObject handleGenerateMnemonic(quint64 id, const QJsonObject& params);
    QJsonObject handleLoadMnemonic(quint64 id, const QJsonObject& params);
    QJsonObject handleFactoryReset(quint64 id, const QJsonObject& params);
    QJsonObject handleGetMetadata(quint64 id, const QJsonObject& params);
    QJsonObject handleStoreMetadata(quint64 id, const QJsonObject& params);
    QJsonObject handleExportLoginKeys(quint64 id, const QJsonObject& params);
    QJsonObject handleExportRecoverKeys(quint64 id, const QJsonObject& params);
    QJsonObject handleCancelCurrentOperation(quint64 id, const QJsonObject& params);
    QJsonObject handleLogin(quint64 id, const QJsonObject& params);
    QJsonObject handleRecover(quint64 id, const QJsonObject& params);
    QJsonObject handleLoad(quint64 id, const QJsonObject& params);
    QJsonObject handleExportExtendedPublicKey(quint64 id, const QJsonObject& params);
    QJsonObject handleExportPublicKey(quint64 id, const QJsonObject& params);
    QJsonObject handleChangeKeycardPIN(quint64 id, const QJsonObject& params);
    QJsonObject handleChangeKeycardPUK(quint64 id, const QJsonObject& params);
    QJsonObject handleUnblockUsingPUK(quint64 id, const QJsonObject& params);
    QJsonObject handleGetKeycardMetadata(quint64 id, const QJsonObject& params);
    QJsonObject handleStoreKeycardMetadata(quint64 id, const QJsonObject& params);
    QJsonObject handleSign(quint64 id, const QJsonObject& params);
    QJsonObject handleFactoryResetKeycard(quint64 id, const QJsonObject& params);

    std::unique_ptr<SessionManager> m_sessionManager;
    std::shared_ptr<Keycard::ICommunicationManager> m_commMgr;
};

} // namespace StatusKeycard
