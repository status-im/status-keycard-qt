#include "session_manager.h"
#include <keycard-qt/i_communication_manager.h>
#include <QDebug>
#include <memory>

namespace StatusKeycard {

SessionManager::LoginKeys SessionManager::login(const QString& keyUid, const QString& pin, bool logEnabled, const QString& logFilePath)
{
    qDebug() << "StatusKeycardQt::SessionManager::login()";

    // Stop any existing session to release the PCSC card handle
    stop();

    // Clear any previous error and cancel flag (after stop, which sets cancelled=true)
    m_lastError.clear();
    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return LoginKeys();
    }

    // Enable batch mode BEFORE starting detection so the NFC session stays alive
    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    // Step 1: Start card detection
    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return LoginKeys();
    }

    // Step 2: Wait for card to be ready (event-driven, no polling)
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while (m_state == SessionState::WaitingForCard && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
    }

    if (m_compositeMethodCallCancelled) {
        setError("Login cancelled");
        return LoginKeys();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return LoginKeys();
    }

    auto status = getStatus();
    if (!status.keycardInfo || !status.keycardInfo) {
        setError("Keycard info not found");
        return LoginKeys();
    }

    if (status.keycardInfo->keyUID != keyUid) {
        setError("Keycard UID does not match the keyUid being tried to login with");
        return LoginKeys();
    }

    // Step 3: Authorize with PIN (batch is already active)
    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return LoginKeys();
    }

    // Step 4: Export login keys (not main command — batch is already open)
    return exportLoginKeys(false);
}

SessionManager::RecoverKeys SessionManager::recover(const QString& pin, const QString& puk, const QString& pairingPassword,
                                const QString& mnemonic, bool logEnabled, const QString& logFilePath)
{
    qDebug() << "StatusKeycardQt::SessionManager::recover()";

    // Stop any existing session to release the PCSC card handle
    stop();

    // Clear any previous error and cancel flag (after stop, which sets cancelled=true)
    m_lastError.clear();
    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return RecoverKeys();
    }

    // Enable batch mode BEFORE starting detection so the NFC session stays alive
    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    // Step 1: Start card detection
    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return RecoverKeys();
    }

    // Step 2: Wait for card to be ready (event-driven, no polling)
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while (m_state == SessionState::WaitingForCard && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
    }

    if (m_compositeMethodCallCancelled) {
        setError("Recover cancelled");
        return RecoverKeys();
    }

    // Step 3: Factory reset (works from any card state)
    if (!factoryReset()) {
        return RecoverKeys();
    }

    // Step 4: Initialize card with new PIN and PUK
    if (!initialize(pin, puk, pairingPassword)) {
        return RecoverKeys();
    }

    // Step 5: Authorize with PIN (batch already active — same NFC session)
    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return RecoverKeys();
    }

    // Step 6: Load mnemonic onto the card
    QString keyUID = loadMnemonic(mnemonic, QString());
    if (keyUID.isEmpty()) {
        return RecoverKeys();
    }

    // Step 7: Export recover keys (not main command — batch already open)
    return exportRecoverKeys(false);
}

} // namespace StatusKeycard
