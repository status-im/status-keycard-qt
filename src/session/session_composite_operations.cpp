#include "session_manager.h"
#include <keycard-qt/i_communication_manager.h>
#include <keycard-qt/command_set.h>
#include <QDebug>
#include <memory>

namespace StatusKeycard {

SessionManager::LoginKeys SessionManager::login(const QString& keyUid, const QString& pin, bool logEnabled, const QString& logFilePath)
{
    qDebug() << "StatusKeycardQt::SessionManager::login()";

    // Stop any existing session to release the PCSC card handle
    stop();

    // Cancel composite method call flag (after stop, which sets cancelled=true)
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
    bool cancelled = false;
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while ((m_state == SessionState::WaitingForCard || m_state == SessionState::WaitingForReader)
               && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
        cancelled = m_compositeMethodCallCancelled;
    }

    if (cancelled) {
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
        setError("Keycard profile does not match the profile (keyUid) being tried to login with");
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

    // Cancel composite method call flag (after stop, which sets cancelled=true)
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
    bool cancelled = false;
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while ((m_state == SessionState::WaitingForCard || m_state == SessionState::WaitingForReader)
               && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
        cancelled = m_compositeMethodCallCancelled;
    }

    if (cancelled) {
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

SessionManager::ExtendedPublicKey SessionManager::exportExtendedPublicKey(const QString& keyUid, const QString& pin,
    const QString& path, const QString& storageFilePath, bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::exportExtendedPublicKey() path:" << path;

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return ExtendedPublicKey();
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return ExtendedPublicKey();
    }

    bool cancelled = false;
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while ((m_state == SessionState::WaitingForCard || m_state == SessionState::WaitingForReader)
               && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
        cancelled = m_compositeMethodCallCancelled;
    }

    if (cancelled) {
        setError("exportExtendedPublicKey cancelled");
        return ExtendedPublicKey();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return ExtendedPublicKey();
    }

    auto status = getStatus();
    if (!status.keycardInfo || !status.keycardInfo) {
        setError("Keycard info not found");
        return ExtendedPublicKey();
    }

    if (status.keycardInfo->keyUID != keyUid) {
        setError("Keycard profile does not match the profile (keyUid) being tried to export extended public key for");
        return ExtendedPublicKey();
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return ExtendedPublicKey();
    }

    return exportExtendedPublicKey(path);
}

SessionManager::ExportPublicKeyResult SessionManager::exportPublicKey(const QString& keyUid, const QString& pin,
    const QStringList& paths, bool exportPrivate, bool exportMasterAddress, const QString& storageFilePath,
    bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::exportPublicKey() paths:" << paths;

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return ExportPublicKeyResult();
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return ExportPublicKeyResult();
    }

    bool cancelled = false;
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while ((m_state == SessionState::WaitingForCard || m_state == SessionState::WaitingForReader)
               && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
        cancelled = m_compositeMethodCallCancelled;
    }

    if (cancelled) {
        setError("exportPublicKey cancelled");
        return ExportPublicKeyResult();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return ExportPublicKeyResult();
    }

    auto status = getStatus();
    if (!status.keycardInfo || !status.keycardInfo) {
        setError("Keycard info not found");
        return ExportPublicKeyResult();
    }

    if (status.keycardInfo->keyUID != keyUid) {
        setError("Keycard profile does not match the profile (keyUid) being tried to export public key for");
        return ExportPublicKeyResult();
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return ExportPublicKeyResult();
    }

    return exportPublicKeyInternal(paths, exportPrivate, exportMasterAddress);
}

bool SessionManager::changeKeycardPIN(const QString& keyUid, const QString& pin, const QString& newPIN,
    const QString& storageFilePath, bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::changeKeycardPIN()";

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return false;
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return false;
    }

    bool cancelled = false;
    {
        QMutexLocker locker(&m_cardReadyMutex);
        while ((m_state == SessionState::WaitingForCard || m_state == SessionState::WaitingForReader)
               && !m_compositeMethodCallCancelled) {
            m_cardReadyCondition.wait(&m_cardReadyMutex);
        }
        cancelled = m_compositeMethodCallCancelled;
    }

    if (cancelled) {
        setError("changePIN cancelled");
        return false;
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return false;
    }

    auto status = getStatus();
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return false;
    }

    if (status.keycardInfo->keyUID != keyUid) {
        setError("Keycard profile does not match the profile (keyUid) being tried to change PIN for");
        return false;
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return false;
    }

    return changePIN(newPIN);
}

} // namespace StatusKeycard
