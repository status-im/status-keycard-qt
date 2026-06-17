#include "session_manager.h"
#include "../utils/common.h"
#include "../utils/constants.h"
#include "../utils/crypto_utils.h"
#include "../utils/signature_utils.h"
#include <keycard-qt/i_communication_manager.h>
#include <keycard-qt/command_set.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/tlv_utils.h>
#include <QDebug>
#include <memory>

namespace StatusKeycard {

bool SessionManager::validateCompositeKeyUid(const QString& keyUid, const ApplicationInfoV2* keycardInfo)
{
    if (keyUid.isEmpty()) {
        return true;
    }
    if (!keycardInfo) {
        setError("Keycard info not found");
        return false;
    }
    if (keycardInfo->keyUID != keyUid) {
        setError("Keycard profile does not match the provided keyUid");
        return false;
    }
    return true;
}

bool SessionManager::validateCompositeKeycardUid(const QString& keycardUid, const ApplicationInfoV2* keycardInfo)
{
    if (keycardUid.isEmpty()) {
        return true;
    }
    if (!keycardInfo) {
        setError("Keycard info not found");
        return false;
    }
    if (QString::compare(keycardInfo->instanceUID, keycardUid, Qt::CaseInsensitive) != 0) {
        setError("Keycard instance UID does not match the provided keycardUid");
        return false;
    }
    return true;
}

SessionManager::LoginKeys SessionManager::login(const QString& keyUid, const QString& pin,
    const QString& xPubPath, bool logEnabled, const QString& logFilePath)
{
    qDebug() << "StatusKeycardQt::SessionManager::login() xPubPath:" << xPubPath;

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
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return LoginKeys();
    }

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return LoginKeys();
    }

    // Step 3: Authorize with PIN (batch is already active)
    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return LoginKeys();
    }

    // Step 4: Export login keys (not main command — batch is already open)
    LoginKeys keys = exportLoginKeys(false);
    if (!m_lastError.isEmpty()) {
        return LoginKeys();
    }

    // Step 5: Optionally derive an extended public key at xPubPath while we're still
    // authorized and inside the open batch.
    if (!xPubPath.isEmpty()) {
        ExtendedPublicKey epk = exportExtendedPublicKey(xPubPath);
        if (!m_lastError.isEmpty()) {
            return LoginKeys();
        }
        keys.extendedPublicKey = epk;
    }

    return keys;
}

SessionManager::RecoverKeys SessionManager::initializeAndLoad(const QString& pin, const QString& puk,
    const QString& pairingPassword, const QString& mnemonic, const QString& metadataName,
    const QStringList& metadataPaths, const bool cardContainsKeyOnly)
{
    // Step 1: Initialize card with the provided PIN and PUK
    if (!cardContainsKeyOnly && !initialize(pin, puk, pairingPassword)) {
        return RecoverKeys();
    }

    // Step 2: Authorize with PIN
    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return RecoverKeys();
    }

    // Step 3: Load mnemonic onto the card
    QString keyUID = loadMnemonic(mnemonic, QString());
    if (keyUID.isEmpty()) {
        return RecoverKeys();
    }

    // Step 4: Optionally store metadata
    if (!metadataName.isEmpty()) {
        if (!storeMetadata(metadataName, metadataPaths)) {
            return RecoverKeys();
        }
    }

    // Step 5: Export recover keys (batch already open)
    return exportRecoverKeys(false);
}

SessionManager::RecoverKeys SessionManager::recover(const QString& pin, const QString& puk, const QString& pairingPassword,
                                const QString& mnemonic, const QString& metadataName, const QStringList& metadataPaths,
                                bool logEnabled, const QString& logFilePath,
                                const QString& keycardUid)
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

    // Step 3: Validate the keycard UID matches if provided
    auto status = getStatus();
    if (!validateCompositeKeycardUid(keycardUid, status.keycardInfo)) {
        return RecoverKeys();
    }

    // Step 4: Factory reset (works from any card state)
    if (!factoryReset()) {
        return RecoverKeys();
    }

    // Step 5: Initialize, load mnemonic, and export keys
    return initializeAndLoad(pin, puk, pairingPassword, mnemonic, metadataName, metadataPaths, false);
}

SessionManager::RecoverKeys SessionManager::load(const QString& pin, const QString& puk, const QString& pairingPassword,
                               const QString& mnemonic, const QString& metadataName, const QStringList& metadataPaths,
                               bool logEnabled, const QString& logFilePath)
{
    qDebug() << "StatusKeycardQt::SessionManager::load()";

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
        setError("Load cancelled");
        return RecoverKeys();
    }

    auto cardContainsKeyOnly = false;
    auto status = getStatus();
    if (!!status.keycardInfo && !status.keycardInfo->instanceUID.isEmpty() && status.keycardInfo->keyUID.isEmpty()) {
        cardContainsKeyOnly = true;
    }

    if (!cardContainsKeyOnly && m_state != SessionState::EmptyKeycard) {
        setError(QString("Card is not empty (state: %1). Use Recover to overwrite an existing keycard").arg(currentStateString()));
        return RecoverKeys();
    }

    // Step 3: Initialize, load mnemonic, and export keys
    return initializeAndLoad(pin, puk, pairingPassword, mnemonic, metadataName, metadataPaths, cardContainsKeyOnly);
}

SessionManager::ExportExtendedPublicKeyResult SessionManager::exportExtendedPublicKey(const QString& keyUid, const QString& pin,
    const QString& path, bool exportMasterAddress, const QString& storageFilePath, bool logEnabled,
    const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::exportExtendedPublicKey() path:" << path;

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return ExportExtendedPublicKeyResult();
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return ExportExtendedPublicKeyResult();
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
        return ExportExtendedPublicKeyResult();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return ExportExtendedPublicKeyResult();
    }

    auto status = getStatus();
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return ExportExtendedPublicKeyResult();
    }

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return ExportExtendedPublicKeyResult();
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return ExportExtendedPublicKeyResult();
    }

    ExportExtendedPublicKeyResult result;
    result.extendedPublicKey = exportExtendedPublicKey(path);
    if (!m_lastError.isEmpty()) {
        return ExportExtendedPublicKeyResult();
    }

    if (exportMasterAddress) {
        // Reuse the single-path export to resolve the master key (m) address (rootWalletMasterKey)
        ExtendedPublicKey masterKey = exportExtendedPublicKey(PathMaster);
        if (!m_lastError.isEmpty()) {
            return ExportExtendedPublicKeyResult();
        }
        result.masterKeyAddress = masterKey.address;
    }

    return result;
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
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return ExportPublicKeyResult();
    }

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return ExportPublicKeyResult();
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return ExportPublicKeyResult();
    }

    return exportPublicKeyInternal(paths, exportPrivate, exportMasterAddress);
}

bool SessionManager::changeKeycardPIN(const QString& keyUid, const QString& pin, const QString& newPIN,
    const QString& storageFilePath, bool logEnabled, const QString& logFilePath,
    const QString& keycardUid)
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

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return false;
    }
    if (!validateCompositeKeycardUid(keycardUid, status.keycardInfo)) {
        return false;
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return false;
    }

    return changePIN(newPIN);
}

bool SessionManager::changeKeycardPUK(const QString& keyUid, const QString& pin, const QString& newPUK,
    const QString& storageFilePath, bool logEnabled, const QString& logFilePath,
    const QString& keycardUid)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::changeKeycardPUK()";

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
        setError("changePUK cancelled");
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

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return false;
    }
    if (!validateCompositeKeycardUid(keycardUid, status.keycardInfo)) {
        return false;
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return false;
    }

    return changePUK(newPUK);
}

bool SessionManager::unblockUsingPUK(const QString& keyUid, const QString& puk, const QString& newPIN,
    const QString& storageFilePath, bool logEnabled, const QString& logFilePath,
    const QString& keycardUid)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::unblockUsingPUK()";

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
        setError("unblockUsingPUK cancelled");
        return false;
    }

    if (m_state != SessionState::BlockedPIN) {
        setError(QString("PIN is not blocked (state: %1)").arg(currentStateString()));
        return false;
    }

    auto status = getStatus();
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return false;
    }

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return false;
    }
    if (!validateCompositeKeycardUid(keycardUid, status.keycardInfo)) {
        return false;
    }

    QMutexLocker locker(&m_operationMutex);

    return unblockPIN(puk, newPIN);
}

SessionManager::Metadata SessionManager::getKeycardMetadata(const QString& pin, const QString& storageFilePath,
    bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::getKeycardMetadata()";

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return Metadata();
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return Metadata();
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
        setError("getKeycardMetadata cancelled");
        return Metadata();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return Metadata();
    }

    QMutexLocker locker(&m_operationMutex);

    const bool hasPin = !pin.isEmpty();

    if (hasPin) {
        if (!authorize(pin)) {
            return Metadata();
        }
    }

    // Fetch metadata from card (requires secure channel, which is established during card init)
    m_metadata = getMetadata(true);

    // If authorized and metadata has wallet paths, resolve address/publicKey for each
    if (hasPin && !m_metadata.wallets.isEmpty()) {
        for (int i = 0; i < m_metadata.wallets.size(); ++i) {
            const QString& path = m_metadata.wallets[i].path;
            QByteArray keyData = exportKeyInternal(true, false, path, Keycard::APDU::P2ExportKeyPublicOnly);
            if (keyData.isEmpty()) {
                qWarning() << "SessionManager::getKeycardMetadata: Failed to export key for path:" << path;
                continue;
            }
            KeyPair kp = parseExportedKey(keyData);
            m_metadata.wallets[i].address = ensure0xPrefix(kp.address);
            m_metadata.wallets[i].publicKey = ensure0xPrefix(kp.publicKey);
        }
    }

    return m_metadata;
}

bool SessionManager::storeKeycardMetadata(const QString& pin, const QString& name, const QStringList& paths,
    const QString& storageFilePath, bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::storeKeycardMetadata()";

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
        setError("storeKeycardMetadata cancelled");
        return false;
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return false;
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return false;
    }

    return storeMetadata(name, paths);
}

SessionManager::SignResult SessionManager::sign(const QString& keyUid, const QString& pin, const QString& txHash,
    const QString& path, const QString& storageFilePath, bool logEnabled, const QString& logFilePath)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::sign()";

    stop();

    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = false;
    }

    if (!ensureKeycardCommunication()) {
        return SignResult();
    }

    m_commMgr->startBatchOperations();
    auto batchGuard = [this](void*) { m_commMgr->endBatchOperations(); };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    if (!start(logEnabled, logFilePath)) {
        setError(QString("Failed to start: %1").arg(m_lastError));
        return SignResult();
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
        setError("sign cancelled");
        return SignResult();
    }

    if (m_state != SessionState::Ready) {
        setError(QString("Card not ready (state: %1)").arg(currentStateString()));
        return SignResult();
    }

    auto status = getStatus();
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return SignResult();
    }

    if (!validateCompositeKeyUid(keyUid, status.keycardInfo)) {
        return SignResult();
    }

    QMutexLocker locker(&m_operationMutex);

    if (!authorize(pin)) {
        return SignResult();
    }

    // Execute sign command
    QByteArray hashBytes = QByteArray::fromHex(txHash.toLatin1());
    if (hashBytes.size() != 32) {
        setError("txHash must be 32 bytes (64 hex characters)");
        return SignResult();
    }

    auto cmd = std::make_unique<Keycard::SignCommand>(hashBytes, path, false);
    Keycard::CommandResult cmdResult = m_commMgr->executeCommandSync(std::move(cmd));

    if (!cmdResult.success) {
        setError(QString("Sign failed: %1").arg(cmdResult.error));
        return SignResult();
    }

    QVariantMap data = cmdResult.data.toMap();
    QByteArray tlvResponse = data["tlvResponse"].toByteArray();
    if (tlvResponse.isEmpty()) {
        setError("Empty sign response");
        return SignResult();
    }

    // Extract template content (unwrap 0xA0/0xA1 if present)
    QByteArray innerData = SignatureUtils::extractTemplateContent(tlvResponse);

    // Find public key (tag 0x80, 65 bytes)
    QByteArray publicKey = Keycard::TLV::findTag(innerData, 0x80);

    // Find DER signature (tag 0x30)
    QByteArray derSig = SignatureUtils::findDERSignature(innerData);
    if (derSig.isEmpty()) {
        setError("DER signature not found in sign response");
        return SignResult();
    }

    // Parse DER to get R and S
    QByteArray r, s;
    if (!SignatureUtils::parseDERSignature(derSig, r, s)) {
        setError("Failed to parse DER signature");
        return SignResult();
    }

    // Calculate recovery ID (V)
    uint8_t v = 27;
    if (!publicKey.isEmpty()) {
        int recoveryId = CryptoUtils::calculateRecoveryId(hashBytes, r, s, publicKey);
        if (recoveryId >= 0) {
            v = static_cast<uint8_t>(recoveryId + 27);
        } else {
            qWarning() << "SessionManager::sign: ECDSA recovery failed, defaulting V=27";
        }
    } else {
        qWarning() << "SessionManager::sign: No public key in response, defaulting V=27";
    }

    SignResult result;
    result.r = QString::fromLatin1(r.toHex());
    result.s = QString::fromLatin1(s.toHex());
    result.v = v;
    return result;
}

bool SessionManager::factoryResetKeycard(const QString& storageFilePath,
    bool logEnabled, const QString& logFilePath, const QString& keycardUid)
{
    Q_UNUSED(storageFilePath);
    qDebug() << "StatusKeycardQt::SessionManager::factoryResetKeycard()";

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
        setError("factoryReset cancelled");
        return false;
    }

    auto status = getStatus();
    if (!status.keycardInfo) {
        setError("Keycard info not found");
        return false;
    }
    if (!validateCompositeKeycardUid(keycardUid, status.keycardInfo)) {
        return false;
    }

    if (!factoryReset()) {
        return false;
    }

    return true;
}

} // namespace StatusKeycard
