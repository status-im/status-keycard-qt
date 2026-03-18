#include "session_manager.h"
#include "signal_manager.h"
#include "../utils/bip32_xpub_helpers.h"
#include "../utils/constants.h"
#include "../utils/crypto_utils.h"
#include <keycard-qt/types.h>
#include <keycard-qt/tlv_utils.h>
#include <keycard-qt/metadata_utils.h>
#include <keycard-qt/i_communication_manager.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QThread>
#include <QCoreApplication>
#include <QMetaObject>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace StatusKeycard {

// LEB128 (Little Endian Base 128) encoding
// Used for encoding wallet path components (matching Go's apdu.WriteLength)
// NOTE: LEB128 utilities moved to metadata_utils.h/cpp for reuse across the codebase

SessionManager::SessionManager(QObject* parent)
    : QObject(parent)
    , m_state(SessionState::UnknownReaderState)
    , m_started(false)
    , m_stateCheckTimer(new QTimer(this))
{
    // CRITICAL: Ensure we're in the main Qt thread for NFC events
    QThread* mainThread = QCoreApplication::instance()->thread();
    QThread* currentThread = QThread::currentThread();

    qDebug() << "StatusKeycardQt::SessionManager: Constructor called in thread:" << currentThread;
    qDebug() << "StatusKeycardQt::SessionManager: Main thread is:" << mainThread;

    if (currentThread != mainThread) {
        qWarning() << "SessionManager: Created in wrong thread! Moving to main thread...";
        moveToThread(mainThread);
        qDebug() << "StatusKeycardQt::SessionManager: Moved to main thread";
    }
}

SessionManager::~SessionManager()
{
    stop();
}

// Removed: startCardOperation() and operationCompleted() - not needed with CommunicationManager

void SessionManager::setCommunicationManager(std::shared_ptr<Keycard::ICommunicationManager> commMgr)
{
    if (m_started) {
        qWarning() << "SessionManager: Cannot set CommunicationManager while started";
        return;
    }

    if (m_commMgr == commMgr) {
        qDebug() << "StatusKeycardQt::SessionManager::setCommunicationManager() - CommunicationManager not changed";
        return;
    }

    qDebug() << "StatusKeycardQt::SessionManager::setCommunicationManager() - Setting CommunicationManager";
    m_commMgr = commMgr;
}

bool SessionManager::start(bool logEnabled, const QString& logFilePath)
{
    if (!m_commMgr) {
        qWarning() << "SessionManager: No CommunicationManager available";
        qWarning() << "SessionManager: Call setCommunicationManager() before start()";
        return false;
    }

    qDebug() << "StatusKeycardQt::SessionManager: Starting with CommunicationManager";

    // Disconnect any previous connections
    QObject::disconnect(m_commMgr.get(), nullptr, this, nullptr);

    // Connect to CommunicationManager signals
    // Use AutoConnection - direct if same thread, queued if cross-thread
    connect(m_commMgr.get(), &Keycard::ICommunicationManager::cardInitialized,
            this, &SessionManager::onCardInitialized,
            Qt::AutoConnection);

    connect(m_commMgr.get(), &Keycard::ICommunicationManager::cardLost,
            this, &SessionManager::onCardRemoved,
            Qt::AutoConnection);

    connect(m_commMgr.get(), &Keycard::ICommunicationManager::operationCancelled,
            this, [this]() { setState(SessionState::Cancelled); },
            Qt::AutoConnection);

    // Start card detection (CommunicationManager should already be init'd by caller)
    if (!m_commMgr->startDetection()) {
        qWarning() << "SessionManager: Failed to start card detection";
        return false;
    }

    setState(SessionState::WaitingForCard);
    m_started = true;

    qDebug() << "StatusKeycardQt::SessionManager: Started successfully, monitoring for cards";
    return true;
}

void SessionManager::stop()
{
    if (!m_started) {
        return;
    }

    qDebug() << "StatusKeycardQt::SessionManager: Stopping...";

    // Cancel any pending login wait
    {
        QMutexLocker locker(&m_cardReadyMutex);
        m_compositeMethodCallCancelled = true;
        m_cardReadyCondition.wakeAll();
    }

    // Stop card detection
    if (m_commMgr) {
        // Disconnect from CommunicationManager signals so SessionManager doesn't react to card events anymore
        QObject::disconnect(m_commMgr.get(), nullptr, this, nullptr);
        m_commMgr->stopDetection();
    }

    m_started = false;
    m_currentCardUID.clear();
    setState(SessionState::UnknownReaderState);

    qDebug() << "StatusKeycardQt::SessionManager: Stopped (detection paused, can restart with start())";
}

void SessionManager::setState(SessionState newState)
{
    qDebug() << "StatusKeycardQt::SessionManager::setState() - New state: "<< sessionStateToString(newState);

    SessionState oldState = m_state;
    m_state = newState;

    // Wake any thread waiting for card readiness (e.g., login())
    if (newState != SessionState::WaitingForCard) {
        QMutexLocker locker(&m_cardReadyMutex);
        m_cardReadyCondition.wakeAll();
    }

    // Emit Qt signal - c_api.cpp will forward to SignalManager
    emit stateChanged(newState, oldState);
}

void SessionManager::onCardInitialized(const Keycard::CardInitializationResult& result)
{
    qDebug() << "StatusKeycardQt::========================================";
    qDebug() << "StatusKeycardQt::SessionManager: CARD INITIALIZED";
    qDebug() << "StatusKeycardQt::========================================";

    // Update cached state from CommunicationManager
    m_currentCardUID = result.uid;
    m_appInfo = result.appInfo;
    m_appStatus = result.appStatus;

    if (!result.success) {
        qWarning() << "SessionManager: Card initialization failed:" << result.error;
        if (result.appInfo.availableSlots == 0) {
            setState(SessionState::NoAvailablePairingSlots);
        } else {
            setState(SessionState::ConnectionError);
            setError(result.error);
        }
        return;
    }

    // Determine state based on card status
    if (!result.appInfo.initialized) {
        qDebug() << "StatusKeycardQt::SessionManager: Card is empty (not initialized)";
        setState(SessionState::EmptyKeycard);
    } else if (m_appStatus.pinRetryCount == 0) {
        qDebug() << "StatusKeycardQt::SessionManager: PIN is blocked";
        setState(SessionState::BlockedPIN);
    } else if (m_appStatus.pukRetryCount == 0) {
        qDebug() << "StatusKeycardQt::SessionManager: PUK is blocked";
        setState(SessionState::BlockedPUK);
    } else {
        qDebug() << "StatusKeycardQt::SessionManager: Card is ready";
        setState(SessionState::Ready);
    }
}

void SessionManager::onCardRemoved()
{
    qDebug() << "StatusKeycardQt::========================================";
    qDebug() << "StatusKeycardQt::SessionManager: CARD REMOVED";
    qDebug() << "StatusKeycardQt::========================================";

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    qDebug() << "StatusKeycardQt::Ignoring card removal on mobile";
    return;
#else
    m_currentCardUID.clear();

    if (m_started) {
        setState(SessionState::WaitingForCard);
    }
#endif
}

void SessionManager::setError(const QString& error)
{
    qDebug() << "StatusKeycardQt::SessionManager::setError() - Error:" << error;
    m_lastError = error;
}

bool SessionManager::ensureKeycardCommunication()
{
    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }
    return true;
}

bool SessionManager::ensureStarted()
{
    if (!m_started) {
        setError("SessionManager not started");
        return false;
    }
    return ensureKeycardCommunication();
}

bool SessionManager::ensureAuthorized()
{
    if (!ensureStarted()) {
        return false;
    }
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    return true;
}

void SessionManager::updateAndPublishStatus(bool authorized)
{
    auto statusCmd = std::make_unique<Keycard::GetStatusCommand>();
    Keycard::CommandResult statusResult = m_commMgr->executeCommandSync(std::move(statusCmd));
    if (!statusResult.success && statusResult.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return;
    }
    if (statusResult.success) {
        QVariantMap statusData = statusResult.data.toMap();
        m_appStatus.pinRetryCount = statusData["pinRetryCount"].toInt();
        m_appStatus.pukRetryCount = statusData["pukRetryCount"].toInt();
    }

    // Determine state based on updated status
    if (m_appStatus.pinRetryCount == 0) {
        setState(SessionState::BlockedPIN);
    } else if (m_appStatus.pukRetryCount == 0) {
        setState(SessionState::BlockedPUK);
    } else if (m_state == SessionState::Ready && authorized) {
        setState(SessionState::Authorized);
    } else {
        setState(m_state);
    }
}

QString SessionManager::currentStateString() const
{
    return sessionStateToString(m_state);
}

SessionManager::Status SessionManager::getStatus() const
{
    Status status;
    status.state = currentStateString();

    // Build keycardInfo (if we have appInfo)
    if (!m_appInfo.instanceUID.isEmpty()) {
        status.keycardInfo = new ApplicationInfoV2();
        status.keycardInfo->installed = true; // If we have it, it's installed
        status.keycardInfo->initialized = m_appInfo.initialized;
        status.keycardInfo->instanceUID = m_appInfo.instanceUID.toHex();
        status.keycardInfo->version = QString("%1.%2").arg(m_appInfo.appVersion).arg(m_appInfo.appVersionMinor);
        status.keycardInfo->availableSlots = m_appInfo.availableSlots;
        status.keycardInfo->keyUID = m_appInfo.keyUID.toHex();
    }

    if ((m_state == SessionState::Ready || m_state == SessionState::Authorized
         || m_state == SessionState::BlockedPIN || m_state == SessionState::BlockedPUK)
        && m_appStatus.pinRetryCount >= 0) {
        status.keycardStatus = new ApplicationStatus();
        status.keycardStatus->remainingAttemptsPIN = m_appStatus.pinRetryCount;
        status.keycardStatus->remainingAttemptsPUK = m_appStatus.pukRetryCount;
        status.keycardStatus->keyInitialized = m_appStatus.keyInitialized;
        status.keycardStatus->path = ""; // TODO: Get from card if available
    }

    // Only include metadata if we have some
    if (!m_metadata.name.isEmpty() || !m_metadata.wallets.isEmpty()) {
        status.metadata = new Metadata();
        status.metadata->name = m_metadata.name;
        status.metadata->wallets = m_metadata.wallets;
    }

    return status;
}

// Card Operations

bool SessionManager::initialize(const QString& pin, const QString& puk, const QString& pairingPassword)
{
    qDebug() << "StatusKeycardQt::SessionManager::initialize()";
    QMutexLocker locker(&m_operationMutex);

    if (!ensureStarted()) {
        return false;
    }

    auto cmd = std::make_unique<Keycard::InitCommand>(pin, puk, pairingPassword);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return false;
    }

    if (result.success) {
        m_currentCardUID.clear();
        m_appInfo = m_commMgr->applicationInfo();
        m_appStatus = m_commMgr->applicationStatus();
        setState(SessionState::Ready);
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::authorize(const QString& pin)
{
    qDebug() << "StatusKeycardQt::SessionManager::authorize() - Thread:" << QThread::currentThread();

    if (!ensureStarted()) {
        return false;
    }

    if (m_state != SessionState::Ready) {
        setError("Card not ready (current state: " + currentStateString() + ")");
        return false;
    }

    auto cmd = std::make_unique<Keycard::VerifyPINCommand>(pin);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));
    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return false;
    }
    bool authorized = result.success;

    updateAndPublishStatus(authorized);

    if (!authorized) {
        setError(result.error);
    }

    return authorized;
}

bool SessionManager::changePIN(const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureAuthorized()) {
        return false;
    }

    auto cmd = std::make_unique<Keycard::ChangePINCommand>(newPIN);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return false;
    }

    if (result.success) {
        qDebug() << "StatusKeycardQt::SessionManager: PIN changed";
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::changePUK(const QString& newPUK)
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureAuthorized()) {
        return false;
    }

    auto cmd = std::make_unique<Keycard::ChangePUKCommand>(newPUK);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return false;
    }

    if (result.success) {
        qDebug() << "StatusKeycardQt::SessionManager: PUK changed";
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::unblockPIN(const QString& puk, const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureStarted()) {
        return false;
    }

    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return false;
    }

    auto cmd = std::make_unique<Keycard::UnblockPINCommand>(puk, newPIN);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return false;
    }

    if (result.success) {
        qDebug() << "StatusKeycardQt::SessionManager: PIN unblocked";
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

// Key Operations

QVector<int> SessionManager::generateMnemonic(int length)
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureStarted()) {
        return QVector<int>();
    }

    int checksumSize = 4; // Default
    if (length == 15) checksumSize = 5;
    else if (length == 18) checksumSize = 6;
    else if (length == 21) checksumSize = 7;
    else if (length == 24) checksumSize = 8;

    auto cmd = std::make_unique<Keycard::GenerateMnemonicCommand>(checksumSize);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setState(SessionState::Cancelled);
        return QVector<int>();
    }

    if (result.success) {
        QVariantList list = result.data.toList();
        QVector<int> indexes;
        for (const QVariant& v : list) {
            indexes.append(v.toInt());
        }
        return indexes;
    } else {
        setError(result.error);
        return QVector<int>();
    }
}

QString SessionManager::loadMnemonic(const QString& mnemonic, const QString& passphrase)
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureStarted()) {
        return QString();
    }

    // Convert mnemonic to BIP39 seed using PBKDF2
    // Formula: PBKDF2(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64, SHA512)

    // Normalize mnemonic and passphrase to NFKD form
    QString mnemonicNormalized = mnemonic.normalized(QString::NormalizationForm_D);
    QString passphraseNormalized = passphrase.normalized(QString::NormalizationForm_D);

    // BIP39 salt = "mnemonic" + passphrase
    QString salt = QString("mnemonic") + passphraseNormalized;

    // Use PBKDF2 to derive seed (64 bytes)
    QByteArray mnemonicBytes = mnemonicNormalized.toUtf8();
    QByteArray saltBytes = salt.toUtf8();

    // Use OpenSSL's PBKDF2
    QByteArray seed(64, 0);
    int pbkdf2Result = PKCS5_PBKDF2_HMAC(
        mnemonicBytes.constData(), mnemonicBytes.size(),
        reinterpret_cast<const unsigned char*>(saltBytes.constData()), saltBytes.size(),
        2048,  // iterations
        EVP_sha512(),  // hash function
        64,  // key length
        reinterpret_cast<unsigned char*>(seed.data())
    );

    if (pbkdf2Result != 1) {
        setError("PBKDF2 derivation failed");
        return QString();
    }

    // Load seed onto keycard
    qDebug() << "StatusKeycardQt::SessionManager: Loading seed onto keycard (" << seed.size() << " bytes)";

    auto cmd = std::make_unique<Keycard::LoadSeedCommand>(seed);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setError("Cancelled");
        return QString();
    }

    if (!result.success) {
        setError(QString("Failed to load seed: %1").arg(result.error));
        return QString();
    }

    QVariantMap data = result.data.toMap();
    QByteArray keyUID = QByteArray::fromHex(data["keyUID"].toString().toUtf8());

    m_appInfo.keyUID = keyUID;
    setState(m_state);

    qDebug() << "StatusKeycardQt::SessionManager: Seed loaded successfully, keyUID:" << keyUID.toHex();

    return QString("0x") + keyUID.toHex();
}

bool SessionManager::factoryReset()
{
    QMutexLocker locker(&m_operationMutex);

    if (!ensureStarted()) {
        return false;
    }

    setState(SessionState::FactoryResetting);

    auto cmd = std::make_unique<Keycard::FactoryResetCommand>();
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setError("Cancelled");
        return false;
    }

    if (!result.success) {
        setError(result.error);
        setState(SessionState::InternalError);
        return false;
    }

    qDebug() << "StatusKeycardQt::SessionManager: Factory reset complete";

    m_appInfo = m_commMgr->applicationInfo();
    m_currentCardUID.clear();
    m_appStatus = m_commMgr->applicationStatus();
    setState(SessionState::EmptyKeycard);

    return true;
}

// Metadata Operations
// NOTE: Implementations moved to after helper functions (line ~945+)
// to avoid forward declaration errors

// Key Export
// NOTE: TLV parsing functions moved to tlv_utils.h/cpp
// All TLV operations now use Keycard::TLV:: utilities

// Parse exported key TLV response
static SessionManager::KeyPair parseExportedKey(const QByteArray& data) {
    SessionManager::KeyPair keyPair;

    if (data.isEmpty()) {
        qWarning() << "parseExportedKey: Empty data";
        return keyPair;
    }

    qDebug() << "StatusKeycardQt::parseExportedKey: Received" << data.size() << "bytes:";
    qDebug() << "StatusKeycardQt::parseExportedKey: Hex dump:" << data.toHex();

    // Find template tag 0xA1 using common TLV utility
    QByteArray template_ = Keycard::TLV::findTag(data, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "Failed to find template tag 0xA1 in exported key";
        qWarning() << "Raw data size:" << data.size() << "bytes";
        qWarning() << "First 32 bytes:" << data.left(32).toHex();
        return keyPair;
    }

    // Find public key (0x80)
    QByteArray pubKey = Keycard::TLV::findTag(template_, 0x80);

    // Find private key (0x81) if available
    QByteArray privKey = Keycard::TLV::findTag(template_, 0x81);
    if (!privKey.isEmpty()) {
        keyPair.privateKey = privKey.toHex();
    }

    // If public key is missing but private key is present, derive it
    if (pubKey.isEmpty() && !privKey.isEmpty()) {
        qDebug() << "StatusKeycardQt::parseExportedKey: Deriving public key from private key";
        pubKey = CryptoUtils::derivePublicKeyFromPrivate(privKey);
        if (pubKey.isEmpty()) {
            qWarning() << "parseExportedKey: Failed to derive public key";
            return keyPair;
        }
        qDebug() << "StatusKeycardQt::parseExportedKey: Derived public key:" << pubKey.toHex();
    }

    // Set public key and address
    if (!pubKey.isEmpty()) {
        keyPair.publicKey = pubKey.toHex();
        keyPair.address = CryptoUtils::publicKeyToAddress(pubKey);
    }

    // Find chain code (0x82) if available
    QByteArray chainCode = Keycard::TLV::findTag(template_, 0x82);
    if (!chainCode.isEmpty()) {
        keyPair.chainCode = chainCode.toHex();
    }

    return keyPair;
}

// Helper methods for exporting keys
// These use executeCommandSync, which is safe within batch operations mode
// (batch mode prevents channel stop/start cycles)
QByteArray SessionManager::exportKeyInternal(bool derive, bool makeCurrent, const QString& path, uint8_t exportType)
{
    if (!ensureKeycardCommunication()) {
        return QByteArray();
    }

    auto cmd = std::make_unique<Keycard::ExportKeyCommand>(derive, makeCurrent, path, exportType);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setError("Cancelled");
        return QByteArray();
    }

    if (!result.success) {
        setError(result.error);
        setState(SessionState::InternalError);
        return QByteArray();
    }

    QVariantMap data = result.data.toMap();
    return data["keyData"].toByteArray();
}

QByteArray SessionManager::exportKeyExtendedInternal(bool derive, bool makeCurrent, const QString& path)
{
    if (!ensureKeycardCommunication()) {
        return QByteArray();
    }

    auto cmd = std::make_unique<Keycard::ExportKeyExtendedCommand>(derive, makeCurrent, path);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setError("Cancelled");
        return QByteArray();
    }

    if (!result.success) {
        setError(result.error);
        return QByteArray();
    }

    QVariantMap data = result.data.toMap();
    return data["keyData"].toByteArray();
}

SessionManager::LoginKeys SessionManager::exportLoginKeys(bool isMainCommand)
{
    // Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);

    // Clear any previous error
    m_lastError.clear();

    LoginKeys keys;

    if (!ensureAuthorized()) {
        return keys;
    }

    // Start batch operations only if this is the main command (not called from exportRecoverKeys)
    if (isMainCommand) {
        m_commMgr->startBatchOperations();
    }

    // Ensure we always end batch operations, even on error (only if we started it)
    // Lambda must accept pointer argument for unique_ptr deleter
    auto batchGuard = [this, isMainCommand](void*) {
        if (isMainCommand) {
            m_commMgr->endBatchOperations();
        }
    };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    // Export encryption private key FIRST (matching status-keycard-go order)
    // Note: makeCurrent=false for all paths except master "m" (matching status-keycard-go)
    qDebug() << "StatusKeycardQt::SessionManager: Exporting encryption key from path:" << PathEncryption;
    QByteArray encryptionData = exportKeyInternal(true, false, PathEncryption, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (encryptionData.isEmpty()) {
        setError(QString("Failed to export encryption key: %1").arg(m_lastError));
        return keys;
    }
    qDebug() << "StatusKeycardQt::SessionManager: Encryption key data size:" << encryptionData.size();
    keys.encryptionPrivateKey = parseExportedKey(encryptionData);

    // Export whisper private key SECOND (matching status-keycard-go order)
    qDebug() << "StatusKeycardQt::SessionManager: Exporting whisper key from path:" << PathWhisper;
    QByteArray whisperData = exportKeyInternal(true, false, PathWhisper, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (whisperData.isEmpty()) {
        setError(QString("Failed to export whisper key: %1").arg(m_lastError));
        return keys;
    }
    qDebug() << "StatusKeycardQt::SessionManager: Whisper key data size:" << whisperData.size();
    keys.whisperPrivateKey = parseExportedKey(whisperData);

    qDebug() << "StatusKeycardQt::SessionManager: Login keys exported successfully";

    return keys;
}

SessionManager::RecoverKeys SessionManager::exportRecoverKeys(bool isMainCommand)
{
    // Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);

    // Clear any previous error
    m_lastError.clear();

    RecoverKeys keys;

    if (!ensureAuthorized()) {
        return keys;
    }

    // Start batch operations only if this is the main command (not called from the caller)
    if (isMainCommand) {
        m_commMgr->startBatchOperations();
    }

    // Ensure we always end batch operations, even on error (only if we started it)
    // Lambda must accept pointer argument for unique_ptr deleter
    auto batchGuard = [this, isMainCommand](void*) {
        if (isMainCommand) {
            m_commMgr->endBatchOperations();
        }
    };
    std::unique_ptr<void, decltype(batchGuard)> guard(reinterpret_cast<void*>(1), batchGuard);

    qDebug() << "StatusKeycardQt::SessionManager: Exporting recover keys";

    // First export login keys
    keys.loginKeys = exportLoginKeys(false);
    if (!m_lastError.isEmpty()) {
        return keys;
    }

    // Export EIP1581 key (public only)
    QByteArray eip1581Data = exportKeyInternal(true, false, PathEip1581, Keycard::APDU::P2ExportKeyPublicOnly);
    if (eip1581Data.isEmpty()) {
        setError(QString("Failed to export EIP1581 key: %1").arg(m_lastError));
        return keys;
    }
    keys.eip1581 = parseExportedKey(eip1581Data);

    // Export wallet root key (extended public if supported, otherwise public only)
    // Check if card supports extended keys (version >= 3.1)
    bool supportsExtended = m_appInfo.appVersion >= 3 && m_appInfo.appVersionMinor >= 1;
    QByteArray walletRootData = supportsExtended ?
        exportKeyExtendedInternal(true, false, PathWalletRoot) :
        exportKeyInternal(true, false, PathWalletRoot, Keycard::APDU::P2ExportKeyPublicOnly);

    if (walletRootData.isEmpty()) {
        setError(QString("Failed to export wallet root key: %1").arg(m_lastError));
        return keys;
    }
    keys.walletRootKey = parseExportedKey(walletRootData);

    // Export wallet key (public only)
    QByteArray walletData = exportKeyInternal(true, false, PathWallet, Keycard::APDU::P2ExportKeyPublicOnly);
    if (walletData.isEmpty()) {
        setError(QString("Failed to export wallet key: %1").arg(m_lastError));
        return keys;
    }
    keys.walletKey = parseExportedKey(walletData);

    // Export master key (public only, derive=false since "m" doesn't need derivation)
    QByteArray masterData = exportKeyInternal(false, false, PathMaster, Keycard::APDU::P2ExportKeyPublicOnly);
    if (masterData.isEmpty()) {
        setError(QString("Failed to export master key: %1").arg(m_lastError));
        return keys;
    }
    keys.masterKey = parseExportedKey(masterData);

    qDebug() << "StatusKeycardQt::SessionManager: Recover keys exported successfully";

    return keys;
}

SessionManager::ExtendedPublicKey SessionManager::exportExtendedPublicKey(const QString& path)
{
    ExtendedPublicKey epk;

    if (!ensureAuthorized()) {
        return epk;
    }

    bool supportsExtended = m_appInfo.appVersion >= 3 && m_appInfo.appVersionMinor >= 1;
    bool isMaster = (path == "m");
    bool derive = !isMaster;

    // Export key at the requested path
    QByteArray keyData = supportsExtended
        ? exportKeyExtendedInternal(derive, isMaster, path)
        : exportKeyInternal(derive, false, path, Keycard::APDU::P2ExportKeyPublicOnly);

    if (keyData.isEmpty()) {
        setError(QString("Failed to export extended public key at path %1: %2").arg(path, m_lastError));
        return epk;
    }

    KeyPair kp = parseExportedKey(keyData);
    epk.address = kp.address;
    epk.publicKey = kp.publicKey;
    epk.chainCode = kp.chainCode;

    Bip32::PathInfo pathInfo = Bip32::parsePath(path);

    QByteArray pubKeyRaw = QByteArray::fromHex(kp.publicKey.toLatin1());
    QByteArray chainCodeRaw = QByteArray::fromHex(kp.chainCode.toLatin1());
    QByteArray compressed = Bip32::compressPublicKey(pubKeyRaw);

    // Compute parent fingerprint (HASH160 of compressed parent public key)
    QByteArray parentFP(4, '\0');
    if (pathInfo.depth > 0) {
        bool parentIsMaster = (pathInfo.parentPath == "m");
        bool parentDerive = !parentIsMaster;

        QByteArray parentData = supportsExtended
            ? exportKeyExtendedInternal(parentDerive, parentIsMaster, pathInfo.parentPath)
            : exportKeyInternal(parentDerive, false, pathInfo.parentPath, Keycard::APDU::P2ExportKeyPublicOnly);

        if (!parentData.isEmpty()) {
            KeyPair parentKp = parseExportedKey(parentData);
            QByteArray parentPubRaw = QByteArray::fromHex(parentKp.publicKey.toLatin1());
            QByteArray parentCompressed = Bip32::compressPublicKey(parentPubRaw);
            if (!parentCompressed.isEmpty()) {
                parentFP = Bip32::hash160(parentCompressed).left(4);
            }
        }
    }

    uint32_t childIndex = pathInfo.childIndexes.isEmpty() ? 0 : pathInfo.childIndexes.last();

    if (!compressed.isEmpty() && chainCodeRaw.size() >= 32) {
        epk.xpub = Bip32::serializeXpub(
            static_cast<uint8_t>(pathInfo.depth),
            parentFP,
            childIndex,
            chainCodeRaw,
            compressed
        );
    }

    return epk;
}

// Metadata Operations Implementation
// These are defined here (after helper functions) to avoid forward declaration issues

SessionManager::Metadata SessionManager::getMetadata(bool isMainCommand)
{
    QMutexLocker locker(&m_operationMutex);

    Metadata metadata;

    if (!ensureKeycardCommunication()) {
        return metadata;
    }

    // Get metadata from card using proper command queue (matching status-keycard-go GetMetadata)
    qDebug() << "StatusKeycardQt::SessionManager: Getting metadata from card";

    auto cmd = std::make_unique<Keycard::GetMetadataCommand>();
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success) {
        if (result.reason == Keycard::CommandResultType::Cancelled) {
            setError("Cancelled");
        }
        // Not an error - might just be empty
        qDebug() << "StatusKeycardQt::SessionManager: No metadata on card or error:" << result.error;
        return metadata;
    }

    QVariantMap data = result.data.toMap();
    QByteArray metadataData = data["tlvData"].toByteArray();

    if (metadataData.isEmpty()) {
        // Not an error - card might not have metadata yet
        qDebug() << "StatusKeycardQt::SessionManager: No metadata on card";
        return metadata;
    }

    // Parse metadata using Go's custom binary format (matching types/metadata.go ParseMetadata())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    //   Byte 0: version (3 bits) + name length (5 bits)
    //   Bytes 1..namelen: card name
    //   Remaining: series of start/count LEB128 pairs for wallet paths

    int offset = 0;
    if (offset >= metadataData.size()) {
        qDebug() << "StatusKeycardQt::SessionManager: Metadata too short";
        return metadata;
    }

    // Parse header byte
    uint8_t header = static_cast<uint8_t>(metadataData[offset++]);
    uint8_t version = header >> 5;
    uint8_t namelen = header & 0x1F;

    qDebug() << "StatusKeycardQt::SessionManager: Metadata version:" << version << "namelen:" << namelen;

    if (version != 1) {
        qWarning() << "SessionManager: Invalid metadata version:" << version;
        return metadata;
    }

    // Parse card name
    if (namelen > 0) {
        if (offset + namelen > metadataData.size()) {
            qWarning() << "SessionManager: Metadata too short for name";
            return metadata;
        }
        QByteArray nameData = metadataData.mid(offset, namelen);
        metadata.name = QString::fromUtf8(nameData);
        offset += namelen;
        qDebug() << "StatusKeycardQt::SessionManager: Card name:" << metadata.name;
    }

    // Parse wallet paths (LEB128 encoded start/count pairs)
    while (offset < metadataData.size()) {
        // Parse start index (LEB128)
        uint32_t start = 0;
        int shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            start |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }

        if (offset >= metadataData.size()) break;

        // Parse count (LEB128)
        uint32_t count = 0;
        shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            count |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }

        // Add all paths in range [start, start+count]
        // Expand to full paths like Go's ToMetadata() does
        for (uint32_t i = start; i <= start + count; ++i) {
            QString walletPath = PathWalletRoot + QString("/%1").arg(i);
            Wallet wallet;
            wallet.path = walletPath;
            // Note: address and publicKey are left empty (not resolved)
            // Use exportKey() separately if you need those
            metadata.wallets.append(wallet);
        }
    }

    qDebug() << "StatusKeycardQt::SessionManager: Metadata retrieved - name:" << metadata.name
             << "wallets:" << metadata.wallets.size();

    return metadata;
}

bool SessionManager::storeMetadata(const QString& name, const QStringList& paths)
{
    qDebug() << "StatusKeycardQt::SessionManager: Storing metadata - name:" << name << "paths:" << paths.size();
    QMutexLocker locker(&m_operationMutex);

    if (!ensureAuthorized()) {
        return false;
    }

    // Store metadata using proper command queue
    auto cmd = std::make_unique<Keycard::StoreMetadataCommand>(name, paths);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd));

    if (!result.success && result.reason == Keycard::CommandResultType::Cancelled) {
        setError("Cancelled");
        return false;
    }

    if (!result.success) {
        setError(QString("Failed to store metadata: %1").arg(result.error));
        return false;
    }

    qDebug() << "StatusKeycardQt::SessionManager: Metadata stored successfully";

    m_metadata.name = name;
    for (const QString& path : paths) {
        m_metadata.wallets.append({
            .path = path,
            .address = "",
            .publicKey = ""
        });
    }

    return true;
}

} // namespace StatusKeycard

