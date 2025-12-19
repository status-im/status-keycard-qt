#include "session_manager.h"
#include "signal_manager.h"
#include <keycard-qt/types.h>
#include <keycard-qt/tlv_utils.h>
#include <keycard-qt/metadata_utils.h>
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
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace StatusKeycard {

// LEB128 (Little Endian Base 128) encoding
// Used for encoding wallet path components (matching Go's apdu.WriteLength)
// NOTE: LEB128 utilities moved to metadata_utils.h/cpp for reuse across the codebase

// Derivation paths matching status-keycard-go/internal/const.go
static const QString PATH_MASTER = "m";
static const QString PATH_WALLET_ROOT = "m/44'/60'/0'/0";
static const QString PATH_WALLET = "m/44'/60'/0'/0/0";
static const QString PATH_EIP1581 = "m/43'/60'/1581'";
static const QString PATH_WHISPER = "m/43'/60'/1581'/0'/0";
static const QString PATH_ENCRYPTION = "m/43'/60'/1581'/1'/0";

SessionManager::SessionManager(QObject* parent)
    : QObject(parent)
    , m_state(SessionState::UnknownReaderState)
    , m_started(false)
    , m_stateCheckTimer(new QTimer(this))
{
    // CRITICAL: Ensure we're in the main Qt thread for NFC events
    QThread* mainThread = QCoreApplication::instance()->thread();
    QThread* currentThread = QThread::currentThread();
    
    qDebug() << "SessionManager: Constructor called in thread:" << currentThread;
    qDebug() << "SessionManager: Main thread is:" << mainThread;
    
    if (currentThread != mainThread) {
        qWarning() << "SessionManager: Created in wrong thread! Moving to main thread...";
        moveToThread(mainThread);
        qDebug() << "SessionManager: Moved to main thread";
    }
}

SessionManager::~SessionManager()
{
    stop();
}

// Removed: startCardOperation() and operationCompleted() - not needed with CommunicationManager

void SessionManager::setCommunicationManager(std::shared_ptr<Keycard::CommunicationManager> commMgr)
{
    if (m_started) {
        qWarning() << "SessionManager: Cannot set CommunicationManager while started";
        return;
    }
    
    if (m_commMgr == commMgr) {
        qDebug() << "SessionManager::setCommunicationManager() - CommunicationManager not changed";
        return;
    }

    qDebug() << "SessionManager::setCommunicationManager() - Setting CommunicationManager";
    m_commMgr = commMgr;
}

bool SessionManager::start(bool logEnabled, const QString& logFilePath)
{
    if (!m_commMgr) {
        qWarning() << "SessionManager: No CommunicationManager available";
        qWarning() << "SessionManager: Call setCommunicationManager() before start()";
        return false;
    }
    
    qDebug() << "SessionManager: Starting with CommunicationManager";

    // Disconnect any previous connections
    QObject::disconnect(m_commMgr.get(), nullptr, this, nullptr);
    
    // Connect to CommunicationManager signals
    connect(m_commMgr.get(), &Keycard::CommunicationManager::cardInitialized,
            this, &SessionManager::onCardInitialized,
            Qt::QueuedConnection);
    
    connect(m_commMgr.get(), &Keycard::CommunicationManager::cardLost,
            this, &SessionManager::onCardRemoved,
            Qt::QueuedConnection);
    
    // Start card detection (CommunicationManager should already be init'd by caller)
    if (!m_commMgr->startDetection()) {
        qWarning() << "SessionManager: Failed to start card detection";
        return false;
    }
    
    setState(SessionState::WaitingForCard);
    m_started = true;
    
    qDebug() << "SessionManager: Started successfully, monitoring for cards";
    return true;
}

void SessionManager::stop()
{
    if (!m_started) {
        return;
    }
    
    qDebug() << "SessionManager: Stopping...";
    
    // Stop card detection
    if (m_commMgr) {
        m_commMgr->stopDetection();
    }
    
    m_started = false;
    m_currentCardUID.clear();
    setState(SessionState::UnknownReaderState);
    
    qDebug() << "SessionManager: Stopped (detection paused, can restart with start())";
}

void SessionManager::setState(SessionState newState)
{
    qDebug() << "SessionManager::setState() - New state: "<< sessionStateToString(newState);
    
    if (newState == m_state) {
        return;
    }
    
    SessionState oldState = m_state;
    m_state = newState;
    
    // Emit Qt signal - c_api.cpp will forward to SignalManager
    emit stateChanged(newState, oldState);
}

void SessionManager::onCardInitialized(Keycard::CardInitializationResult result)
{
    qDebug() << "========================================";
    qDebug() << "SessionManager: CARD INITIALIZED";
    qDebug() << "========================================";
    
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
        qDebug() << "SessionManager: Card is empty (not initialized)";
        setState(SessionState::EmptyKeycard);
    } else {
        qDebug() << "SessionManager: Card is ready";
        setState(SessionState::Ready);
    }
}

void SessionManager::onCardRemoved()
{
    qDebug() << "========================================";
    qDebug() << "SessionManager: CARD REMOVED";
    qDebug() << "========================================";
    
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    qDebug() << "Ignoring card removal on mobile";
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
    m_lastError = error;
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

    if ((m_state == SessionState::Ready || m_state == SessionState::Authorized) && m_appStatus.pinRetryCount >= 0) {
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
    qDebug() << "SessionManager::initialize()";
    QMutexLocker locker(&m_operationMutex);
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::InitCommand>(pin, puk, pairingPassword);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 60000);
    
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
    qDebug() << "SessionManager::authorize() - Thread:" << QThread::currentThread();
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }
    
    if (m_state != SessionState::Ready) {
        setError("Card not ready (current state: " + currentStateString() + ")");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::VerifyPINCommand>(pin);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (result.success) {
        // Update status from result
        QVariantMap data = result.data.toMap();
        m_appStatus.pinRetryCount = data["remainingAttempts"].toInt();
        
        setState(SessionState::Authorized);
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::changePIN(const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::ChangePINCommand>(newPIN);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (result.success) {
        qDebug() << "SessionManager: PIN changed";
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::changePUK(const QString& newPUK)
{
    QMutexLocker locker(&m_operationMutex);

    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::ChangePUKCommand>(newPUK);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (result.success) {
        qDebug() << "SessionManager: PUK changed";
        return true;
    } else {
        setError(result.error);
        return false;
    }
}

bool SessionManager::unblockPIN(const QString& puk, const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }

    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::UnblockPINCommand>(puk, newPIN);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (result.success) {
        qDebug() << "SessionManager: PIN unblocked";
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

    if (!m_commMgr) {
        setError("No communication manager available");
        return QVector<int>();
    }

    int checksumSize = 4; // Default
    if (length == 15) checksumSize = 5;
    else if (length == 18) checksumSize = 6;
    else if (length == 21) checksumSize = 7;
    else if (length == 24) checksumSize = 8;
    
    auto cmd = std::make_unique<Keycard::GenerateMnemonicCommand>(checksumSize);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
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
    
    if (!m_commMgr) {
        setError("No communication manager available");
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
    qDebug() << "SessionManager: Loading seed onto keycard (" << seed.size() << " bytes)";
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return QString();
    }
    
    auto cmd = std::make_unique<Keycard::LoadSeedCommand>(seed);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 60000);
    
    if (!result.success) {
        setError(QString("Failed to load seed: %1").arg(result.error));
        return QString();
    }
    
    QVariantMap data = result.data.toMap();
    QByteArray keyUID = QByteArray::fromHex(data["keyUID"].toString().toUtf8());
    
    qDebug() << "SessionManager: Seed loaded successfully, keyUID:" << keyUID.toHex();
    
    return QString("0x") + keyUID.toHex();
}

bool SessionManager::factoryReset()
{
    QMutexLocker locker(&m_operationMutex);
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }
    
    setState(SessionState::FactoryResetting);
    
    auto cmd = std::make_unique<Keycard::FactoryResetCommand>();
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 60000);
    
    if (!result.success) {
        setError(result.error);
        setState(SessionState::InternalError);
        return false;
    }
    
    qDebug() << "SessionManager: Factory reset complete";
    
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

// Compute Ethereum address from public key using Qt's QCryptographicHash
static QString publicKeyToAddress(const QByteArray& pubKey) {
    if (pubKey.size() != 65 || pubKey[0] != 0x04) {
        qWarning() << "Invalid public key format";
        return QString();
    }
    
    // Remove 0x04 prefix, hash with Keccak-256, take last 20 bytes
    QByteArray pubKeyData = pubKey.mid(1);
    QByteArray hash = QCryptographicHash::hash(pubKeyData, QCryptographicHash::Keccak_256);
    QByteArray address = hash.right(20);
    
    return QString("0x") + address.toHex();
}

// Derive public key from private key using OpenSSL secp256k1
static QByteArray derivePublicKeyFromPrivate(const QByteArray& privKey) {
    if (privKey.size() != 32) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid private key size:" << privKey.size();
        return QByteArray();
    }
    
    // Create EC_KEY for secp256k1
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to create EC_KEY";
        return QByteArray();
    }
    
    // Set private key
    BIGNUM* priv_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(privKey.data()), privKey.size(), nullptr);
    if (!priv_bn || !EC_KEY_set_private_key(eckey, priv_bn)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to set private key";
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return QByteArray();
    }
    
    // Compute public key from private key
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to compute public key";
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return QByteArray();
    }
    
    EC_KEY_set_public_key(eckey, pub_point);
    
    // Export public key in uncompressed format (0x04 + X + Y)
    unsigned char pub_key_bytes[65];
    size_t pub_key_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, 
                                            pub_key_bytes, sizeof(pub_key_bytes), nullptr);
    
    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);
    
    if (pub_key_len != 65) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid public key length:" << pub_key_len;
        return QByteArray();
    }
    
    return QByteArray(reinterpret_cast<const char*>(pub_key_bytes), pub_key_len);
}

// Parse exported key TLV response
static SessionManager::KeyPair parseExportedKey(const QByteArray& data) {
    SessionManager::KeyPair keyPair;
    
    if (data.isEmpty()) {
        qWarning() << "parseExportedKey: Empty data";
        return keyPair;
    }
    
    qDebug() << "parseExportedKey: Received" << data.size() << "bytes:";
    qDebug() << "parseExportedKey: Hex dump:" << data.toHex();
    
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
        qDebug() << "parseExportedKey: Deriving public key from private key";
        pubKey = derivePublicKeyFromPrivate(privKey);
        if (pubKey.isEmpty()) {
            qWarning() << "parseExportedKey: Failed to derive public key";
            return keyPair;
        }
        qDebug() << "parseExportedKey: Derived public key:" << pubKey.toHex();
    }
    
    // Set public key and address
    if (!pubKey.isEmpty()) {
        keyPair.publicKey = pubKey.toHex();
        keyPair.address = publicKeyToAddress(pubKey);
    }
    
    // Find chain code (0x82) if available
    QByteArray chainCode = Keycard::TLV::findTag(template_, 0x82);
    if (!chainCode.isEmpty()) {
        keyPair.chainCode = chainCode.toHex();
    }
    
    return keyPair;
}

// Helper methods for exporting keys
QByteArray SessionManager::exportKeyInternal(bool derive, bool makeCurrent, const QString& path, uint8_t exportType)
{
    if (!m_commMgr) {
        setError("No communication manager available");
        return QByteArray();
    }
    
    auto cmd = std::make_unique<Keycard::ExportKeyCommand>(derive, makeCurrent, path, exportType);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
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
    if (!m_commMgr) {
        setError("No communication manager available");
        return QByteArray();
    }
    
    auto cmd = std::make_unique<Keycard::ExportKeyExtendedCommand>(derive, makeCurrent, path);
    Keycard::CommandResult result = m_commMgr->executeCommandSync(std::move(cmd), 30000);
    
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
    
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return keys;
    }
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return keys;
    }

    qDebug() << "SessionManager: Exporting whisper key from path:" << PATH_WHISPER;
    QByteArray whisperData = exportKeyInternal(true, true, PATH_WHISPER, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (whisperData.isEmpty()) {
        setError(QString("Failed to export whisper key: %1").arg(m_lastError));
        return keys;
    }
    qDebug() << "SessionManager: Whisper key data size:" << whisperData.size();
    keys.whisperPrivateKey = parseExportedKey(whisperData);

    // Export encryption private key
    // Now we can use makeCurrent=false since the whisper export already set the card state
    qDebug() << "SessionManager: Exporting encryption key from path:" << PATH_ENCRYPTION;
    QByteArray encryptionData = exportKeyInternal(true, false, PATH_ENCRYPTION, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (encryptionData.isEmpty()) {
        setError(QString("Failed to export encryption key: %1").arg(m_lastError));
        return keys;
    }
    qDebug() << "SessionManager: Encryption key data size:" << encryptionData.size();
    keys.encryptionPrivateKey = parseExportedKey(encryptionData);
    
    qDebug() << "SessionManager: Login keys exported successfully";
    
    return keys;
}

SessionManager::RecoverKeys SessionManager::exportRecoverKeys()
{
    // Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);
    
    // Clear any previous error
    m_lastError.clear();
    
    RecoverKeys keys;
    
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return keys;
    }
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return keys;
    }
    
    qDebug() << "SessionManager: Exporting recover keys";
    
    // First export login keys
    keys.loginKeys = exportLoginKeys(false);
    if (!m_lastError.isEmpty()) {
        return keys;
    }
    
    // Export EIP1581 key (public only)
    QByteArray eip1581Data = exportKeyInternal(true, false, PATH_EIP1581);
    if (eip1581Data.isEmpty()) {
        setError(QString("Failed to export EIP1581 key: %1").arg(m_lastError));
        return keys;
    }
    keys.eip1581 = parseExportedKey(eip1581Data);
    
    // Export wallet root key (extended public if supported, otherwise public only)
    // Check if card supports extended keys (version >= 3.1)
    bool supportsExtended = m_appInfo.appVersion >= 3 && m_appInfo.appVersionMinor >= 1;
    QByteArray walletRootData = supportsExtended ?
        exportKeyExtendedInternal(true, false, PATH_WALLET_ROOT) :
        exportKeyInternal(true, false, PATH_WALLET_ROOT);
    
    if (walletRootData.isEmpty()) {
        setError(QString("Failed to export wallet root key: %1").arg(m_lastError));
        return keys;
    }
    keys.walletRootKey = parseExportedKey(walletRootData);
    
    // Export wallet key (public only)
    QByteArray walletData = exportKeyInternal(true, false, PATH_WALLET);
    if (walletData.isEmpty()) {
        setError(QString("Failed to export wallet key: %1").arg(m_lastError));
        return keys;
    }
    keys.walletKey = parseExportedKey(walletData);
    
    // Export master key (public only, makeCurrent=true for compatibility)
    QByteArray masterData = exportKeyInternal(true, true, PATH_MASTER);
    if (masterData.isEmpty()) {
        setError(QString("Failed to export master key: %1").arg(m_lastError));
        return keys;
    }
    keys.masterKey = parseExportedKey(masterData);
    
    qDebug() << "SessionManager: Recover keys exported successfully";
    
    return keys;
}

// Metadata Operations Implementation
// These are defined here (after helper functions) to avoid forward declaration issues

SessionManager::Metadata SessionManager::getMetadata(bool isMainCommand)
{
    QMutexLocker locker(&m_operationMutex);

    Metadata metadata;

    if (!m_commMgr) {
        setError("No communication manager available");
        return metadata;
    }
    
    // Get metadata from card (matching status-keycard-go GetMetadata)
    qDebug() << "SessionManager: Getting metadata from card";
    QByteArray metadataData = m_commMgr->getDataFromCard(Keycard::APDU::P1StoreDataPublic);  // 0x00
    
    // Check if data looks like a status word (error response)
    if (metadataData.size() == 2) {
        uint16_t sw = (static_cast<uint8_t>(metadataData[0]) << 8) | static_cast<uint8_t>(metadataData[1]);
        if (sw != 0x9000) {  // Not success
            qDebug() << "SessionManager: Card returned status word:" << QString("0x%1").arg(sw, 4, 16, QChar('0'));
            qDebug() << "SessionManager: No metadata on card (error or empty)";
            return metadata;
        }
    }
    
    if (metadataData.isEmpty()) {
        // Not an error - card might not have metadata yet
        qDebug() << "SessionManager: No metadata on card";
        return metadata;
    }
    
    // Parse metadata using Go's custom binary format (matching types/metadata.go ParseMetadata())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    //   Byte 0: version (3 bits) + name length (5 bits)
    //   Bytes 1..namelen: card name
    //   Remaining: series of start/count LEB128 pairs for wallet paths
    
    int offset = 0;
    if (offset >= metadataData.size()) {
        qDebug() << "SessionManager: Metadata too short";
        return metadata;
    }
    
    // Parse header byte
    uint8_t header = static_cast<uint8_t>(metadataData[offset++]);
    uint8_t version = header >> 5;
    uint8_t namelen = header & 0x1F;
    
    qDebug() << "SessionManager: Metadata version:" << version << "namelen:" << namelen;
    
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
        qDebug() << "SessionManager: Card name:" << metadata.name;
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
            QString walletPath = PATH_WALLET_ROOT + QString("/%1").arg(i);
            Wallet wallet;
            wallet.path = walletPath;
            // Note: address and publicKey are left empty (not resolved)
            // Use exportKey() separately if you need those
            metadata.wallets.append(wallet);
        }
    }
    
    qDebug() << "SessionManager: Metadata retrieved - name:" << metadata.name
             << "wallets:" << metadata.wallets.size();
    
    return metadata;
}

bool SessionManager::storeMetadata(const QString& name, const QStringList& paths)
{
    qDebug() << "SessionManager: Storing metadata - name:" << name << "paths:" << paths.size();
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    if (!m_commMgr) {
        setError("No communication manager available");
        return false;
    }
    
    // Encode metadata using common utility
    QString errorMsg;
    QByteArray metadata = Keycard::MetadataEncoding::encode(name, paths, errorMsg);
    
    if (metadata.isEmpty()) {
        setError(errorMsg);
        return false;
    }
    
    qDebug() << "SessionManager: Encoded metadata size:" << metadata.size() << "bytes";
    qDebug() << "SessionManager: Metadata hex:" << metadata.toHex();
    
    // Store metadata on card (public data type)
    // Use P1StoreDataPublic (0x00) as defined in status-keycard-go
    bool success = m_commMgr->storeDataToCard(0x00, metadata);  // 0x00 = P1StoreDataPublic
    
    if (!success) {
        setError("Failed to store metadata");
        return false;
    }

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

