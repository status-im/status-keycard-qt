#include "flow_base.h"
#include "../flow_manager.h"
#include "../flow_signals.h"
#include <keycard-qt/keycard_channel.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/tlv_utils.h>
#include <QDebug>
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <QCryptographicHash>
#include <QJsonArray>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace StatusKeycard {

FlowBase::FlowBase(FlowManager* manager, FlowType type, const QJsonObject& params, QObject* parent)
    : QObject(parent)
    , m_manager(manager)
    , m_flowType(type)
    , m_params(params)
    , m_paused(false)
    , m_cancelled(false)
    , m_shouldRestart(false)
{
}

FlowBase::~FlowBase()
{
}

const FlowBase::CardInfo FlowBase::cardInfo() const {
    return buildCardInfo();
}

void FlowBase::resume(const QJsonObject& newParams)
{
    QMutexLocker locker(&m_resumeMutex);
    
    // Merge new params into existing params
    for (auto it = newParams.begin(); it != newParams.end(); ++it) {
        m_params[it.key()] = it.value();
    }
    
    // Wake up flow
    m_paused = false;
    m_resumeCondition.wakeAll();
}

void FlowBase::cancel()
{
    QMutexLocker locker(&m_resumeMutex);
    m_cancelled = true;
    m_resumeCondition.wakeAll();
}

// ============================================================================
// Access to manager resources
// ============================================================================

std::shared_ptr<Keycard::CommandSet> FlowBase::commandSet() const { 
    if (!m_manager) {
        qWarning() << "FlowBase::commandSet() No FlowManager available";
        return nullptr;
    }
    return m_manager->commandSet();
}

std::shared_ptr<Keycard::ICommunicationManager> FlowBase::communicationManager() const {
    if (!m_manager) {
        qWarning() << "FlowBase::communicationManager() No FlowManager available";
        return nullptr;
    }
    return m_manager->communicationManager();
}

// ============================================================================
// Pause/Resume mechanism
// ============================================================================

void FlowBase::pauseAndWait(const QString& action, const QString& error)
{
    pauseAndWaitWithStatus(action, error, QJsonObject());
}

void FlowBase::pauseAndWaitWithStatus(const QString& action, const QString& error, 
                                     const QJsonObject& status)
{
    
    // Build event with error and status
    QJsonObject event = status;
    event[FlowParams::ERROR_KEY] = error;
    auto info = cardInfo();

    // Add card info if available
    if (info.freeSlots >= 0) {
        event[FlowParams::INSTANCE_UID] = info.instanceUID;
        event[FlowParams::KEY_UID] = info.keyUID;
        event[FlowParams::FREE_SLOTS] = info.freeSlots;
    }
    
    if (info.pinRetries >= 0) {
        event[FlowParams::PIN_RETRIES] = info.pinRetries;
        event[FlowParams::PUK_RETRIES] = info.pukRetries;
    }
    
    // Emit pause signal
    emit flowPaused(action, event);
    
    // Wait for resume or cancel
    QMutexLocker locker(&m_resumeMutex);
    m_paused = true;
    
    while (m_paused && !m_cancelled) {
        m_resumeCondition.wait(&m_resumeMutex);
    }
}

void FlowBase::pauseAndRestart(const QString& action, const QString& error)
{
    m_shouldRestart = true;
    pauseAndWait(action, error);
}

// ============================================================================
// Card operations
// ============================================================================

bool FlowBase::selectKeycard()
{
    qDebug() << "FlowBase::selectKeycard()";
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "FlowBase: CommunicationManager not available (should never happen after Phase 4)";
        emit flowError("CommunicationManager not initialized");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::SelectCommand>(false);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        qCritical() << "FlowBase: SELECT failed:" << result.error;
        emit flowError(result.error);
        return false;
    }
    
    // Check if applet is installed
    QVariantMap data = result.data.toMap();
    bool installed = data["installed"].toBool();
    
    if (!installed) {
        qCritical() << "FlowBase: Keycard applet not installed!";
        emit flowError("Keycard applet not installed");
        return false;
    }
    
    qDebug() << "FlowBase::selectKeycard() - SUCCESS";
    return true;
}

FlowResult FlowBase::initializeKeycard()
{
    // Check if card is initialized (pre-initialized cards need initialization first)
    // This matches status-keycard-go behavior: pause and ask for PIN/PUK/pairing
    QJsonObject result = buildCardInfoJson();

    QString pin = m_params[FlowParams::NEW_PIN].toString();
    if (pin.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "require-init");
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        pin = m_params[FlowParams::NEW_PIN].toString();
    }

    QString puk = m_params[FlowParams::NEW_PUK].toString();
    if (puk.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PUK, "require-init");
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        puk = m_params[FlowParams::NEW_PUK].toString();
    }

    QString pairingPassword = m_params[FlowParams::NEW_PAIRING].toString();
    if (pairingPassword.isEmpty()) {
        pairingPassword = "KeycardDefaultPairing";
    }
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "FlowBase: CommunicationManager not available";
        result[FlowParams::ERROR_KEY] = "init-failed";
        return FlowResult{false, result};
    }
    
    auto cmd = std::make_unique<Keycard::InitCommand>(pin, puk, pairingPassword);
    Keycard::CommandResult cmdResult = commMgr->executeCommandSync(std::move(cmd), 60000);
    
    if (!cmdResult.success) {
        qWarning() << "FlowBase: Card initialization failed:" << cmdResult.error;
        result[FlowParams::ERROR_KEY] = "init-failed";
        return FlowResult{false, result};
    }
    
    qDebug() << "FlowBase::initializeKeycard() - SUCCESS";
    return FlowResult{true, buildCardInfoJson()};
}

bool FlowBase::unblockPIN()
{
    qDebug() << "FlowBase: Unblocking PIN...";

    QString puk = m_params[FlowParams::PUK].toString();

    if (puk.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_PUK, "");
        if (m_cancelled) {
            return false;
        }
        puk = m_params[FlowParams::PUK].toString();
    }

    QString newPIN = m_params[FlowParams::NEW_PIN].toString();

    if (newPIN.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "unblocking");
        if (m_cancelled) {
            return false;
        }
        newPIN = m_params[FlowParams::NEW_PIN].toString();
    }

    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "FlowBase: CommunicationManager not available";
        emit flowError("CommunicationManager not initialized");
        return false;
    }
    
    auto cmd = std::make_unique<Keycard::UnblockPINCommand>(puk, newPIN);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        // Check if PUK is exhausted
        auto status = commMgr->applicationStatus();
        if (status.pukRetryCount == 0) {
            qCritical() << "FlowBase: PUK exhausted!";
            return false;
        }
        
        qWarning() << "FlowBase: Unblock PIN failed:" << result.error;
        pauseAndWait(FlowSignals::ENTER_PUK, "puk");
        if (m_cancelled) {
            return false;
        }
        return unblockPIN();
    }
    
    m_params[FlowParams::PIN] = newPIN;
    qDebug() << "FlowBase::unblockPIN() - SUCCESS";
    return true;
}

bool FlowBase::verifyPIN(bool giveup)
{
    qDebug() << "FlowBase: Verifying PIN...";
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "FlowBase: CommunicationManager not available";
        emit flowError("CommunicationManager not initialized");
        return false;
    }
    
    // Check card info (should be available from CommunicationManager)
    auto selectCommand = std::make_unique<Keycard::SelectCommand>(false);
    Keycard::CommandResult selectResult = commMgr->executeCommandSync(std::move(selectCommand), 30000);
    if (!selectResult.success) {
        qCritical() << "FlowBase: Select command failed:" << selectResult.error;
        emit flowError(selectResult.error);
        return false;
    }
    QVariantMap selectData = selectResult.data.toMap();
    bool initialized = selectData["initialized"].toBool();
    
    if (!initialized) {
        if (!giveup)
            return initializeKeycard().ok;
        return true;
    }

    // Check PIN status
    auto appStatus = commMgr->applicationStatus();
    if (appStatus.pinRetryCount == 0) {
        qWarning() << "FlowBase: PIN blocked!";
        auto ok = unblockPIN();
        if (m_cancelled) {
            return false;
        }
        if (!ok) {
            pauseAndRestart(FlowSignals::SWAP_CARD, "puk-retries");
            return false;
        }
    }
    
    // Check if PIN already in params
    QString pin = m_params[FlowParams::PIN].toString();
    
    if (pin.isEmpty()) {
        // Request PIN (empty error means normal PIN request, not an error condition)
        pauseAndWait(FlowSignals::ENTER_PIN, "");
        
        if (m_cancelled) {
            return false;
        }
        
        pin = m_params[FlowParams::PIN].toString();
    }
    
    if (pin.isEmpty()) {
        qWarning() << "FlowBase: No PIN provided!";
        emit flowError("No PIN provided");
        return false;
    }
    
    // Verify PIN using command
    auto cmd = std::make_unique<Keycard::VerifyPINCommand>(pin);
    Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd), 30000);
    
    if (!result.success) {
        qCritical() << "FlowBase: PIN verification failed:" << result.error;
        // Wrong PIN, ask again (pauseAndWait will include pinRetries in the event)
        pauseAndWait(FlowSignals::ENTER_PIN, "pin");
        
        if (m_cancelled) {
            return false;
        }
        
        // Retry
        return verifyPIN();
    }
    
    qDebug() << "FlowBase: PIN verified successfully";
    return true;
}

bool FlowBase::requireKeys()
{
    if (!cardInfo().keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has keys";
        return true;
    }
    
    qWarning() << "FlowBase: Card has no keys!";

    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "no-keys");
    
    // If we get here and not cancelled, restart was requested
    return false; // Will restart flow
}

FlowResult FlowBase::requireNoKeys()
{
    QJsonObject result = buildCardInfoJson();
    if (cardInfo().keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has no keys (as required)";
        return {true, result};
    }
    
    // Check if overwrite allowed
    if (m_params.contains(FlowParams::OVERWRITE) && 
        m_params[FlowParams::OVERWRITE].toBool()) {
        qDebug() << "FlowBase: Card has keys but overwrite allowed";
        return {true, result};
    }
    
    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "has-keys");
    
    result[FlowParams::ERROR_KEY] = "has-keys";
    return {false, result}; // Will restart flow
}

// Convert BIP39 mnemonic to binary seed using PBKDF2-HMAC-SHA512
// This matches the BIP39 standard and status-keycard-go implementation
QByteArray FlowBase::mnemonicToSeed(const QString& mnemonic, const QString& password)
{
    // BIP39 standard:
    // - Key: mnemonic (NFKD normalized)
    // - Salt: "mnemonic" + password (NFKD normalized)
    // - Iterations: 2048
    // - Key length: 64 bytes
    // - Hash: SHA-512
    
    // Qt's QString already handles Unicode, we use normalized form for consistency
    QString normalizedMnemonic = mnemonic.normalized(QString::NormalizationForm_D);
    QString normalizedPassword = password.normalized(QString::NormalizationForm_D);
    
    // BIP39 salt is "mnemonic" + password
    QString saltString = QString("mnemonic") + normalizedPassword;
    
    QByteArray mnemonicBytes = normalizedMnemonic.toUtf8();
    QByteArray saltBytes = saltString.toUtf8();
    
    // Allocate 64 bytes for the derived key (BIP39 standard)
    QByteArray seed(64, 0);
    
    // Use OpenSSL's PBKDF2-HMAC-SHA512
    int result = PKCS5_PBKDF2_HMAC(
        mnemonicBytes.constData(), mnemonicBytes.size(),
        reinterpret_cast<const unsigned char*>(saltBytes.constData()), saltBytes.size(),
        2048,  // iterations (BIP39 standard)
        EVP_sha512(),
        64,    // key length (BIP39 standard)
        reinterpret_cast<unsigned char*>(seed.data())
    );
    
    if (result != 1) {
        qWarning() << "LoadAccountFlow: PBKDF2 failed";
        return QByteArray();
    }
    
    return seed;
}

FlowResult FlowBase::loadMnemonic()
{
    // Get mnemonic from params (or generate indexes and pause to request it)
    QString mnemonic = m_params[FlowParams::MNEMONIC].toString();
    
    if (mnemonic.isEmpty()) {
        int mnemonicLength = 12; // Default BIP39 mnemonic length
        if (m_params.contains(FlowParams::MNEMONIC_LEN)) {
            mnemonicLength = m_params[FlowParams::MNEMONIC_LEN].toInt();
        }
        int checksumSize = mnemonicLength / 3;
        
        QJsonObject result = buildCardInfoJson();
        
        // Phase 6: CommunicationManager is always available
        auto commMgr = communicationManager();
        if (!commMgr) {
            qCritical() << "FlowBase: CommunicationManager not available";
            result[FlowParams::ERROR_KEY] = "generate-failed";
            return FlowResult{false, result};
        }
        
        auto cmd = std::make_unique<Keycard::GenerateMnemonicCommand>(checksumSize);
        Keycard::CommandResult cmdResult = commMgr->executeCommandSync(std::move(cmd), 30000);
        
        if (!cmdResult.success) {
            qWarning() << "LoadAccountFlow: Failed to generate mnemonic:" << cmdResult.error;
            result[FlowParams::ERROR_KEY] = "generate-failed";
            return FlowResult{false, result};
        }
        
        // Extract indexes from result
        QVariantList indexList = cmdResult.data.toList();
        QVector<int> indexes;
        for (const QVariant& v : indexList) {
            indexes.append(v.toInt());
        }
        
        // Add mnemonic-indexes array
        QJsonArray indexesArray;
        for (int idx : indexes) {
            indexesArray.append(idx);
        }
        result[FlowParams::MNEMONIC_IDXS] = indexesArray;

        pauseAndWaitWithStatus(FlowSignals::ENTER_MNEMONIC, "loading-keys", result);
        
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        mnemonic = m_params[FlowParams::MNEMONIC].toString();
    }

    // Convert mnemonic to seed using BIP39 standard (PBKDF2-HMAC-SHA512)
    QByteArray seed = mnemonicToSeed(mnemonic, "");
    if (seed.isEmpty()) {
        qWarning() << "LoadAccountFlow: Failed to convert mnemonic to seed";
        QJsonObject result = buildCardInfoJson();
        result[FlowParams::ERROR_KEY] = "mnemonic-conversion-failed";
        return FlowResult{false, result};
    }
    
    // Load seed onto card
    QJsonObject result = buildCardInfoJson();
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "FlowBase: CommunicationManager not available";
        result[FlowParams::ERROR_KEY] = "load-failed";
        return FlowResult{false, result};
    }
    
    auto cmd = std::make_unique<Keycard::LoadSeedCommand>(seed);
    Keycard::CommandResult cmdResult = commMgr->executeCommandSync(std::move(cmd), 60000);
    
    if (!cmdResult.success) {
        qWarning() << "LoadAccountFlow: Failed to load seed:" << cmdResult.error;
        result[FlowParams::ERROR_KEY] = "load-failed";
        return FlowResult{false, result};
    }
    
    // Extract keyUID from result
    QVariantMap data = cmdResult.data.toMap();
    QString keyUIDHex = data["keyUID"].toString();
    result[FlowParams::KEY_UID] = QString("0x") + keyUIDHex;
    
    qDebug() << "FlowBase::loadMnemonic() - SUCCESS";
    return FlowResult{true, result};
}

// ============================================================================
// Card information
// ============================================================================

FlowBase::CardInfo FlowBase::buildCardInfo() const
{
    FlowBase::CardInfo result;
    if (!communicationManager())
        return result;

    auto appInfo = communicationManager()->applicationInfo();
    auto appStatus = communicationManager()->applicationStatus();

    result.instanceUID = appInfo.instanceUID.toHex();
    result.keyUID = appInfo.keyUID.toHex();
    result.initialized = appInfo.initialized;
    result.freeSlots = appInfo.availableSlots;
    result.keyInitialized = !appInfo.keyUID.isEmpty();
    result.version = (appInfo.appVersion << 8) | appInfo.appVersionMinor;
    
    // Get status to get PIN/PUK retry counts
    // Note: This requires secure channel, so we'll set defaults for now
    // and update later when we have secure channel
    result.pinRetries = appStatus.pinRetryCount;
    result.pukRetries = appStatus.pukRetryCount;
    return result;
}

QJsonObject FlowBase::buildCardInfoJson() const
{
    QJsonObject json;
    auto info = cardInfo();
    
    if (!info.instanceUID.isEmpty()) {
        json[FlowParams::INSTANCE_UID] = info.instanceUID;
    }
    
    if (!info.keyUID.isEmpty()) {
        json[FlowParams::KEY_UID] = info.keyUID;
    }
    
    if (info.freeSlots >= 0) {
        json[FlowParams::FREE_SLOTS] = info.freeSlots;
    }
    
    if (info.pinRetries >= 0) {
        json[FlowParams::PIN_RETRIES] = info.pinRetries;
        json[FlowParams::PUK_RETRIES] = info.pukRetries;
    }
    
    return json;
}

QString FlowBase::publicKeyToAddress(const QByteArray& pubKey) {
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

// TLV parsing functions moved to tlv_utils.h/cpp - using Keycard::TLV:: utilities

bool FlowBase::parseExportedKey(const QByteArray& data, QByteArray& publicKey, QByteArray& privateKey) {
    publicKey.clear();
    privateKey.clear();
    
    if (data.isEmpty()) {
        qWarning() << "parseExportedKey: Empty data";
        return false;
    }
    
    // Find template tag 0xA1 using common TLV utility
    QByteArray template_ = Keycard::TLV::findTag(data, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "parseExportedKey: Failed to find template tag 0xA1";
        return false;
    }
    
    // Find public key (0x80)
    publicKey = Keycard::TLV::findTag(template_, 0x80);
    
    // Find private key (0x81) if available
    privateKey = Keycard::TLV::findTag(template_, 0x81);
    
    if (publicKey.isEmpty()) {
        qWarning() << "parseExportedKey: No public key found";
        return false;
    }
    
    return true;
}

} // namespace StatusKeycard

