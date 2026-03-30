#pragma once

#include "session_state.h"
#include <keycard-qt/i_communication_manager.h>
#include <keycard-qt/types.h>
#include <QObject>
#include <QTimer>
#include <QMutex>
#include <QWaitCondition>
#include <memory>

namespace StatusKeycard {

/**
 * @brief Manages keycard session lifecycle
 *
 * Responsibilities:
 * - Card/reader detection and monitoring
 * - Automatic connection management
 * - State machine management
 * - Signal emission for state changes
 */
class SessionManager : public QObject {
    Q_OBJECT

public:
    explicit SessionManager(QObject* parent = nullptr);
    ~SessionManager();

    /**
     * @brief Set CommunicationManager
     * @param commMgr CommunicationManager instance (must be started)
     *
     * Must be called before start().
     * The CommunicationManager should be created and started by the caller
     * (e.g., RPC service) with the channel and dependencies.
     *
     * Accepts ICommunicationManager interface for testability.
     */
    void setCommunicationManager(std::shared_ptr<Keycard::ICommunicationManager> commMgr);
    std::shared_ptr<Keycard::ICommunicationManager> communicationManager() const { return m_commMgr; }

    // Session lifecycle
    bool start(bool logEnabled = false, const QString& logFilePath = QString());
    void stop();
    bool isStarted() const { return m_started; }

    // Current state
    SessionState currentState() const { return m_state; }
    QString currentStateString() const;

    // Card operations (require Authorized state for most)
    bool initialize(const QString& pin, const QString& puk, const QString& pairingPassword);
    bool authorize(const QString& pin);
    bool changePIN(const QString& newPIN);
    bool changePUK(const QString& newPUK);
    bool unblockPIN(const QString& puk, const QString& newPIN);

    // Key operations
    QVector<int> generateMnemonic(int length);
    QString loadMnemonic(const QString& mnemonic, const QString& passphrase);
    bool factoryReset();

    // Forward-declare nested types for method signatures
    struct Metadata;

    // Metadata operations
    Metadata getMetadata(bool isMainCommand = true);
    bool storeMetadata(const QString& name, const QStringList& paths);

    // Key export
    struct KeyPair {
        QString address;
        QString publicKey;
        QString privateKey;  // Optional
        QString chainCode;   // Optional (for extended keys)
    };

    struct LoginKeys {
        KeyPair whisperPrivateKey;
        KeyPair encryptionPrivateKey;
    };
    LoginKeys exportLoginKeys(bool isMainCommand = true);
    LoginKeys login(const QString& keyUid, const QString& pin, bool logEnabled = false, const QString& logFilePath = QString());

    struct RecoverKeys {
        LoginKeys loginKeys;
        KeyPair eip1581;
        KeyPair walletRootKey;
        KeyPair walletKey;
        KeyPair masterKey;
    };
    RecoverKeys exportRecoverKeys(bool isMainCommand = true);
    RecoverKeys recover(const QString& pin, const QString& puk, const QString& pairingPassword, const QString& mnemonic,
                        bool logEnabled = false, const QString& logFilePath = QString());

    struct ExtendedPublicKey {
        QString address;
        QString publicKey;
        QString chainCode;
        QString xpub;       // Base58Check-encoded BIP32 extended public key
    };
    ExtendedPublicKey exportExtendedPublicKey(const QString& path);
    ExtendedPublicKey exportExtendedPublicKey(const QString& keyUid, const QString& pin, const QString& path,
        const QString& storageFilePath, bool logEnabled = false, const QString& logFilePath = QString());

    struct ExportedKeyPair {
        QString address;
        QString publicKey;   // Hex with 0x prefix (matches ExportPublicFlow)
        QString privateKey;  // Optional, hex with 0x prefix
        QString chainCode;   // Optional, hex with 0x prefix
    };
    struct ExportPublicKeyResult {
        QString masterKeyAddress;  // Empty if exportMasterAddress was false
        QVector<ExportedKeyPair> exportedKeys;
        bool inputWasArray;  // True if paths was array (affects result format)
    };
    ExportPublicKeyResult exportPublicKey(const QString& keyUid, const QString& pin, const QStringList& paths,
        bool exportPrivate, bool exportMasterAddress, const QString& storageFilePath,
        bool logEnabled = false, const QString& logFilePath = QString());

    bool changeKeycardPIN(const QString& keyUid, const QString& pin, const QString& newPIN,
        const QString& storageFilePath, bool logEnabled = false, const QString& logFilePath = QString());
    bool changeKeycardPUK(const QString& keyUid, const QString& pin, const QString& newPUK,
        const QString& storageFilePath, bool logEnabled = false, const QString& logFilePath = QString());
    bool unblockUsingPUK(const QString& keyUid, const QString& puk, const QString& newPIN,
        const QString& storageFilePath, bool logEnabled = false, const QString& logFilePath = QString());

    Metadata getKeycardMetadata(const QString& pin, const QString& storageFilePath, bool logEnabled = false,
        const QString& logFilePath = QString());

    struct SignResult {
        QString r;   // 32-byte hex
        QString s;   // 32-byte hex
        int v;       // Recovery ID + 27
        SignResult() : v(0) {}
    };
    SignResult sign(const QString& keyUid, const QString& pin, const QString& txHash, const QString& path,
        const QString& storageFilePath, bool logEnabled = false, const QString& logFilePath = QString());

    // Status structures (matching status-keycard-go exactly)
    struct Wallet {
        QString path;
        QString address;
        QString publicKey;
    };

    struct Metadata {
        QString name;
        QVector<Wallet> wallets;
    };

    struct ApplicationInfoV2 {
        bool installed;
        bool initialized;
        QString instanceUID;
        QString version;
        int availableSlots;
        QString keyUID;
    };

    struct ApplicationStatus {
        int remainingAttemptsPIN;
        int remainingAttemptsPUK;
        bool keyInitialized;
        QString path;
    };

    struct Status {
        QString state;  // State string (e.g., "ready", "authorized")
        ApplicationInfoV2* keycardInfo;  // Can be null
        ApplicationStatus* keycardStatus;  // Can be null
        Metadata* metadata;  // Can be null

        Status() : keycardInfo(nullptr), keycardStatus(nullptr), metadata(nullptr) {}
        ~Status() {
            delete keycardInfo;
            delete keycardStatus;
            delete metadata;
        }
    };
    Status getStatus() const;

    // Error handling
    QString lastError() const { return m_lastError; }

signals:
    void stateChanged(SessionState newState, SessionState oldState);
    void error(const QString& message);

public slots:
    void onCardInitialized(const Keycard::CardInitializationResult& result);
    void onCardRemoved();
    void onReaderAvailabilityChanged(bool available);
    void onChannelError(const QString& errorMsg);

private:
    void setState(SessionState newState);
    void setError(const QString& error);

    bool ensureKeycardCommunication();
    bool ensureStarted();
    bool ensureAuthorized();

    // Fetch fresh app status from card and publish status-changed signal
    void updateAndPublishStatus(bool authorized);

    // Helper for exporting keys
    QByteArray exportKeyInternal(bool derive, bool makeCurrent, const QString& path, uint8_t exportType = 0x00);
    QByteArray exportKeyExtendedInternal(bool derive, bool makeCurrent, const QString& path);
    ExportPublicKeyResult exportPublicKeyInternal(const QStringList& paths, bool exportPrivate, bool exportMasterAddress);
    static KeyPair parseExportedKey(const QByteArray& data);

    // State
    SessionState m_state;
    bool m_started;
    QString m_lastError;

    // Keycard components (uses interface for testability)
    std::shared_ptr<Keycard::ICommunicationManager> m_commMgr;

    // Cached card state
    Keycard::ApplicationInfo m_appInfo;
    Keycard::ApplicationStatus m_appStatus;  // Cached status to avoid redundant GET_STATUS calls
    Metadata m_metadata;

    // Monitoring
    QTimer* m_stateCheckTimer;
    QString m_currentCardUID;
    bool m_authorized;

    // Thread safety - protects all card operations
    // MUST be recursive to allow exportRecoverKeys() to call exportLoginKeys()
    mutable QRecursiveMutex m_operationMutex;

    // Event-based wait for login() — RPC thread sleeps until card state changes
    QWaitCondition m_cardReadyCondition;
    QMutex m_cardReadyMutex;
    bool m_compositeMethodCallCancelled = false;
};

} // namespace StatusKeycard

