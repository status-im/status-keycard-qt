#include "status-keycard-qt/status_keycard.h"
#include "rpc/rpc_service.h"
#include "session/session_manager.h"
#include "signal_manager.h"
#include "storage/file_pairing_storage.h"
#include "keycard-qt/communication_manager.h"
#include <QString>
#include <QObject>
#include <memory>
#include <cstring>

// Context structure
struct StatusKeycardContextImpl {
    std::unique_ptr<StatusKeycard::RpcService> rpcService;
    StatusKeycard::SignalManager* signalManager;
    SignalCallback signalCallback;
    std::shared_ptr<Keycard::CommunicationManager> commMgr;  // Communication manager for SessionManager
    std::shared_ptr<Keycard::CommandSet> commandSet;  // CommandSet used by SessionManager
    std::shared_ptr<Keycard::KeycardChannel> channel;  // Global channel instance
    std::shared_ptr<Keycard::IPairingStorage> pairingStorage;

    StatusKeycardContextImpl()
        : signalCallback(nullptr)
        , commMgr(nullptr)
        , commandSet(nullptr)
    {
        qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: Constructor called";
        // Initialize Qt if needed
        int argc = 0;
        char* argv[] = {nullptr};

        channel = std::make_shared<Keycard::KeycardChannel>();
        // Stop detection immediately - the PCSC backend starts detection in its constructor, don't detect cards
        // until Start() is called and the storage path is configured.
        // SessionManager::start() will call startDetection() at the right time.
        channel->stopDetection();

        pairingStorage = std::make_shared<StatusKeycard::FilePairingStorage>();

        // Create password provider
        auto passwordProvider = [](const QString& cardUID) { return "KeycardDefaultPairing"; };

        // Create CommandSet used by SessionManager
        commandSet = std::make_shared<Keycard::CommandSet>(
            channel, pairingStorage, passwordProvider);
        qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: Created CommandSet";

        // Create and initialize CommunicationManager using CommandSet
        // CommunicationManager connects to CommandSet signals (cardReady, cardLost)
        // Note: We init() here but don't startDetection() yet
        // SessionManager will call startDetection() when it's ready
        commMgr = std::make_shared<Keycard::CommunicationManager>();
        if (!commMgr->init(commandSet)) {
            qWarning() << "StatusKeycardContextImpl: Failed to initialize CommunicationManager";
        }
        qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: CommunicationManager initialized with CommandSet";

        // Create RPC service and pass CommunicationManager
        rpcService = std::make_unique<StatusKeycard::RpcService>();
        rpcService->setCommunicationManager(commMgr);

        // Get signal manager instance
        signalManager = StatusKeycard::SignalManager::instance();

        // Connect SessionManager signals to SignalManager
        QObject::connect(rpcService->sessionManager(), &StatusKeycard::SessionManager::stateChanged,
                        [this](StatusKeycard::SessionState, StatusKeycard::SessionState) {
            // Emit status-changed signal
            auto status = rpcService->sessionManager()->getStatus();
            signalManager->emitStatusChanged(status);
        });

        // Connect channel state changes to SignalManager
        QObject::connect(channel.get(), &Keycard::KeycardChannel::channelStateChanged, signalManager,
                        [this](Keycard::ChannelOperationalState state) {
            // Convert enum to string
            qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: Channel state changed:" << static_cast<int>(state);
            QString stateStr;
            switch (state) {
                case Keycard::ChannelOperationalState::Idle:
                    stateStr = "idle";
                    break;
                case Keycard::ChannelOperationalState::WaitingForKeycard:
                    stateStr = "waiting-for-keycard";
                    break;
                case Keycard::ChannelOperationalState::Reading:
                    stateStr = "reading";
                    break;
                case Keycard::ChannelOperationalState::Error:
                    stateStr = "error";
                    break;
                case Keycard::ChannelOperationalState::NotSupported:
                    stateStr = "not-supported";
                    break;
                case Keycard::ChannelOperationalState::NotAvailable:
                    stateStr = "not-available";
                    break;
            }
            qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: Emitting channel state changed signal:" << stateStr;
            signalManager->emitChannelStateChanged(stateStr);
        });

    }

    ~StatusKeycardContextImpl() {
        qDebug() << "StatusKeycardQt::StatusKeycardContextImpl: Destructor called";
    }
};

extern "C" {

// ============================================================================
// Core RPC Functions (MUST match nim-keycard-go)
// ============================================================================

// Global context for compatibility with old API
static StatusKeycardContext g_global_context = nullptr;

// Internal function that returns context (not exposed in header)
static StatusKeycardContext KeycardInitializeRPCInternal(void) {
    try {
        StatusKeycardContextImpl* ctx = new StatusKeycardContextImpl();
        qDebug() << "StatusKeycardQt::C API: Context created successfully";
        return reinterpret_cast<StatusKeycardContext>(ctx);
    } catch (...) {
        qCritical() << "C API: Failed to create context!";
        return nullptr;
    }
}

// Initialize global context if needed
static void ensure_global_context() {
    if (!g_global_context) {
        g_global_context = KeycardInitializeRPCInternal();
    }
}

// Public function that returns JSON string (matching nim-keycard-go expectation)
char* KeycardInitializeRPC(void) {
    // Create global context if needed
    ensure_global_context();

    // Return success response in Go format: {"error":""}
    const char* response = R"({"error":""})";
    return strdup(response);
}

// Context-based API for testing and advanced usage
StatusKeycardContext KeycardCreateContext(void) {
    return KeycardInitializeRPCInternal();
}

void KeycardDestroyContext(StatusKeycardContext ctx) {
    if (ctx) {
        StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
        delete impl;
    }
}

char* KeycardCallRPCWithContext(StatusKeycardContext ctx, const char* payload_json) {
    qDebug() << "StatusKeycardQt::C API: KeycardCallRPCWithContext() called";
    qDebug() << "StatusKeycardQt::C API: Payload:" << (payload_json ? payload_json : "NULL");

    if (!ctx || !payload_json) {
        qCritical() << "C API: Invalid context or payload!";
        // Return error response
        const char* error = R"({"jsonrpc":"2.0","id":"","result":null,"error":{"code":-32603,"message":"Invalid context or payload"}})";
        return strdup(error);
    }

    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);

    // Process the JSON-RPC request
    QString request = QString::fromUtf8(payload_json);
    qDebug() << "StatusKeycardQt::C API: Processing RPC request:" << request;
    QString response = impl->rpcService->processRequest(request);
    qDebug() << "StatusKeycardQt::C API: RPC response:" << response;

    // Return response (caller must free with Free())
    return strdup(response.toUtf8().constData());
}

void KeycardSetSignalEventCallbackWithContext(StatusKeycardContext ctx, SignalCallback callback) {
    if (!ctx) {
        return;
    }

    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
    impl->signalCallback = callback;
    impl->signalManager->setCallback(callback);
}

void Free(void* param) {
    if (param) {
        free(param);
    }
}

void ResetAPIWithContext(StatusKeycardContext ctx) {
    if (!ctx) {
        return;
    }

    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);

    // Stop the session
    if (impl->rpcService && impl->rpcService->sessionManager()) {
        impl->rpcService->sessionManager()->stop();
    }

    // The following block handles the case where the keycard was factory resetted or recovered during onboarding,
    // and the keycard was not removed from the reader, without this block, this lib will be using old cached state.
#if not defined(Q_OS_ANDROID) && not defined(Q_OS_IOS)
    // Restart card detection so the CommunicationManager runs the full
    // initialization sequence (SELECT force=true + pairing + secure channel
    // + get status). This refreshes all cached state (appInfo, appStatus)
    // so subsequent operations see up-to-date card data.
    if (impl->commMgr) {
        impl->commMgr->stopDetection();
        impl->commMgr->startDetection();
    }
#endif

    // Reset RPC service
    impl->rpcService.reset();
    impl->rpcService = std::make_unique<StatusKeycard::RpcService>();
    impl->rpcService->setCommunicationManager(impl->commMgr);

    // Reconnect signals
    QObject::connect(impl->rpcService->sessionManager(), &StatusKeycard::SessionManager::stateChanged,
                    [impl](StatusKeycard::SessionState, StatusKeycard::SessionState) {
        auto status = impl->rpcService->sessionManager()->getStatus();
        impl->signalManager->emitStatusChanged(status);
    });
}

// ============================================================================
// Compatibility Wrappers (No context parameter - for Nim compatibility)
// ============================================================================
void KeycardSetSignalEventCallback(SignalCallback callback) {
    qDebug() << "StatusKeycardQt::========================================";
    qDebug() << "StatusKeycardQt::C API: KeycardSetSignalEventCallback() called!";
    qDebug() << "StatusKeycardQt::C API: Callback pointer:" << (void*)callback;
    qDebug() << "StatusKeycardQt::========================================";
    ensure_global_context();
    KeycardSetSignalEventCallbackWithContext(g_global_context, callback);
    qDebug() << "StatusKeycardQt::C API: Signal callback registered successfully";
}

// Wrapper: resetAPI (Nim expects this signature)
void ResetAPI() {
    if (g_global_context) {
        ResetAPIWithContext(g_global_context);
    }
}

// NOTE: keycardInitializeRPC is removed - Nim uses KeycardInitializeRPC directly

// Wrapper: keycardCallRPC (Nim expects this signature)
char* KeycardCallRPC(const char* params) {
    ensure_global_context();
    return KeycardCallRPCWithContext(g_global_context, params);
}

} // extern "C"
