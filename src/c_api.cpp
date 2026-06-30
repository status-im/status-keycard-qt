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

#ifdef USE_SIMULATED_KEYCARD
#include "session/simulated_channel_backend.h"
#include "keycard-qt/keycard_channel.h"
#include <cstdlib>
#endif

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

#ifdef USE_SIMULATED_KEYCARD
        {
            // Test build: drive a jcardsim-backed simulator instead of a physical reader.
            auto* simBackend = new StatusKeycard::SimulatedChannelBackend();
            const char* ep = std::getenv("STATUS_KEYCARD_SIM_ENDPOINT");
            simBackend->attach(ep ? QString::fromUtf8(ep) : QStringLiteral("127.0.0.1:9025"));
            channel = std::make_shared<Keycard::KeycardChannel>(simBackend);
        }
#else
        channel = std::make_shared<Keycard::KeycardChannel>();
#endif
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

// Internal implementations behind the no-context wrappers below.
static char* KeycardCallRPCWithContext(StatusKeycardContext ctx, const char* payload_json) {
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

static void KeycardSetSignalEventCallbackWithContext(StatusKeycardContext ctx, SignalCallback callback) {
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

// Wrapper: keycardCallRPC (Nim expects this signature)
char* KeycardCallRPC(const char* params) {
    ensure_global_context();
    return KeycardCallRPCWithContext(g_global_context, params);
}

#ifdef USE_SIMULATED_KEYCARD
// ============================================================================
// Test-only control (simulated keycard backend)
// ============================================================================

static StatusKeycard::SimulatedChannelBackend* sim_backend() {
    ensure_global_context();
    auto* impl = reinterpret_cast<StatusKeycardContextImpl*>(g_global_context);
    if (!impl || !impl->channel) {
        return nullptr;
    }
    return dynamic_cast<StatusKeycard::SimulatedChannelBackend*>(impl->channel->backend());
}

static char* sim_result(bool ok, const char* error) {
    if (ok) {
        return strdup(R"({"error":""})");
    }
    QString json = QStringLiteral("{\"error\":\"%1\"}").arg(QString::fromUtf8(error));
    return strdup(json.toUtf8().constData());
}

char* KeycardTestCreateCard(const char* cardId) {
    auto* b = sim_backend();
    if (!b || !cardId) return sim_result(false, "simulated backend not available");
    return sim_result(b->createCard(QString::fromUtf8(cardId)), "createCard failed");
}

char* KeycardTestInsertCard(const char* cardId) {
    auto* b = sim_backend();
    if (!b || !cardId) return sim_result(false, "simulated backend not available");
    return sim_result(b->insertCard(QString::fromUtf8(cardId)), "insertCard failed");
}

char* KeycardTestRemoveCard(void) {
    auto* b = sim_backend();
    if (!b) return sim_result(false, "simulated backend not available");
    b->removeCard();
    return sim_result(true, "");
}

char* KeycardTestPlugReader(void) {
    auto* b = sim_backend();
    if (!b) return sim_result(false, "simulated backend not available");
    b->plugReader();
    return sim_result(true, "");
}

char* KeycardTestUnplugReader(void) {
    auto* b = sim_backend();
    if (!b) return sim_result(false, "simulated backend not available");
    b->unplugReader();
    return sim_result(true, "");
}
#endif // USE_SIMULATED_KEYCARD

} // extern "C"
