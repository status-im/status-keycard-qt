/**
 * Simple Usage Example
 *
 * Demonstrates the status-keycard-qt C API driven by JSON-RPC.
 *
 * The library requires a running Qt event loop (a QCoreApplication on the main
 * thread) for card detection. Operation methods block until a card is ready, so
 * they are issued from a worker thread while the event loop runs on the main
 * thread. A timeout cancels the operation if no card is inserted.
 */

#include <status-keycard-qt/status_keycard.h>
#include <QCoreApplication>
#include <QTimer>
#include <atomic>
#include <thread>
#include <cstdio>
#include <cstring>

// Signal callback handler
static void on_signal(const char* signal_json) {
    if (signal_json) {
        printf("\n📡 Signal: %s\n", signal_json);
    }
}

// Helper to build a JSON-RPC request, call it and print the result.
static void call_rpc(const char* method, const char* params) {
    char request[512];
    snprintf(request, sizeof(request),
             "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":\"1\"}",
             method, (params && strlen(params) > 0) ? params : "{}");

    printf("   Request: %s\n", request);
    char* response = KeycardCallRPC(request);
    if (response) {
        printf("   Response: %s\n\n", response);
        Free(response);
    } else {
        printf("   ❌ No response\n\n");
    }
}

int main(int argc, char* argv[]) {
    // A Qt event loop is required for card detection to work.
    QCoreApplication app(argc, argv);

    printf("=== Status Keycard Qt - Simple Usage Example ===\n\n");
    printf("This example demonstrates the C API using JSON-RPC.\n\n");

    // 1. Set signal callback (the RPC service/global context is created lazily on first use)
    printf("1. Setting up signal callback...\n");
    KeycardSetSignalEventCallback(on_signal);
    printf("   ✅ Callback registered\n\n");

    // 3. Read the card metadata on a worker thread. Detection starts implicitly
    //    and the call blocks until a card is ready (or the operation is
    //    cancelled), so it must not run on the main (event-loop) thread.
    printf("3. Reading keycard metadata...\n");
    printf("   Insert a keycard within 15 seconds.\n\n");

    std::atomic<bool> finished{false};
    std::thread worker([&]() {
        call_rpc("keycard.GetKeycardMetadata",
                 "{\"storageFilePath\":\"./pairings.json\"}");
        finished = true;
        QMetaObject::invokeMethod(&app, &QCoreApplication::quit);
    });

    // 4. If no card shows up in time, cancel the pending operation so the worker
    //    unblocks and the example can exit.
    QTimer::singleShot(15000, &app, [&]() {
        if (!finished) {
            printf("\n   ⏱️  Timeout - cancelling operation...\n");
            call_rpc("keycard.CancelCurrentOperation", "{}");
        }
    });

    int rc = app.exec();
    worker.join();

    // 5. Cleanup
    printf("4. Cleaning up...\n");
    printf("   ✅ Done\n\n");

    printf("=== Example Complete ===\n");
    return rc;
}
