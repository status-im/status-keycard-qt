/**
 * Hardware Test Program
 *
 * Exercises the status-keycard-qt JSON-RPC C API against real Keycard hardware.
 *
 * The library needs a running Qt event loop for card detection, and operation
 * methods block until a card is ready. Each RPC call therefore runs on a worker
 * thread while a (nested) event loop is pumped on the main thread.
 */

#include <status-keycard-qt/status_keycard.h>
#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <thread>

// Test results tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
};

TestResults g_results;

// Signal callback handler
void on_signal(const char* signal_json) {
    if (!signal_json) return;

    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(signal_json));
    QJsonObject obj = doc.object();
    printf("📡 Signal: %s\n", obj["type"].toString().toUtf8().constData());
}

// Call an RPC method and check the result.
// The call runs on a worker thread (operation methods block until a card is
// ready); the main thread pumps a nested event loop so detection can progress.
// An optional timeout cancels the in-flight operation so the test can finish.
bool call_rpc_test(const char* test_name, const char* method, const char* params,
                   bool expect_success = true, int timeout_ms = 0) {
    printf("\n🔧 Test: %s\n", test_name);
    printf("   Method: %s\n", method);

    char request[1024];
    snprintf(request, sizeof(request),
             "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":\"1\"}",
             method, (params && strlen(params) > 0) ? params : "{}");

    QEventLoop loop;
    QByteArray responseBytes;
    std::atomic<bool> done{false};

    std::thread worker([&]() {
        char* response = KeycardCallRPC(request);
        if (response) {
            responseBytes = QByteArray(response);
            Free(response);
        }
        done = true;
        QMetaObject::invokeMethod(&loop, &QEventLoop::quit);
    });

    if (timeout_ms > 0) {
        QTimer::singleShot(timeout_ms, &loop, [&]() {
            if (!done) {
                printf("   ⏱️  Timeout - cancelling operation...\n");
                char* cancel = KeycardCallRPC(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"keycard.CancelCurrentOperation\","
                    "\"params\":{},\"id\":\"1\"}");
                Free(cancel);
            }
        });
    }

    loop.exec();
    worker.join();

    bool success = false;
    if (!responseBytes.isEmpty()) {
        QJsonObject obj = QJsonDocument::fromJson(responseBytes).object();
        bool has_error = obj.contains("error") && !obj["error"].isNull();
        bool has_result = obj.contains("result") && !obj["result"].isNull();

        if (expect_success) {
            success = has_result && !has_error;
            if (success) {
                printf("   ✅ PASS\n");
            } else {
                printf("   ❌ FAIL: %s\n",
                       obj["error"].toObject()["message"].toString().toUtf8().constData());
            }
        } else {
            success = has_error;
            printf("%s", success ? "   ✅ PASS (expected error)\n"
                                 : "   ❌ FAIL: Expected error but got success\n");
        }
        printf("   Response: %s\n", responseBytes.constData());
    } else {
        printf("   ❌ FAIL: No response\n");
    }

    success ? g_results.passed++ : g_results.failed++;
    return success;
}

void test_error_handling() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 1: Error Handling (no card needed)\n");
    printf("═══════════════════════════════════════\n");

    call_rpc_test("Invalid method", "keycard.InvalidMethod", "{}",
                  /*expect_success=*/false);
    call_rpc_test("Malformed params", "keycard.GetKeycardMetadata", "{invalid json}",
                  /*expect_success=*/false);
}

void test_read_metadata() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 2: Read Card Metadata\n");
    printf("═══════════════════════════════════════\n");
    printf("   ⏳ Please insert a Keycard now (up to 30s)...\n");

    // No PIN -> reads metadata without resolving wallet addresses.
    call_rpc_test("Get keycard metadata", "keycard.GetKeycardMetadata",
                  "{\"storageFilePath\":\"./test_pairings.json\"}",
                  /*expect_success=*/true, /*timeout_ms=*/30000);
}

void test_cleanup() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 3: Cleanup\n");
    printf("═══════════════════════════════════════\n");

    call_rpc_test("Stop service", "keycard.Stop", "{}");
}

void print_summary() {
    printf("\n\n╔═══════════════════════════════════════╗\n");
    printf("║       TEST SUMMARY                    ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");
    printf("   ✅ Passed: %d\n", g_results.passed);
    printf("   ❌ Failed: %d\n", g_results.failed);
    printf("   📊 Total:  %d\n\n", g_results.passed + g_results.failed);
    printf("%s", g_results.failed == 0
                     ? "   🎉 ALL TESTS PASSED!\n\n"
                     : "   ⚠️  SOME TESTS FAILED - review the output above.\n\n");
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  Status Keycard Qt - Hardware Test                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // The RPC service / global context is created lazily on first use.
    KeycardSetSignalEventCallback(on_signal);
    printf("✅ Signal callback registered\n");

    test_error_handling();
    test_read_metadata();
    test_cleanup();

    print_summary();

    printf("Cleaning up...\n");
    printf("✅ Done\n\n");

    return (g_results.failed == 0) ? 0 : 1;
}
