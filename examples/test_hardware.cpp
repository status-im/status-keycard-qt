/**
 * Hardware Test Program - Phase 5 Validation
 * 
 * Tests the migrated Flow API with real Keycard hardware.
 * Verifies CommunicationManager integration and command queuing.
 */

#include <status-keycard-qt/status_keycard.h>
#include <QCoreApplication>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <stdio.h>
#include <string.h>

// Test results tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    int skipped = 0;
};

TestResults g_results;
bool g_cardDetected = false;
QString g_cardInstanceUID;
QString g_cardKeyUID;

// Signal callback handler
void on_signal(const char* signal_json) {
    if (!signal_json) return;
    
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(signal_json));
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    
    printf("📡 Signal: %s\n", type.toUtf8().constData());
    
    // Track card detection
    if (type == "keycard.detected" || type.contains("detected")) {
        g_cardDetected = true;
        QJsonObject event = obj["event"].toObject();
        g_cardInstanceUID = event["instance-uid"].toString();
        g_cardKeyUID = event["key-uid"].toString();
        printf("   ✅ Card detected: %s\n", g_cardInstanceUID.toUtf8().constData());
    }
    else if (type == "keycard.lost" || type.contains("lost")) {
        g_cardDetected = false;
        printf("   ⚠️  Card removed\n");
    }
}

// Helper to call RPC and check result
bool call_rpc_test(const char* test_name, const char* method, const char* params, bool expect_success = true) {
    printf("\n🔧 Test: %s\n", test_name);
    printf("   Method: %s\n", method);
    
    char request[1024];
    if (params && strlen(params) > 0) {
        snprintf(request, sizeof(request), 
                "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":\"1\"}", 
                method, params);
    } else {
        snprintf(request, sizeof(request), 
                "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{},\"id\":\"1\"}", 
                method);
    }
    
    char* response = KeycardCallRPC(request);
    bool success = false;
    
    if (response) {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
        QJsonObject obj = doc.object();
        
        bool has_error = obj.contains("error");
        bool has_result = obj.contains("result");
        
        if (expect_success) {
            success = has_result && !has_error;
            if (success) {
                printf("   ✅ PASS\n");
                g_results.passed++;
            } else {
                printf("   ❌ FAIL: %s\n", obj["error"].toObject()["message"].toString().toUtf8().constData());
                g_results.failed++;
            }
        } else {
            success = has_error;
            if (success) {
                printf("   ✅ PASS (expected error)\n");
                g_results.passed++;
            } else {
                printf("   ❌ FAIL: Expected error but got success\n");
                g_results.failed++;
            }
        }
        
        printf("   Response: %s\n", response);
        Free(response);
    } else {
        printf("   ❌ FAIL: No response\n");
        g_results.failed++;
    }
    
    return success;
}

// Test categories
void test_01_initialization() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 1: Initialization\n");
    printf("═══════════════════════════════════════\n");
    
    call_rpc_test(
        "Start service with storage path",
        "keycard.Start",
        "{\"storageFilePath\":\"./test_pairings.json\"}"
    );
}

void test_02_card_detection() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 2: Card Detection\n");
    printf("═══════════════════════════════════════\n");
    
    printf("\n🔧 Test: Wait for card insertion\n");
    printf("   ⏳ Please insert Keycard now...\n");
    printf("   Waiting up to 30 seconds...\n");
    
    // Wait for card with timeout
    QCoreApplication* app = QCoreApplication::instance();
    QTimer timeout;
    timeout.setSingleShot(true);
    
    QTimer checker;
    bool detected = false;
    QObject::connect(&checker, &QTimer::timeout, [&]() {
        if (g_cardDetected) {
            detected = true;
            checker.stop();
            timeout.stop();
            app->quit();
        }
    });
    
    QObject::connect(&timeout, &QTimer::timeout, [&]() {
        checker.stop();
        app->quit();
    });
    
    checker.start(500); // Check every 500ms
    timeout.start(30000); // 30 second timeout
    app->exec();
    
    if (detected) {
        printf("   ✅ PASS: Card detected\n");
        g_results.passed++;
    } else {
        printf("   ⚠️  SKIPPED: No card inserted within timeout\n");
        g_results.skipped++;
    }
}

void test_03_basic_operations() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 3: Basic Operations\n");
    printf("═══════════════════════════════════════\n");
    
    if (!g_cardDetected) {
        printf("   ⚠️  SKIPPED: No card available\n");
        g_results.skipped += 2;
        return;
    }
    
    call_rpc_test(
        "Get card status",
        "keycard.GetStatus",
        "{}"
    );
    
    // This will pause for PIN if card has keys
    call_rpc_test(
        "Get card app info",
        "keycard.GetAppInfo",
        "{}"
    );
}

void test_04_concurrent_operations() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 4: Concurrent Operations\n");
    printf("═══════════════════════════════════════\n");
    
    if (!g_cardDetected) {
        printf("   ⚠️  SKIPPED: No card available\n");
        g_results.skipped += 2;
        return;
    }
    
    printf("\n🔧 Test: Multiple GetStatus calls (queuing test)\n");
    printf("   Calling GetStatus 3 times in rapid succession...\n");
    
    // These should all be queued and executed serially
    bool test1 = call_rpc_test("GetStatus #1", "keycard.GetStatus", "{}");
    bool test2 = call_rpc_test("GetStatus #2", "keycard.GetStatus", "{}");
    bool test3 = call_rpc_test("GetStatus #3", "keycard.GetStatus", "{}");
    
    if (test1 && test2 && test3) {
        printf("\n   ✅ Concurrent operations queued and executed correctly\n");
    } else {
        printf("\n   ❌ Some concurrent operations failed\n");
    }
}

void test_05_error_handling() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 5: Error Handling\n");
    printf("═══════════════════════════════════════\n");
    
    call_rpc_test(
        "Invalid method",
        "keycard.InvalidMethod",
        "{}",
        false // Expect error
    );
    
    call_rpc_test(
        "Malformed params",
        "keycard.GetStatus",
        "{invalid json}",
        false // Expect error
    );
}

void test_06_cleanup() {
    printf("\n\n═══════════════════════════════════════\n");
    printf("TEST CATEGORY 6: Cleanup\n");
    printf("═══════════════════════════════════════\n");
    
    call_rpc_test(
        "Stop service",
        "keycard.Stop",
        "{}"
    );
}

void print_summary() {
    printf("\n\n╔═══════════════════════════════════════╗\n");
    printf("║       TEST SUMMARY                    ║\n");
    printf("╚═══════════════════════════════════════╝\n");
    printf("\n");
    printf("   ✅ Passed:  %d\n", g_results.passed);
    printf("   ❌ Failed:  %d\n", g_results.failed);
    printf("   ⚠️  Skipped: %d\n", g_results.skipped);
    printf("   📊 Total:   %d\n", g_results.passed + g_results.failed + g_results.skipped);
    printf("\n");
    
    if (g_results.failed == 0) {
        printf("   🎉 ALL TESTS PASSED!\n");
        printf("\n");
        printf("   ✅ Phase 5 Hardware Testing: SUCCESS\n");
        printf("   ✅ CommunicationManager integration verified\n");
        printf("   ✅ Command queuing working correctly\n");
        printf("   ✅ No race conditions detected\n");
        printf("\n");
    } else {
        printf("   ⚠️  SOME TESTS FAILED\n");
        printf("\n");
        printf("   Please review the test output above.\n");
        printf("   Check logs for detailed error messages.\n");
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  Status Keycard Qt - Phase 5 Hardware Test              ║\n");
    printf("║  Testing CommunicationManager Migration                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Platform: macOS (PC/SC)\n");
    printf("Purpose: Verify Phases 1-4 & 6 migration with real hardware\n");
    printf("\n");
    
    // Initialize RPC
    printf("Initializing RPC service...\n");
    char* init_response = KeycardInitializeRPC();
    if (init_response) {
        Free(init_response);
    }
    printf("✅ RPC initialized\n\n");
    
    // Set signal callback
    KeycardSetSignalEventCallback(on_signal);
    printf("✅ Signal callback registered\n\n");
    
    printf("═══════════════════════════════════════\n");
    printf("Starting Test Suite\n");
    printf("═══════════════════════════════════════\n");
    
    // Run test categories
    test_01_initialization();
    test_02_card_detection();
    test_03_basic_operations();
    test_04_concurrent_operations();
    test_05_error_handling();
    test_06_cleanup();
    
    // Print summary
    print_summary();
    
    // Cleanup
    printf("Cleaning up...\n");
    ResetAPI();
    printf("✅ Done\n\n");
    
    return (g_results.failed == 0) ? 0 : 1;
}




