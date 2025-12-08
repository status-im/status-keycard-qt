#include <status-keycard-qt/status_keycard.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Signal callback handler
void on_signal(const char* signal_json) {
    if (signal_json) {
        printf("\n📡 Signal: %s\n", signal_json);
    }
}

// Helper to call RPC and print result
void call_rpc(const char* method, const char* params) {
    char request[512];
    if (params && strlen(params) > 0) {
        snprintf(request, sizeof(request), 
                "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":\"1\"}", 
                method, params);
    } else {
        snprintf(request, sizeof(request), 
                "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{},\"id\":\"1\"}", 
                method);
    }
    
    printf("   Request: %s\n", request);
    char* response = KeycardCallRPC(request);
    
    if (response) {
        printf("   Response: %s\n\n", response);
        Free(response);
    } else {
        printf("   ❌ No response\n\n");
    }
}

int main() {
    printf("=== Status Keycard Qt - Simple Usage Example ===\n\n");
    printf("This example demonstrates the C API using JSON-RPC.\n\n");
    
    // 1. Initialize RPC
    printf("1. Initializing RPC service...\n");
    char* init_response = KeycardInitializeRPC();
    if (init_response) {
        printf("   Response: %s\n", init_response);
        Free(init_response);
    }
    printf("   ✅ RPC initialized\n\n");
    
    // 2. Set signal callback
    printf("2. Setting up signal callback...\n");
    KeycardSetSignalEventCallback(on_signal);
    printf("   ✅ Callback registered\n\n");
    
    // 3. Start service (with storage path)
    printf("3. Starting keycard service...\n");
    call_rpc("keycard.Start", "{\"storageFilePath\":\"./pairings.json\"}");
    
    // 4. Get initial status
    printf("4. Getting status...\n");
    call_rpc("keycard.GetStatus", "{}");
    
    // 5. Wait for signals
    printf("5. Listening for keycard events...\n");
    printf("   Insert a keycard to see signals\n");
    printf("   Waiting 10 seconds...\n\n");
    
    for (int i = 0; i < 10; i++) {
        sleep(1);
        printf(".");
        fflush(stdout);
    }
    printf("\n\n");
    
    // 6. Get final status
    printf("6. Getting final status...\n");
    call_rpc("keycard.GetStatus", "{}");
    
    // 7. Stop service
    printf("7. Stopping service...\n");
    call_rpc("keycard.Stop", "{}");
    
    // 8. Cleanup
    printf("8. Cleaning up...\n");
    ResetAPI();
    printf("   ✅ Done\n\n");
    
    printf("=== Example Complete ===\n");
    printf("\nNote: To see more activity, insert a physical keycard during step 5.\n");
    printf("The service will detect the card and emit signals.\n\n");
    
    return 0;
}
