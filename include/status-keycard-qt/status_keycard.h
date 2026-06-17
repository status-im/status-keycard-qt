#ifndef STATUS_KEYCARD_H
#define STATUS_KEYCARD_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file status_keycard.h
 * @brief C API for Status Keycard - Compatible with nim-keycard-go
 * 
 * This library provides the EXACT same C API as status-keycard-go
 * so that nim-keycard-go can link to it without any changes.
 */

// Opaque context type
typedef struct StatusKeycardContextImpl* StatusKeycardContext;

// Signal callback type
typedef void (*SignalCallback)(const char* signal_json);

// ============================================================================
// Core RPC Functions (MUST match nim-keycard-go)
// ============================================================================

/**
 * @brief Call an RPC method (compatibility wrapper - uses global context)
 * @param payload_json JSON-RPC request string
 * @return JSON-RPC response string (must be freed with Free())
 */
char* KeycardCallRPC(const char* payload_json);

/**
 * @brief Set signal event callback (compatibility wrapper - uses global context)
 * @param callback Function pointer to receive signal events
 */
void KeycardSetSignalEventCallback(SignalCallback callback);

/**
 * @brief Free memory allocated by library
 * @param param Pointer to memory to free
 */
void Free(void* param);

// ============================================================================
// Android JNI Support (not part of original API)
// ============================================================================

// NOTE: KeycardSetAndroidTag is now OBSOLETE after Qt NFC fix
//
// The JNI registration fix in keycard-qt properly registers QtNative.onNewIntent(),
// enabling Qt NFC to work automatically without Activity modifications.
// Manual tag forwarding is no longer needed.
//
// See: keycard-qt/src/channel/android_jni_register.cpp

#if 0  // DISABLED - Qt NFC works automatically now
#ifdef __ANDROID__
#include <jni.h>

/**
 * @brief Set Android IsoDep tag for keycard communication
 * @param env JNI environment
 * @param tag Android Tag object (jobject)
 * @return 1 if successful, 0 if failed
 * 
 * This function is called from Java when an NFC tag is detected.
 * It extracts the IsoDep interface and passes it to the KeycardChannel.
 */
int KeycardSetAndroidTag(JNIEnv* env, jobject tag);

#endif // __ANDROID__
#endif // DISABLED

#ifdef __cplusplus
}
#endif

#endif // STATUS_KEYCARD_H
