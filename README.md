# status-keycard-qt

High-level Session API for Status Keycard operations. Drop-in replacement for [status-keycard-go](../status-keycard-go).

## Overview

This library provides a **simple C API** for keycard operations, designed to integrate seamlessly with [status-desktop](https://github.com/status-im/status-desktop) via Nim bindings.

**Built on:** [keycard-qt](https://github.com/status-im/keycard-qt) - Low-level APDU library

## Architecture

```
┌──────────────────────────────────────────┐
│  status-desktop (Nim)                    │
│  Direct C function calls                 │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  status-keycard-qt (C API)               │
│  • KeycardCallRPC(jsonRpcRequest)        │
│  • KeycardSetSignalEventCallback(cb)     │
│  • Free()                                │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  SessionManager (C++/Qt)                 │
│  • Card/reader monitoring                │
│  • Auto-connection management            │
│  • State machine                         │
│  • Pairing storage                       │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  keycard-qt                              │
│  • CommandSet (26 methods)               │
│  • SecureChannel (AES-256)               │
│  • KeycardChannel (PC/SC + NFC)          │
└──────────────────────────────────────────┘
```

## Features

- **JSON-RPC C API** - A single `KeycardCallRPC` entry point driven by JSON-RPC requests
- **Composite operations** - High-level methods (Login, Recover, Sign, ...) that drive the full card flow
- **Session Management** - Auto-detection, state machine, persistent pairing
- **Signal System** - Real-time status-changed notifications
- **Cross-platform** - Linux, macOS, Windows, Android, iOS
- **Drop-in replacement** - Compatible with status-keycard-go's C ABI

## API

The library exposes a small C ABI. All keycard operations go through a single
JSON-RPC entry point (`KeycardCallRPC`); results and asynchronous status updates
are returned as JSON strings. Every `char*` returned by the library must be
released with `Free()`.

### Core Functions

```c
// Execute a JSON-RPC request (see "RPC Methods" below). Returns a JSON-RPC response.
// The RPC service / process-global context is created lazily on first use.
char* KeycardCallRPC(const char* payload_json);

// Register a callback that receives asynchronous signal events as JSON.
void KeycardSetSignalEventCallback(SignalCallback callback);

// Free any char* returned by the library.
void Free(void* param);
```

> The library requires a running Qt event loop: a `QCoreApplication` (or
> `QGuiApplication`) must exist on the main thread. Blocking operation methods
> should be called from a worker thread so the event loop keeps processing card
> detection (see [examples](examples/)).

### RPC Methods

Requests use standard JSON-RPC 2.0:

```json
{"jsonrpc":"2.0","method":"keycard.Login","params":{ ... },"id":"1"}
```

| Method | Purpose | Key params |
|--------|---------|------------|
| `keycard.Login` | Authorize and export login keys | `storageFilePath`, `keyUid`, `pin`, `xPubPath`, `extendedResponse` |
| `keycard.Recover` | Initialize/recover a card from a mnemonic | `storageFilePath`, `pin`, `puk`, `pairingPassword`, `mnemonic`, `keycardUid`, `metadataName`, `metadataPaths` |
| `keycard.Load` | Load a mnemonic onto a PIN-only card | `storageFilePath`, `pin`, `puk`, `pairingPassword`, `mnemonic`, `metadataName`, `metadataPaths` |
| `keycard.ExportPublicKey` | Export public key(s) for path(s) | `storageFilePath`, `keyUid`, `pin`, `paths`/`path`, `exportPrivate`, `exportMasterAddress` |
| `keycard.ExportExtendedPublicKey` | Export an extended public key | `storageFilePath`, `keyUid`, `pin`, `path`, `exportMasterAddr` |
| `keycard.Sign` | Sign a transaction hash | `storageFilePath`, `keyUid`, `pin`, `txHash`, `path` |
| `keycard.ChangeKeycardPIN` | Change the PIN | `storageFilePath`, `keyUid`, `pin`, `newPin`, `keycardUid` |
| `keycard.ChangeKeycardPUK` | Change the PUK | `storageFilePath`, `keyUid`, `pin`, `newPuk`, `keycardUid` |
| `keycard.UnblockUsingPUK` | Unblock the PIN using the PUK | `storageFilePath`, `keyUid`, `puk`, `newPin`, `keycardUid` |
| `keycard.GetKeycardMetadata` | Read card metadata (resolves wallets when `pin` is given) | `storageFilePath`, `pin` (optional) |
| `keycard.StoreKeycardMetadata` | Store card metadata | `storageFilePath`, `pin`, `name`, `paths` |
| `keycard.FactoryResetKeycard` | Factory reset a card | `storageFilePath`, `keycardUid` |
| `keycard.Stop` | Stop the session | – |
| `keycard.CancelCurrentOperation` | Cancel the in-flight operation | – |

#### Pairing password

Every method above also accepts an optional `pairingPassword`. Pairing happens implicitly
whenever a card is detected and no stored pairing exists for it; when the parameter is omitted or
empty, the default password (`KeycardDefaultPairing`) is used, which is what cards initialized
through `keycard.Recover` / `keycard.Load` carry.

Cards provisioned elsewhere (e.g. on the Keycard shell) may use a custom pairing password. There
is no way to know this in advance, so the expected client flow is:

1. Run the operation without `pairingPassword`.
2. If it fails and the session state is `pairing-error`, ask the user for the pairing password.
3. Re-run the same operation with `pairingPassword` set.

A failed pairing attempt consumes no pairing slot and there is no retry counter, so step 3 can be
repeated. Once pairing succeeds the derived key is persisted to `storageFilePath` and the password
is not needed again for that card.

`pairing-error` means specifically "wrong pairing password" and is distinct from
`no-available-pairing-slots`, which is not recoverable by supplying a password.

For `keycard.Recover` and `keycard.Load` the parameter does double duty: it is the password
written to the card by INIT *and* the password used for the pairing that follows.

All operation methods accept optional `logEnabled` / `logFilePath` params and
implicitly start card detection — they **block until a card is ready** (or the
operation is cancelled via `keycard.CancelCurrentOperation`).

### Result Structure

Responses are JSON-RPC 2.0 objects (`result` and `error` are always both
present; exactly one is non-null):

```json
// success
{"jsonrpc":"2.0","id":"1","result":{ ... },"error":null}

// error
{"jsonrpc":"2.0","id":"1","result":null,"error":{"code":-32601,"message":"Method not found: ..."}}
```

### Signal Callback

```c
typedef void (*KeycardSignalCallback)(const char* signal);
void keycard_set_signal_callback(KeycardSignalCallback callback);
```

Signal format:
```json
{
  "type": "status-changed",
  "event": {
    "state": "Ready",
    "cardUID": "abc123",
    "cardPresent": true,
    "keyInitialized": true,
    "pinRetryCount": 3,
    "pukRetryCount": 5
  }
}
```

## Building

```bash
# Prerequisites
# 1. Build keycard-qt first
cd ../qt-keycard/build
cmake .. && make

# 2. Build status-keycard-qt
cd ../../status-keycard-qt
mkdir build && cd build
cmake ..
make
```

### Dependencies

- Qt 6.9.2+ (Core)
- OpenSSL 3.x
- keycard-qt (built)
- CMake 3.16+
- C++20 compiler

## Usage Example

See [`examples/simple_usage.cpp`](examples/simple_usage.cpp) for a complete,
runnable program and [`examples/test_hardware.cpp`](examples/test_hardware.cpp)
for a hardware test harness.

### C/C++ API

```cpp
#include <status-keycard-qt/status_keycard.h>
#include <QCoreApplication>
#include <thread>
#include <cstdio>

void on_signal(const char* signal_json) {
    printf("Signal: %s\n", signal_json);
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);  // required: the library needs a Qt event loop

    // The RPC service / global context is created lazily on first use.
    KeycardSetSignalEventCallback(on_signal);

    // Blocking operations wait for a card, so run them off the main thread
    // while the Qt event loop keeps processing card detection.
    std::thread worker([&app]() {
        const char* request =
            R"({"jsonrpc":"2.0","method":"keycard.GetKeycardMetadata",)"
            R"("params":{"storageFilePath":"./pairings.json"},"id":"1"})";
        char* response = KeycardCallRPC(request);
        printf("Response: %s\n", response);
        Free(response);

        QMetaObject::invokeMethod(&app, &QCoreApplication::quit);
    });

    int rc = app.exec();
    worker.join();
    return rc;
}
```

### Nim Bindings

```nim
# impl.nim
proc keycardCallRPC(payload: cstring): cstring {.importc: "KeycardCallRPC".}
proc free(p: pointer) {.importc: "Free".}

type SignalCallback* = proc(signal: cstring) {.cdecl.}
proc keycardSetSignalEventCallback(cb: SignalCallback) {.importc: "KeycardSetSignalEventCallback".}
```

```nim
import json

proc callRPC*(methodName: string, params: JsonNode = newJObject()): JsonNode =
  let request = $(%*{
    "jsonrpc": "2.0",
    "method": "keycard." & methodName,
    "params": params,
    "id": "1",
  })
  let raw = keycardCallRPC(request.cstring)
  defer: free(raw)
  result = ($raw).parseJson
```

## Related Projects

- [keycard-qt](https://github.com/status-im/keycard-qt) - Low-level APDU library
- [status-keycard-go](https://github.com/status-im/status-go) - Original Go implementation
- [nim-keycard-go](https://github.com/status-im/status-im/nim-keycard-go) - Nim bindings
- [status-desktop](https://github.com/status-im/status-desktop) - Status Desktop application
