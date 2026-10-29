# keycard-simulator

An **APDU-over-TCP server** that runs the **real Status Keycard applet** inside
[jcardsim](https://github.com/status-im/jcardsim), so `status-keycard-qt` (built with
`USE_SIMULATED_KEYCARD`) can drive a real card in tests without hardware. The C++
`SimulatedChannelBackend` is the socket client; this server runs the applet, so behaviour is
state-dependent like a physical card (real secp256k1 secure channel, PIN/PUK counters, pairing).

Running it needs **only a JVM** — the `status-keycard` checkout / JavaCard SDK / Gradle are needed
only to *regenerate* the vendored `libs/`.

## Versions

| version | secure channel | matches |
|---------|----------------|---------|
| **3.2** (default) | `SecureChannel` v1, password `PAIR` (`INS 0x12`) | introduced in the keycard-qt commit `df00b931` |
| 4.0 | `SecureChannelV2` (cert-based, no `PAIR`) | applet tag `4.0.1`; keycard-qt with SCv2 support |

Both are supported. 3.2 stays the default for the classic `PAIR` flow; 4.0 is driven by keycard-qt's
SecureChannelV2 client (`./run.sh <port> 4.0`). A client can ask a running server which one it is with
`VERSION`.

## Layout

```
src/im/status/keycardqt/sim/        # version-NEUTRAL core (no im.status.keycard.* imports)
  SimProtocolServer.java            #   TCP protocol + per-id card map; delegates to a CardFactory
  CardFactory.java                  #   interface: appletVersion(), newCard(untrusted)
  CardInstall.java                  #   shared AIDs + install + assignUniqueInstanceUid()
  ExposedRuntime.java               #   exposes jcardsim's installed applet (for the UID patch)
  IdentCertificates.java            #   fixed test CAs + identity certificates + IdentApplet STORE DATA
  IdentityCardSimulator.java        #   card that owns its identity (see below)
libs/common/                        # version-independent: jcardsim, bcprov (bcprov only used by 4.0)
versions/<v>/
  libs/                             # keycard-applet, keycard-math (+ status-keycard-java for 4.0)
  src/.../v<v>/{Main,Card<v>Factory}.java   # entry point + that version's card recipe
  version.properties                # appletVersion, mainClass, needsPersonalization, provenance SHAs
tools/                              # gen-scv2-vectors.sh + generator -> scv2-vectors.json (4.0)
build.sh  run.sh  refresh-artifacts.sh
```

3.2 and 4.0 applet jars share the same class names with different bytecode, so they **cannot share a
classpath**: the core is version-neutral, and each version's recipe is compiled/run against only its
own `libs/` (`run.sh` puts one version on the classpath).

## Card recipe (`Card<v>Factory.newCard()`)

- **3.2** — install KeycardApplet + NDEF + Cash + Ident, `assignUniqueInstanceUid()`, then store a
  CA-signed Ident certificate (handed out by IDENTIFY, blank or initialized). That's a blank /
  post-`FactoryReset` card; the app drives INIT/pair/load-key over real APDUs.
- **4.0** — install the same applets, then store a CA-signed Ident certificate (the 4.0 applet rejects
  every APDU until it has one, and reports it in SELECT). Still blank/no-key.

Both generations give each card a random identity key, with the certificate signed by one of two
**fixed** test CAs (`IdentCertificates`), so a client can pin the trusted one:

| CA | private key | compressed public key |
|----|-------------|-----------------------|
| test (trusted) | SHA256(UTF-8 `keycard-qt simulator test CA`) | `036a5b809145f2c8f75d9737affd72d0a01c6696cbc5efdc69db70a3d2fbbf26fa` |
| untrusted (`CREATE <id> UNTRUSTED`) | SHA256(UTF-8 `keycard-qt simulator untrusted CA`) | `02571b5324234aebec0ab4554a50ac6aa95dea309ee35bc560e39f55d47af3c9b7` |

The 4.x applet has no instance UID (and no pairing), so `assignUniqueInstanceUid()` is 3.2-only.

The applets keep the identity in `SharedMemory`, whose fields are **static**, so in one JVM every card
would share the identity of the card created last (and installing an IdentApplet clears it). Each card
is therefore an `IdentityCardSimulator`: it keeps its own identity and puts it back into `SharedMemory`
before handling an APDU, under one lock for all cards, which card creation holds too.

`COUNTERFEIT <id>` turns a card into one that carries a copied certificate: it keeps the certificate
(and its keys, PIN and pairings) but gets an unrelated identity key, which the applet does not check.
On 4.x its secure channel signature no longer matches the certificate, so a client refuses it
(`untrusted-keycard`); on 3.x it fails IDENTIFY and is reported untrusted. A blank 4.x card opens no
secure channel until INIT, so counterfeit a card after loading it.

`assignUniqueInstanceUid()` overwrites the applet's instance UID with random bytes, because jcardsim's
RNG is deterministic and would otherwise give every card the same UID — colliding in the lib's
pairing storage (keyed by instance UID).

## Build & run

```bash
./build.sh
./run.sh 9025            # applet 3.2 (default) on TCP 9025
./run.sh 9025 4.0        # applet 4.0 (SecureChannelV2)
```

## C++ integration tests

See the [root README](../../README.md#integration-tests-jcardsim) for cmake/ctest
commands. Tests spawn `run.sh` automatically; a manual `./run.sh` is only needed
for debugging. `run.sh` frees the port from a leftover simulator first, and
passes `-noverify` (jcardsim's `javacard.*` classes have no stackmap frames).

## Protocol (text, one request/response per line)

```
VERSION                  -> OK <appletVersion>  e.g. OK 4.0 / OK 3.2
CREATE <id>              -> OK <atrHex>   create if absent (no-op if present)
CREATE <id> UNTRUSTED    -> OK <atrHex>   same, identity cert signed by the untrusted CA
CREATE_EMPTY <id>        -> OK <atrHex>   card with no Keycard applet (SELECT fails)
RESET  <id>              -> OK            recreate fresh / blank, keeping the card's trust flavour
POWER  <id>              -> OK            power-cycle volatile state (PIN session) without wiping EEPROM
COUNTERFEIT <id>         -> OK            swap the identity key, keeping the certificate and all state:
                                          a genuine certificate the card cannot sign for (see below)
ATR    <id>              -> OK <atrHex>
APDU   <id> <apduHex>    -> OK <respHex>
PING                     -> OK
<other>                  -> ERR <message>
```

Each `<id>` is an independent card (e.g. `A`, `B`) for multi-card flows; state persists until `RESET`.
`CREATE` on an existing id is a no-op even if the flag differs; use another id or `RESET` to change it.
To check a running server by hand (SELECT the keycard AID; a blank 3.2 card replies with its
secure-channel pubkey + `9000`, a 4.0 card with an `A4` template whose tag `8A` is the 98-byte
identity certificate):

```python
import socket
s = socket.create_connection(("127.0.0.1", 9025))
s.sendall(b"CREATE A\nAPDU A 00a4040009a00000080400010101\n")
print(s.recv(8192).decode())   # OK <ATR>  then  OK 8041<pubkey>9000
```

## SecureChannelV2 test vectors

`tools/scv2-vectors.json` holds known-answer vectors for the C++ SCv2 client: the CA and a fixed
identity key, the certificate (`v` is the raw recovery id 0..3), a full handshake with fixed salt and
ephemeral keys (shared X, HKDF keys, transcript, one card signature) and two AES-CCM round trips
(nonce 0 and 1). They come from the real 4.0 applet in jcardsim driven by the real host SDK, with the
randomness pinned, and are cross-checked with BouncyCastle (`tools/src/.../GenScv2Vectors.java`).
Regenerate with `./tools/gen-scv2-vectors.sh` — only the certificate signature and the card's
handshake signature change between runs (both use a random ECDSA nonce); the notes in the JSON spell
out the wire formats.

## Updating the vendored `libs/`

`libs/` is committed. Regenerate it only when bumping the applet/jcardsim, from a built
`status-keycard` checkout at the version's SHA (`version.properties`):

```bash
cd "$STATUS_KEYCARD_DIR" && git checkout <sha>   # need the jcardsim + keycard-math jars present here
cd - && STATUS_KEYCARD_DIR="$STATUS_KEYCARD_DIR" ./refresh-artifacts.sh <version>
./build.sh   # recompile the recipe, then commit the changed libs/
```
`STATUS_KEYCARD_DIR` is required (no default); a `git worktree` of status-keycard works. For 4.0 the
host SDK and bcprov are taken from the Gradle cache if present, otherwise downloaded from JitPack /
Maven Central. Do **not** run `./gradlew compileJava` — it fails on JDK 9+
(status-keycard targets source/target 1.6) and isn't needed: `refresh-artifacts.sh` recompiles the applet
from source with `javac --release 11` (override with `APPLET_RELEASE`) rather than reusing gradle's class
files, so the vendored `keycard-applet.jar` stays runnable on any JRE ≥ 11. Otherwise, if built with a
newer JDK (e.g. 17), it becomes the highest-versioned class on the classpath and forces that JRE at
runtime — which breaks a double-clicked macOS app (whose JRE, via `/usr/bin/java`, may be older than your
shell's). You only need the prebuilt `jcardsim`/`keycard-math` jars in the checkout (build just those
modules if missing, e.g. `./gradlew :keycard-math:jar`).

## Provenance

| version | status-keycard | jcardsim | host SDK |
|---------|----------------|----------|----------|
| 3.2 | `72e9574` | `e1e351a` | `…:desktop:e898afd` (unused — install-only) |
| 4.0 | `37393a2` (tag `4.0.1`) | `e1e351a` | `…:lib:4.0.0` (+ bcprov 1.65 for personalization) |

SHAs are also recorded in each `versions/<v>/version.properties`. The 4.0 SDK is the one status-keycard
`6f8544a` ("update SDK used for tests") moved its tests to (`…:desktop:4.0.0`, which pulls in
`…:lib:4.0.0`; only `lib` is needed here). The vendored jcardsim jar is `e1e351a` plus status-keycard's
local jcardsim patches (on-curve check in ECDH, transient EC private keys, `sendBytes` bounds) — the
same jar both versions use.
