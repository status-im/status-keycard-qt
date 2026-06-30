// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
#pragma once

#include "keycard-qt/backends/keycard_channel_backend.h"

#include <QByteArray>
#include <QMutex>
#include <QString>
#include <atomic>

namespace StatusKeycard {

/**
 * @brief A KeycardChannelBackend that talks to the jcardsim-backed simulator over TCP.
 *
 * Compiled only when USE_SIMULATED_KEYCARD is defined. Instead of a physical PC/SC reader,
 * APDUs are forwarded to the keycard-simulator server (see test/keycard-simulator), which runs the
 * real Status Keycard applet. Card presence (insert/remove/swap) is driven explicitly via the
 * control methods below — wired to the test-only C API in c_api.cpp — rather than by polling.
 *
 * Threading: control methods and transmit() are guarded by a mutex and may be called from any
 * thread; detection state changes are published via the base-class signals (delivered queued to
 * the consumer's thread by Qt).
 */
class SimulatedChannelBackend : public Keycard::KeycardChannelBackend {
    Q_OBJECT

public:
    explicit SimulatedChannelBackend(QObject* parent = nullptr);
    ~SimulatedChannelBackend() override;

    // ---- Test control (called from the test-only C API) -------------------
    /** Connect to the simulator server. @param endpoint "host:port" (e.g. "127.0.0.1:9025"). */
    bool attach(const QString& endpoint);
    /** Create a fresh/empty card @p cardId in the simulator's map, without presenting it. */
    bool createCard(const QString& cardId);
    /** Make @p cardId the inserted card (creating it on the server if needed) and emit detection. */
    bool insertCard(const QString& cardId);
    /** Remove the currently inserted card (emits cardRemoved). */
    void removeCard();
    /** Simulate the reader being plugged in / unplugged. */
    void plugReader();
    void unplugReader();

    // ---- KeycardChannelBackend --------------------------------------------
    void startDetection() override;
    void stopDetection() override;
    bool isDetectionActive() const override;
    void disconnect() override;
    bool isConnected() const override;
    QByteArray transmit(const QByteArray& apdu) override;
    QString backendName() const override { return QStringLiteral("Simulated (jcardsim)"); }
    void setState(Keycard::ChannelState state) override;
    Keycard::ChannelState state() const override;
    Keycard::ChannelOperationalState channelState() const override;
    void forceScan() override;

private:
    // Socket helpers (raw blocking TCP). m_mutex must be held by the caller.
    bool ensureConnectedLocked();
    void closeSocketLocked();
    // Sends one protocol line and returns the response payload after "OK ";
    // throws std::runtime_error on transport error or an "ERR ..." reply.
    QString commandLocked(const QString& line);

    // Emits the current reader/card availability to the upper layers (SessionManager). This
    // event-driven backend has no polling thread, so we publish presence whenever detection
    // (re)starts — i.e. from setState(WaitingForCard).
    void publishPresence();

    // Emits targetDetected exactly ONCE per inserted card. Re-emitting for an already-detected card
    // makes the lib treat it as a re-tap -> resetSecureChannel -> the secure channel is reopened
    // mid-flow, dropping the card's PIN-validated state and breaking LOAD_KEY (SW=6985). Reset by
    // removeCard()/unplugReader() (and on a fresh insertCard()).
    void announceCard();

    mutable QMutex m_mutex;
    int m_fd = -1;              // socket fd (-1 = not connected); SOCKET cast on Windows
    QByteArray m_readBuf;       // line-assembly buffer for socket reads
    QString m_host;
    quint16 m_port = 0;

    QString m_activeCard;
    std::atomic<bool> m_cardPresent{false};
    std::atomic<bool> m_cardAnnounced{false};  // has targetDetected been emitted for the current card?
    std::atomic<bool> m_detecting{false};
    std::atomic<bool> m_readerPresent{false};  // reader starts unplugged (mirrors no reader present)
    Keycard::ChannelState m_lifecycleState{Keycard::ChannelState::Idle};
};

} // namespace StatusKeycard
