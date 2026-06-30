// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
#include "session/simulated_channel_backend.h"

#include <QDebug>
#include <cstring>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define SK_CLOSESOCKET closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <unistd.h>
#  define SK_CLOSESOCKET ::close
#endif

namespace StatusKeycard {

namespace {
#if defined(_WIN32)
struct WinsockInit {
    WinsockInit() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
};
static WinsockInit g_winsockInit;
#endif

QString toHex(const QByteArray& b) { return QString::fromLatin1(b.toHex()); }
} // namespace

SimulatedChannelBackend::SimulatedChannelBackend(QObject* parent)
    : Keycard::KeycardChannelBackend(parent) {}

SimulatedChannelBackend::~SimulatedChannelBackend() {
    QMutexLocker lock(&m_mutex);
    closeSocketLocked();
}

// ---- socket helpers (m_mutex held) ----------------------------------------

void SimulatedChannelBackend::closeSocketLocked() {
    if (m_fd >= 0) {
        SK_CLOSESOCKET(m_fd);
        m_fd = -1;
    }
    m_readBuf.clear();
}

bool SimulatedChannelBackend::ensureConnectedLocked() {
    if (m_fd >= 0) {
        return true;
    }
    if (m_host.isEmpty() || m_port == 0) {
        return false;
    }

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    const std::string portStr = std::to_string(m_port);
    if (getaddrinfo(m_host.toUtf8().constData(), portStr.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

    int fd = static_cast<int>(socket(res->ai_family, res->ai_socktype, res->ai_protocol));
    if (fd < 0) {
        freeaddrinfo(res);
        return false;
    }
    if (::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        SK_CLOSESOCKET(fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    m_fd = fd;
    m_readBuf.clear();
    return true;
}

QString SimulatedChannelBackend::commandLocked(const QString& line) {
    if (!ensureConnectedLocked()) {
        throw std::runtime_error("keycard simulator not reachable");
    }

    // send "<line>\n"
    const QByteArray out = line.toUtf8() + '\n';
    int sent = 0;
    while (sent < out.size()) {
        const auto n = ::send(m_fd, out.constData() + sent, out.size() - sent, 0);
        if (n <= 0) {
            closeSocketLocked();
            throw std::runtime_error("keycard simulator write failed");
        }
        sent += static_cast<int>(n);
    }

    // read one line
    int nl;
    while ((nl = m_readBuf.indexOf('\n')) < 0) {
        char buf[4096];
        const auto n = ::recv(m_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            closeSocketLocked();
            throw std::runtime_error("keycard simulator closed connection");
        }
        m_readBuf.append(buf, static_cast<int>(n));
    }
    const QString resp = QString::fromUtf8(m_readBuf.left(nl)).trimmed();
    m_readBuf.remove(0, nl + 1);

    if (resp.startsWith(QLatin1String("OK"))) {
        return resp.mid(2).trimmed(); // payload after "OK"
    }
    if (resp.startsWith(QLatin1String("ERR"))) {
        throw std::runtime_error(("keycard simulator: " + resp.mid(3).trimmed()).toStdString());
    }
    throw std::runtime_error(("keycard simulator: unexpected reply: " + resp).toStdString());
}

// ---- test control ---------------------------------------------------------

bool SimulatedChannelBackend::attach(const QString& endpoint) {
    const int colon = endpoint.lastIndexOf(':');
    if (colon <= 0) {
        qWarning() << "SimulatedChannelBackend::attach: invalid endpoint" << endpoint;
        return false;
    }
    QMutexLocker lock(&m_mutex);
    m_host = endpoint.left(colon);
    m_port = static_cast<quint16>(endpoint.mid(colon + 1).toUShort());
    closeSocketLocked();
    // Only RECORD the endpoint here — do NOT connect. attach() runs at app startup (keycard context
    // creation, via setSignalEventCallback), when the jcardsim server usually isn't up yet. A blocking
    // connect to an unreachable endpoint would stall startup (and under Squish/e2e the app would never
    // open its control port). commandLocked() connects lazily on the first real command.
    qDebug() << "SimulatedChannelBackend::attach: endpoint set to" << endpoint;
    return true;
}

bool SimulatedChannelBackend::insertCard(const QString& cardId) {
    {
        QMutexLocker lock(&m_mutex);
        try {
            commandLocked(QStringLiteral("CREATE ") + cardId); // no-op if it already exists
        } catch (const std::exception& e) {
            qWarning() << "SimulatedChannelBackend::insertCard failed:" << e.what();
            return false;
        }
        m_activeCard = cardId;
    }
    m_readerPresent = true;
    m_cardPresent = true;
    m_cardAnnounced = false;   // fresh card: not yet announced

    emit readerAvailabilityChanged(true);
    // Announce only if the lib is already waiting for a card (an interactive insert during a flow).
    // If the card is inserted BEFORE a flow runs, publishPresence() announces it once when the flow
    // enters WaitingForCard (see setState) — announcing here too would double-detect and reset the
    // secure channel mid-flow.
    if (m_lifecycleState == Keycard::ChannelState::WaitingForCard) {
        announceCard();
    }
    qDebug() << "SimulatedChannelBackend: inserted card" << cardId << "uid" << toHex(cardId.toUtf8());
    return true;
}

void SimulatedChannelBackend::removeCard() {
    m_cardPresent = false;
    m_cardAnnounced = false;
    {
        QMutexLocker lock(&m_mutex);
        m_activeCard.clear();
    }
    emit cardRemoved();
    qDebug() << "SimulatedChannelBackend: removed card";
}

bool SimulatedChannelBackend::createCard(const QString& cardId) {
    QMutexLocker lock(&m_mutex);
    try {
        commandLocked(QStringLiteral("CREATE ") + cardId);
        return true;
    } catch (const std::exception& e) {
        qWarning() << "SimulatedChannelBackend::createCard failed:" << e.what();
        return false;
    }
}

void SimulatedChannelBackend::plugReader() {
    m_readerPresent = true;
    emit readerAvailabilityChanged(true);
    qDebug() << "SimulatedChannelBackend::plugReader";
}

void SimulatedChannelBackend::unplugReader() {
    m_readerPresent = false;
    m_cardPresent = false;
    m_cardAnnounced = false;
    {
        QMutexLocker lock(&m_mutex);
        m_activeCard.clear();
    }
    emit readerAvailabilityChanged(false);
    emit cardRemoved();
    qDebug() << "SimulatedChannelBackend::unplugReader";
}

// ---- KeycardChannelBackend ------------------------------------------------

void SimulatedChannelBackend::announceCard() {
    // Emit targetDetected at most once per inserted card; re-emitting causes a re-detection which
    // resets the secure channel mid-flow (see header). Reset on removeCard()/unplugReader().
    if (m_cardAnnounced.exchange(true)) {
        return;
    }
    QString cardId;
    {
        QMutexLocker lock(&m_mutex);
        cardId = m_activeCard;
    }
    emit targetDetected(toHex(cardId.toUtf8()));
}

void SimulatedChannelBackend::publishPresence() {
    if (m_cardPresent) {
        emit readerAvailabilityChanged(true);
        announceCard();
    } else {
        // false (the default) makes SessionManager show "plug reader" and wait.
        emit readerAvailabilityChanged(m_readerPresent);
    }
    qDebug() << "SimulatedChannelBackend::publishPresence reader=" << bool(m_readerPresent)
             << "card=" << bool(m_cardPresent);
}

void SimulatedChannelBackend::startDetection() {
    m_detecting = true;
    publishPresence();
}

void SimulatedChannelBackend::stopDetection() {
    m_detecting = false;
    emit targetDetectionStopped(false);
}

bool SimulatedChannelBackend::isDetectionActive() const { return m_detecting; }

void SimulatedChannelBackend::disconnect() {
    // Programmatic disconnect: do not emit cardRemoved (matches PC/SC semantics).
}

bool SimulatedChannelBackend::isConnected() const { return m_cardPresent; }

QByteArray SimulatedChannelBackend::transmit(const QByteArray& apdu) {
    QMutexLocker lock(&m_mutex);
    if (!m_cardPresent || m_activeCard.isEmpty()) {
        throw std::runtime_error("no simulated card present");
    }
    const QString payload = commandLocked(QStringLiteral("APDU ") + m_activeCard + ' ' + toHex(apdu));
    const QByteArray resp = QByteArray::fromHex(payload.toLatin1());
    if (resp.isEmpty()) {
        throw std::runtime_error("empty response from simulated card");
    }
    return resp;
}

void SimulatedChannelBackend::setState(Keycard::ChannelState state) {
    // Entering WaitingForCard from another state starts a fresh detection cycle: clear the "announced"
    // flag so an already-present card is re-announced for this flow. Without this, a flow started
    // while a card is already inserted would never detect it (publishPresence would be deduped).
    const bool freshWait = (state == Keycard::ChannelState::WaitingForCard
                            && m_lifecycleState != Keycard::ChannelState::WaitingForCard);
    m_lifecycleState = state;
    // CommandSet::startDetection() drives this to WaitingForCard. Unlike the PC/SC backend (which
    // polls from a background thread), this backend has no poll, so we publish the current
    // reader/card presence here — that's what makes SessionManager show "plug reader" when no
    // reader is plugged, instead of jumping straight to "insert keycard".
    if (state == Keycard::ChannelState::WaitingForCard) {
        if (freshWait) {
            m_cardAnnounced = false;
        }
        publishPresence();
    }
}

Keycard::ChannelState SimulatedChannelBackend::state() const { return m_lifecycleState; }

Keycard::ChannelOperationalState SimulatedChannelBackend::channelState() const {
    if (m_cardPresent) {
        return Keycard::ChannelOperationalState::Reading;
    }
    if (m_readerPresent) {
        return Keycard::ChannelOperationalState::WaitingForKeycard;
    }
    return Keycard::ChannelOperationalState::NotAvailable;
}

void SimulatedChannelBackend::forceScan() {
    if (m_cardPresent) {
        announceCard();
    }
}

} // namespace StatusKeycard
