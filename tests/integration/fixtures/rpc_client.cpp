#include "rpc_client.h"
#include "simulator_client.h"
#include "test_constants.h"

#include <status-keycard-qt/status_keycard.h>

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QTimer>
#include <atomic>
#include <thread>

namespace IntegrationTest {

RpcClient* RpcClient::s_activeClient = nullptr;

RpcClient::RpcClient()
{
    s_activeClient = this;
    KeycardSetSignalEventCallback(&RpcClient::onSignal);
}

RpcClient::~RpcClient()
{
    if (s_activeClient == this) {
        KeycardSetSignalEventCallback(nullptr);
        s_activeClient = nullptr;
    }
}

QString RpcClient::storagePath() const
{
    return m_tempDir.filePath(QStringLiteral("pairings.json"));
}

void RpcClient::onSignal(const char* signalJson)
{
    if (!s_activeClient || !signalJson) {
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(QByteArray(signalJson));
    if (!doc.isObject()) {
        return;
    }

    const QJsonObject root = doc.object();
    if (root.value(QStringLiteral("type")).toString() != QStringLiteral("status-changed")) {
        return;
    }

    const QJsonObject event = root.value(QStringLiteral("event")).toObject();
    s_activeClient->recordSignal(event);
    s_activeClient->triggerStatusAction(event.value(QStringLiteral("state")).toString());
}

void RpcClient::recordSignal(const QJsonObject& event)
{
    StatusSignal status;
    status.state = event.value(QStringLiteral("state")).toString();

    const QJsonObject cardStatus = event.value(QStringLiteral("keycardStatus")).toObject();
    if (!cardStatus.isEmpty()) {
        status.remainingPinAttempts = cardStatus.value(QStringLiteral("remainingAttemptsPIN")).toInt(-1);
        status.remainingPukAttempts = cardStatus.value(QStringLiteral("remainingAttemptsPUK")).toInt(-1);
    }

    const QJsonObject cardInfo = event.value(QStringLiteral("keycardInfo")).toObject();
    if (!cardInfo.isEmpty()) {
        status.instanceUid = cardInfo.value(QStringLiteral("instanceUID")).toString();
        status.keyUid = cardInfo.value(QStringLiteral("keyUID")).toString();
        status.availableSlots = cardInfo.value(QStringLiteral("availableSlots")).toInt(-1);
    }

    QMutexLocker locker(&m_signalsMutex);
    m_statusSignals.append(status);
}

QJsonObject RpcClient::parseResponse(const QByteArray& responseBytes) const
{
    if (responseBytes.isEmpty()) {
        return {};
    }
    return QJsonDocument::fromJson(responseBytes).object();
}

QJsonObject RpcClient::callRpc(const QString& method, const QJsonObject& params, int timeoutMs)
{
    return callRpcInternal(method, params, timeoutMs).response;
}

InterruptedRpcCall RpcClient::callRpcAfterStatus(
    const QString& method,
    const QJsonObject& params,
    const QString& triggerState,
    std::function<void()> action,
    int timeoutMs)
{
    return callRpcInternal(method, params, timeoutMs, triggerState, std::move(action));
}

InterruptedRpcCall RpcClient::callRpcInternal(
    const QString& method,
    const QJsonObject& params,
    int timeoutMs,
    const QString& triggerState,
    std::function<void()> action)
{
    QJsonObject request;
    request.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));
    request.insert(QStringLiteral("method"), method);
    request.insert(QStringLiteral("id"), 1);

    QJsonArray paramsArray;
    paramsArray.append(params);
    request.insert(QStringLiteral("params"), paramsArray);

    const QByteArray payload = QJsonDocument(request).toJson(QJsonDocument::Compact);

    QEventLoop loop;
    QByteArray responseBytes;
    std::atomic<bool> done{false};

    {
        QMutexLocker locker(&m_actionMutex);
        m_triggerState = triggerState;
        m_statusAction = std::move(action);
        m_actionTriggered = false;
    }

    std::thread worker([&]() {
        char* response = KeycardCallRPC(payload.constData());
        if (response) {
            responseBytes = QByteArray(response);
            Free(response);
        }
        done = true;
        QMetaObject::invokeMethod(&loop, &QEventLoop::quit, Qt::QueuedConnection);
    });

    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, [&]() {
        if (!done) {
            cancelCurrentOperation();
        }
    });
    timer.start(timeoutMs);

    QTimer hardTimeout;
    hardTimeout.setSingleShot(true);
    QObject::connect(&hardTimeout, &QTimer::timeout, &loop, [&]() {
        if (!done) {
            qWarning("RPC %s still running after timeout; forcing Stop", qPrintable(method));
            char* stop = KeycardCallRPC(
                "{\"jsonrpc\":\"2.0\",\"method\":\"keycard.Stop\",\"params\":[{}],\"id\":\"stop\"}");
            Free(stop);
            loop.quit();
        }
    });
    hardTimeout.start(timeoutMs + 5000);

    loop.exec();
    worker.join();

    bool actionTriggered = false;
    {
        QMutexLocker locker(&m_actionMutex);
        actionTriggered = m_actionTriggered;
        m_triggerState.clear();
        m_statusAction = {};
    }

    return {parseResponse(responseBytes), actionTriggered};
}

void RpcClient::cancelCurrentOperation()
{
    char* response = KeycardCallRPC(
        "{\"jsonrpc\":\"2.0\",\"method\":\"keycard.CancelCurrentOperation\",\"params\":[],\"id\":\"cancel\"}");
    Free(response);
}

void RpcClient::stop()
{
    callRpc(QStringLiteral("keycard.Stop"), QJsonObject(), 10000);
}

void RpcClient::plugReader()
{
    char* result = KeycardTestPlugReader();
    Free(result);
}

void RpcClient::unplugReader()
{
    char* result = KeycardTestUnplugReader();
    Free(result);
}

void RpcClient::plugInsertCard(const QString& cardId)
{
    plugReader();

    char* insert = KeycardTestInsertCard(cardId.toUtf8().constData());
    Free(insert);
}

void RpcClient::removeCard()
{
    char* result = KeycardTestRemoveCard();
    Free(result);
}

void RpcClient::clearPairings()
{
    QFile file(storagePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write("{}");
        file.close();
    }
}

StatusSignal RpcClient::lastStatusSignal() const
{
    QMutexLocker locker(&m_signalsMutex);
    if (m_statusSignals.isEmpty()) {
        return {};
    }
    return m_statusSignals.last();
}

QVector<StatusSignal> RpcClient::statusSignals() const
{
    QMutexLocker locker(&m_signalsMutex);
    return m_statusSignals;
}

void RpcClient::clearSignals()
{
    QMutexLocker locker(&m_signalsMutex);
    m_statusSignals.clear();
}

void RpcClient::triggerStatusAction(const QString& state)
{
    std::function<void()> action;
    {
        QMutexLocker locker(&m_actionMutex);
        if (!m_actionTriggered && m_statusAction && state == m_triggerState) {
            m_actionTriggered = true;
            action = std::move(m_statusAction);
        }
    }
    if (action) {
        action();
    }
}

QString RpcClient::keyUidFromLastStatus() const
{
    QMutexLocker locker(&m_signalsMutex);
    for (auto it = m_statusSignals.crbegin(); it != m_statusSignals.crend(); ++it) {
        if (!it->keyUid.isEmpty()) {
            return it->keyUid;
        }
    }
    return {};
}

QString RpcClient::keycardUidFromLastStatus() const
{
    QMutexLocker locker(&m_signalsMutex);
    for (auto it = m_statusSignals.crbegin(); it != m_statusSignals.crend(); ++it) {
        if (!it->instanceUid.isEmpty()) {
            return it->instanceUid;
        }
    }
    return {};
}

QJsonObject RpcClient::loadCard(const QString& cardId, const QString& mnemonic,
                                const QString& pin, const QString& puk,
                                const QString& pairingPassword)
{
    SimulatorClient simulator(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
    if (!simulator.resetCard(cardId)) {
        return {
            {QStringLiteral("error"),
             QJsonObject{{QStringLiteral("message"), QStringLiteral("Failed to reset simulator card")}}}
        };
    }

    stop();
    clearSignals();
    plugInsertCard(cardId);

    QJsonObject params;
    params.insert(QStringLiteral("storageFilePath"), storagePath());
    params.insert(QStringLiteral("pin"), pin);
    params.insert(QStringLiteral("puk"), puk);
    params.insert(QStringLiteral("mnemonic"), mnemonic);
    if (!pairingPassword.isEmpty()) {
        params.insert(QStringLiteral("pairingPassword"), pairingPassword);
    }

    // Do not retry SW=6F00 / 6982 / 6985: those are the host/card desync
    // failures the applet integration is meant to catch.
    return callRpc(QStringLiteral("keycard.Load"), params);
}

QJsonObject RpcClient::login(const QString& pin, const QString& keyUid, const QString& pairingPassword)
{
    QJsonObject params;
    params.insert(QStringLiteral("storageFilePath"), storagePath());
    params.insert(QStringLiteral("pin"), pin);
    if (!keyUid.isEmpty()) {
        params.insert(QStringLiteral("keyUid"), keyUid);
    }
    if (!pairingPassword.isEmpty()) {
        params.insert(QStringLiteral("pairingPassword"), pairingPassword);
    }
    return callRpc(QStringLiteral("keycard.Login"), params);
}

QVector<int> RpcClient::blockPin(const QString& cardId, const QString& keyUid, int attempts)
{
    QVector<int> remainingAttempts;
    for (int i = 0; i < attempts; ++i) {
        // Do not POWER/remove between wrong-PIN tries: jcardsim reset() can restore
        // pinRetryCount, and a successful Login (cached PIN) would abort the loop at 1.
        stop();
        plugInsertCard(cardId);
        clearSignals();
        login(QString::fromUtf8(kWrongPin), keyUid);

        int remaining = -1;
        for (const StatusSignal& signal : statusSignals()) {
            if (signal.remainingPinAttempts >= 0
                && (remaining < 0 || signal.remainingPinAttempts < remaining)) {
                remaining = signal.remainingPinAttempts;
            }
        }
        remainingAttempts.append(remaining);
        if (remaining == 0) {
            break;
        }
    }
    return remainingAttempts;
}

} // namespace IntegrationTest
