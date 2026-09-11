#pragma once

#include <functional>

#include <QJsonObject>
#include <QMutex>
#include <QString>
#include <QTemporaryDir>
#include <QVector>

namespace IntegrationTest {

struct StatusSignal {
    QString state;
    int remainingPinAttempts = -1;
    int remainingPukAttempts = -1;
    int availableSlots = -1;
    QString instanceUid;
    QString keyUid;
};

struct InterruptedRpcCall {
    QJsonObject response;
    bool actionTriggered = false;
};

class RpcClient {
public:
    RpcClient();
    ~RpcClient();

    QString storagePath() const;

    QJsonObject callRpc(const QString& method, const QJsonObject& params, int timeoutMs = 60000);
    InterruptedRpcCall callRpcAfterStatus(
        const QString& method,
        const QJsonObject& params,
        const QString& triggerState,
        std::function<void()> action,
        int timeoutMs = 15000);
    void cancelCurrentOperation();

    void stop();
    void plugReader();
    void unplugReader();
    void plugInsertCard(const QString& cardId);
    void removeCard();
    void clearPairings();

    StatusSignal lastStatusSignal() const;
    QVector<StatusSignal> statusSignals() const;
    void clearSignals();

    QString keyUidFromLastStatus() const;
    QString keycardUidFromLastStatus() const;

    QJsonObject loadCard(const QString& cardId, const QString& mnemonic,
                         const QString& pin = QStringLiteral("111111"),
                         const QString& puk = QStringLiteral("000000000000"),
                         const QString& pairingPassword = QString());

    QJsonObject login(const QString& pin, const QString& keyUid = QString(),
                      const QString& pairingPassword = QString());
    QVector<int> blockPin(const QString& cardId, const QString& keyUid, int attempts = 3);

private:
    static void onSignal(const char* signalJson);

    InterruptedRpcCall callRpcInternal(
        const QString& method,
        const QJsonObject& params,
        int timeoutMs,
        const QString& triggerState = {},
        std::function<void()> action = {});
    QJsonObject parseResponse(const QByteArray& responseBytes) const;
    void recordSignal(const QJsonObject& signal);
    void triggerStatusAction(const QString& state);

    QTemporaryDir m_tempDir;
    static RpcClient* s_activeClient;
    mutable QMutex m_signalsMutex;
    QVector<StatusSignal> m_statusSignals;
    mutable QMutex m_actionMutex;
    QString m_triggerState;
    std::function<void()> m_statusAction;
    bool m_actionTriggered = false;
};

} // namespace IntegrationTest
