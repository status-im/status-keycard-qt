#include "simulator_client.h"

#include <QByteArray>
#include <QTcpSocket>

namespace IntegrationTest {

SimulatorClient::SimulatorClient(const QString& host, int port)
    : m_host(host)
    , m_port(port)
{
}

QString SimulatorClient::command(const QString& line, int timeoutMs) const
{
    QTcpSocket socket;
    socket.connectToHost(m_host, static_cast<quint16>(m_port));
    if (!socket.waitForConnected(timeoutMs)) {
        return {};
    }

    const QByteArray out = line.toUtf8() + '\n';
    socket.write(out);
    if (!socket.waitForBytesWritten(timeoutMs) || !socket.waitForReadyRead(timeoutMs)) {
        return {};
    }

    return QString::fromUtf8(socket.readLine()).trimmed();
}

bool SimulatorClient::ping(int timeoutMs) const
{
    const QString response = command(QStringLiteral("PING"), timeoutMs);
    return response.startsWith(QStringLiteral("OK"));
}

bool SimulatorClient::supportsPowerCycle() const
{
    const QString response = command(QStringLiteral("POWER __probe__"));
    return !response.contains(QStringLiteral("unknown op"), Qt::CaseInsensitive);
}

bool SimulatorClient::supportsCreateEmpty() const
{
    const QString response = command(QStringLiteral("CREATE_EMPTY __probe__"));
    return !response.contains(QStringLiteral("unknown op"), Qt::CaseInsensitive);
}

bool SimulatorClient::resetCard(const QString& cardId) const
{
    const QString response = command(QStringLiteral("RESET %1").arg(cardId));
    return response.startsWith(QStringLiteral("OK"));
}

bool SimulatorClient::createEmptyCard(const QString& cardId) const
{
    const QString response = command(QStringLiteral("CREATE_EMPTY %1").arg(cardId));
    return response.startsWith(QStringLiteral("OK"));
}

} // namespace IntegrationTest
