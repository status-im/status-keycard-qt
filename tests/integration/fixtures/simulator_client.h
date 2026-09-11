#pragma once

#include <QString>

namespace IntegrationTest {

class SimulatorClient {
public:
    explicit SimulatorClient(const QString& host = QStringLiteral("127.0.0.1"), int port = 9025);

    bool ping(int timeoutMs = 5000) const;
    bool supportsPowerCycle() const;
    bool supportsCreateEmpty() const;
    bool resetCard(const QString& cardId) const;
    bool createEmptyCard(const QString& cardId) const;

private:
    QString command(const QString& line, int timeoutMs = 5000) const;

    QString m_host;
    int m_port;
};

} // namespace IntegrationTest
