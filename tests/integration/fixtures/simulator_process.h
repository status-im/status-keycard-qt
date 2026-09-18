#pragma once

#include <QProcess>
#include <QString>

namespace IntegrationTest {

class SimulatorProcess {
public:
    explicit SimulatorProcess(const QString& simulatorDir, int port = 9025);
    ~SimulatorProcess();

    bool start(int timeoutMs = 30000);
    void stop();

private:
    QString m_simulatorDir;
    int m_port;
    QProcess m_process;
    bool m_ownsProcess = false;
};

} // namespace IntegrationTest
