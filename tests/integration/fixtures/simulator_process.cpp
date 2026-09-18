#include "simulator_process.h"
#include "simulator_client.h"

#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QThread>

namespace IntegrationTest {

SimulatorProcess::SimulatorProcess(const QString& simulatorDir, int port)
    : m_simulatorDir(simulatorDir)
    , m_port(port)
{
}

SimulatorProcess::~SimulatorProcess()
{
    stop();
}

bool SimulatorProcess::start(int timeoutMs)
{
    SimulatorClient client(QStringLiteral("127.0.0.1"), m_port);
    if (client.ping(1000) && client.supportsPowerCycle() && client.supportsCreateEmpty()) {
        return true;
    }
    if (client.ping(1000)) {
        qWarning("Restarting outdated keycard simulator (missing POWER or CREATE_EMPTY)");
    }
    if (m_process.state() != QProcess::NotRunning) {
        stop();
    }

    const QString runScript = QDir(m_simulatorDir).filePath(QStringLiteral("run.sh"));
    if (!QFileInfo::exists(runScript)) {
        qWarning("Simulator run.sh not found at %s", qPrintable(runScript));
        return false;
    }

    m_process.setProgram(QStringLiteral("/bin/bash"));
    m_process.setArguments({runScript, QString::number(m_port), QStringLiteral("3.2")});
    m_process.setWorkingDirectory(m_simulatorDir);
    m_process.setProcessChannelMode(QProcess::MergedChannels);
    m_process.start();

    if (!m_process.waitForStarted(5000)) {
        qWarning("Failed to start keycard simulator: %s", qPrintable(m_process.errorString()));
        return false;
    }

    m_ownsProcess = true;

    const int stepMs = 200;
    int waited = 0;
    while (waited < timeoutMs) {
        if (client.ping(1000)) {
            return true;
        }
        if (m_process.state() == QProcess::NotRunning) {
            qWarning("Simulator process exited early: %s", m_process.readAllStandardOutput().constData());
            m_ownsProcess = false;
            return false;
        }
        QThread::msleep(static_cast<unsigned long>(stepMs));
        waited += stepMs;
    }

    qWarning("Simulator did not respond to PING within %d ms", timeoutMs);
    stop();
    return false;
}

void SimulatorProcess::stop()
{
    if (!m_ownsProcess || m_process.state() == QProcess::NotRunning) {
        m_ownsProcess = false;
        return;
    }

    m_process.terminate();
    if (!m_process.waitForFinished(3000)) {
        m_process.kill();
        m_process.waitForFinished(3000);
    }
    m_ownsProcess = false;
}

} // namespace IntegrationTest
