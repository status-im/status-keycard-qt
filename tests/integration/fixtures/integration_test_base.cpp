#include "integration_test_base.h"

#include <QDateTime>

namespace IntegrationTest {

SimulatorProcess* IntegrationTestBase::s_simulator = nullptr;

bool IntegrationTestBase::initSimulator()
{
    if (!s_simulator) {
        s_simulator = new SimulatorProcess(QString::fromUtf8(KEYCARD_SIMULATOR_DIR));
        if (!s_simulator->start()) {
            delete s_simulator;
            s_simulator = nullptr;
            return false;
        }
    }
    return true;
}

void IntegrationTestBase::shutdownSimulator()
{
    m_rpc.stop();
    if (s_simulator) {
        s_simulator->stop();
        delete s_simulator;
        s_simulator = nullptr;
    }
}

QString IntegrationTestBase::freshCardId(const QString& suffix) const
{
    return QStringLiteral("it-%1-%2").arg(suffix, QString::number(QDateTime::currentMSecsSinceEpoch()));
}

} // namespace IntegrationTest
