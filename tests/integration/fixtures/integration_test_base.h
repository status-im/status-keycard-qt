#pragma once

#include "rpc_client.h"
#include "simulator_process.h"

#include <QObject>
#include <QString>

namespace IntegrationTest {

class IntegrationTestBase : public QObject {
    Q_OBJECT

protected:
    bool initSimulator();
    void shutdownSimulator();

    QString freshCardId(const QString& suffix) const;

    static SimulatorProcess* s_simulator;
    RpcClient m_rpc;
};

} // namespace IntegrationTest
