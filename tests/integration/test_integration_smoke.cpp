#include "fixtures/integration_test_base.h"
#include "fixtures/simulator_client.h"
#include "fixtures/test_constants.h"

#include <QtTest/QtTest>

using namespace IntegrationTest;

class TestIntegrationSmoke : public IntegrationTestBase {
    Q_OBJECT

private slots:
    void initTestCase()
    {
        QVERIFY2(initSimulator(), "keycard simulator must be running (JRE >= 11 required)");
    }

    void cleanupTestCase()
    {
        shutdownSimulator();
    }

    void test_simulatorPing()
    {
        SimulatorClient client(QString::fromUtf8(kSimulatorHost), kSimulatorPort);
        QVERIFY(client.ping());
    }
};

QTEST_MAIN(TestIntegrationSmoke)
#include "test_integration_smoke.moc"
