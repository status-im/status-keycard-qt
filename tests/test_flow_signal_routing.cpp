#include <QtTest/QtTest>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include "signal_manager.h"
#include "flow/flow_manager.h"
#include "flow/flow_signals.h"
#include "flow/flow_types.h"
#include "mocks/mock_communication_manager.h"
#include <memory>

using namespace StatusKeycard;
using namespace StatusKeycardTest;

class TestFlowSignalRouting : public QObject
{
    Q_OBJECT

private:
    static void signalCallback(const char* signal) {
        if (!signal) return;
        
        QString signalStr = QString::fromUtf8(signal);
        
        QJsonDocument doc = QJsonDocument::fromJson(signalStr.toUtf8());
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            QString type = obj["type"].toString();
            s_receivedSignalTypes.append(type);
        }
    }
    
    static QList<QString> s_receivedSignalTypes;
    
    std::shared_ptr<StatusKeycardTest::MockCommunicationManager> m_mockCommMgr;

private slots:
    void initTestCase()
    {
        if (!QCoreApplication::instance()) {
            int argc = 0;
            char* argv[] = {nullptr};
            new QCoreApplication(argc, argv);
        }
    }
    
    void init()
    {
        s_receivedSignalTypes.clear();
        
        SignalManager::instance()->setCallback(signalCallback);
        
        m_mockCommMgr = std::make_shared<StatusKeycardTest::MockCommunicationManager>();
        bool success = FlowManager::instance()->init(m_mockCommMgr);
        QVERIFY(success);
        
        QObject::connect(FlowManager::instance(), &FlowManager::flowSignal,
                        SignalManager::instance(), [](const QString& type, const QJsonObject& event) {
            QJsonObject signal;
            signal["type"] = type;
            for (auto it = event.begin(); it != event.end(); ++it) {
                signal[it.key()] = it.value();
            }
            QString jsonString = QString::fromUtf8(QJsonDocument(signal).toJson(QJsonDocument::Compact));
            SignalManager::instance()->emitSignal(jsonString);
        });
        
    }
    
    void cleanup()
    {
        FlowManager::instance()->cancelFlow();
        QTest::qWait(100);
        
        FlowManager::destroyInstance();
        m_mockCommMgr.reset();
        
        SignalManager::instance()->setCallback(nullptr);
        s_receivedSignalTypes.clear();
    }
    
    void testFlowSignalsReachCallback()
    {
        // Login with no PIN deterministically triggers ENTER_PIN pause signal.
        QJsonObject params;
        bool success = FlowManager::instance()->startFlow(static_cast<int>(FlowType::Login), params);
        QVERIFY(success);
        
        for (int i = 0; i < 50; ++i) {
            QCoreApplication::processEvents();
            QTest::qWait(10);
            if (!s_receivedSignalTypes.isEmpty()) {
                break;
            }
        }
        
        QVERIFY2(!s_receivedSignalTypes.isEmpty(), 
                 "Expected to receive flow signals via callback");
        
        FlowManager::instance()->cancelFlow();
        QTest::qWait(100);
    }
    
    void testSignalRoutingWithoutCallback()
    {
        SignalManager::instance()->setCallback(nullptr);
        s_receivedSignalTypes.clear();
        
        QJsonObject params;
        bool success = FlowManager::instance()->startFlow(static_cast<int>(FlowType::Login), params);
        QVERIFY(success);
        
        for (int i = 0; i < 20; ++i) {
            QCoreApplication::processEvents();
            QTest::qWait(10);
        }
        
        QVERIFY(s_receivedSignalTypes.isEmpty());
        
        FlowManager::instance()->cancelFlow();
        QTest::qWait(100);
        
        SignalManager::instance()->setCallback(signalCallback);
    }
};

QList<QString> TestFlowSignalRouting::s_receivedSignalTypes;

QTEST_MAIN(TestFlowSignalRouting)
#include "test_flow_signal_routing.moc"
