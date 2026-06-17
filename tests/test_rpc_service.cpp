#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include "rpc/rpc_service.h"
#include "mocks/mock_communication_manager.h"

using namespace StatusKeycard;

class TestRpcService : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // JSON-RPC protocol tests
    void testParseError();
    void testMethodNotFound();
    void testInvalidRequest();
    void testSuccessResponse();

    // Lifecycle method tests
    void testStopMethod();

    // Composite method tests
    void testLoginMethod();

private:
    RpcService* m_service;
    std::shared_ptr<StatusKeycardTest::MockCommunicationManager> m_mockCommMgr;
    QString sendRequest(const QString& method, const QJsonObject& params = QJsonObject());
    QJsonObject parseResponse(const QString& response);
};

void TestRpcService::initTestCase()
{
    // Nothing needed
}

void TestRpcService::cleanupTestCase()
{
    // Nothing needed
}

void TestRpcService::init()
{
    m_service = new RpcService();
    m_mockCommMgr = std::make_shared<StatusKeycardTest::MockCommunicationManager>();
    m_service->setCommunicationManager(m_mockCommMgr);
}

void TestRpcService::cleanup()
{
    delete m_service;
    m_service = nullptr;
    m_mockCommMgr.reset();
}

QString TestRpcService::sendRequest(const QString& method, const QJsonObject& params)
{
    QJsonObject request;
    request["jsonrpc"] = "2.0";
    request["id"] = 1234567890;
    request["method"] = method;

    if (!params.isEmpty()) {
        QJsonArray paramsArray;
        paramsArray.append(params);
        request["params"] = paramsArray;
    } else {
        request["params"] = QJsonArray();
    }

    QJsonDocument doc(request);
    QString requestStr = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));

    return m_service->processRequest(requestStr);
}

QJsonObject TestRpcService::parseResponse(const QString& response)
{
    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
    return doc.object();
}

void TestRpcService::testParseError()
{
    QString invalidJson = "{ invalid json }";
    QString response = m_service->processRequest(invalidJson);

    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32700);
}

void TestRpcService::testMethodNotFound()
{
    QString response = sendRequest("keycard.NonExistentMethod");

    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32601);
}

void TestRpcService::testInvalidRequest()
{
    QString response = m_service->processRequest("{}");

    QJsonObject resp = parseResponse(response);
    // Should handle gracefully (method not found)
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testSuccessResponse()
{
    QString response = sendRequest("keycard.Stop");

    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("result"));
    QVERIFY(!resp.contains("error") || resp["error"].isNull());
    QCOMPARE(resp["jsonrpc"].toString(), QString("2.0"));
    QCOMPARE(resp["id"].toInt(), 1234567890);
}

void TestRpcService::testStopMethod()
{
    QString response = sendRequest("keycard.Stop");
    QJsonObject resp = parseResponse(response);

    QVERIFY(resp.contains("result"));
    QVERIFY(resp["result"].toObject().isEmpty());
}

void TestRpcService::testLoginMethod()
{
    // Test missing storageFilePath
    QJsonObject params;

    QString response = sendRequest("keycard.Login", params);
    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32602);
    QVERIFY(resp["error"].toObject()["message"].toString().contains("storageFilePath"));

    params["storageFilePath"] = "/tmp/test_login_pairings.json";

    // Test invalid keyUid (too short)
    params["keyUid"] = "1234567890abcdef1234567890abcdef1234567890abcdef";
    response = sendRequest("keycard.Login", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32602);
    QVERIFY(resp["error"].toObject()["message"].toString().contains("keyUid"));

    params["keyUid"] = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    // Test invalid PIN (too short)
    params["pin"] = "12345";

    response = sendRequest("keycard.Login", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32602);
    QVERIFY(resp["error"].toObject()["message"].toString().contains("PIN"));

    params["pin"] = "123456";

    // Test missing CommunicationManager
    response = sendRequest("keycard.Login", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32000);
}

QTEST_MAIN(TestRpcService)
#include "test_rpc_service.moc"

