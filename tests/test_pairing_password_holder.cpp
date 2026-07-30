#include <QtTest>
#include <QThread>
#include <QSemaphore>
#include <memory>

#include "session/pairing_password_holder.h"

using namespace StatusKeycard;

/**
 * @brief Tests for PairingPasswordHolder
 *
 * The holder feeds the CommandSet's pairing password provider, which is invoked from the card
 * detection/command thread while an RPC thread is inside a composite operation. Both the
 * default fallback and the cross-thread access are load-bearing.
 */
class TestPairingPasswordHolder : public QObject
{
    Q_OBJECT

private slots:
    void testDefaultsWhenUnset()
    {
        PairingPasswordHolder holder;
        QCOMPARE(holder.getOrDefault(), PairingPasswordHolder::DefaultPairingPassword);
    }

    void testEmptyPasswordMeansDefault()
    {
        // Callers pass the RPC parameter through verbatim, and an absent parameter arrives as an
        // empty string. That must select the default rather than attempt to pair with "".
        PairingPasswordHolder holder;
        holder.set(QString());
        QCOMPARE(holder.getOrDefault(), PairingPasswordHolder::DefaultPairingPassword);

        holder.set(QStringLiteral(""));
        QCOMPARE(holder.getOrDefault(), PairingPasswordHolder::DefaultPairingPassword);
    }

    void testCustomPasswordIsReturned()
    {
        PairingPasswordHolder holder;
        holder.set(QStringLiteral("MyCustomPass"));
        QCOMPARE(holder.getOrDefault(), QStringLiteral("MyCustomPass"));
    }

    void testClearRestoresDefault()
    {
        PairingPasswordHolder holder;
        holder.set(QStringLiteral("MyCustomPass"));
        holder.clear();
        QCOMPARE(holder.getOrDefault(), PairingPasswordHolder::DefaultPairingPassword);
    }

    void testScopedPairingPasswordClearsOnExit()
    {
        // A password must not outlive the operation that supplied it, otherwise the next
        // operation would silently pair with the previous card's password.
        auto holder = std::make_shared<PairingPasswordHolder>();
        {
            ScopedPairingPassword scope(holder, QStringLiteral("MyCustomPass"));
            QCOMPARE(holder->getOrDefault(), QStringLiteral("MyCustomPass"));
        }
        QCOMPARE(holder->getOrDefault(), PairingPasswordHolder::DefaultPairingPassword);
    }

    void testScopedPairingPasswordKeepsHolderAlive()
    {
        // The guard shares ownership, so it stays valid even if every other owner drops the
        // holder while an operation is still in flight.
        auto holder = std::make_shared<PairingPasswordHolder>();
        std::weak_ptr<PairingPasswordHolder> observer = holder;
        {
            ScopedPairingPassword scope(holder, QStringLiteral("MyCustomPass"));
            holder.reset();
            QVERIFY(!observer.expired());
            QCOMPARE(observer.lock()->getOrDefault(), QStringLiteral("MyCustomPass"));
        }
        QVERIFY(observer.expired());
    }

    void testScopedPairingPasswordToleratesNullHolder()
    {
        // SessionManager is constructed without a holder in tests and in any embedder that does
        // not install one, so the guard has to be a no-op rather than a crash.
        ScopedPairingPassword scope(nullptr, QStringLiteral("MyCustomPass"));
    }

    void testConcurrentAccess()
    {
        // Mirrors the real access pattern: one thread publishes the password while another reads
        // it from the pairing callback. Run under a sanitizer build to make this meaningful.
        PairingPasswordHolder holder;
        QSemaphore started;

        QThread* reader = QThread::create([&holder, &started]() {
            started.release();
            for (int i = 0; i < 10000; ++i) {
                const QString password = holder.getOrDefault();
                QVERIFY(!password.isEmpty());
            }
        });
        reader->start();
        started.acquire();

        for (int i = 0; i < 10000; ++i) {
            holder.set(QStringLiteral("pass-%1").arg(i));
            holder.clear();
        }

        QVERIFY(reader->wait(30000));
        delete reader;
    }
};

QTEST_MAIN(TestPairingPasswordHolder)
#include "test_pairing_password_holder.moc"
