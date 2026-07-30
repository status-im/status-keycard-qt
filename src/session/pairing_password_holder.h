#pragma once

#include <QMutex>
#include <QString>
#include <memory>
#include <utility>

namespace StatusKeycard {

/**
 * @brief Holds the pairing password to use for the current operation
 *
 * Pairing happens implicitly, deep inside the card initialization sequence
 * (CommunicationManager::initializeCardSequence -> CommandSet::ensurePairing), which asks a
 * PairingPasswordProvider callback for the password. That callback is fixed at CommandSet
 * construction time, so this holder is the seam that lets a caller supply a per-operation
 * password without rebuilding the CommandSet.
 *
 * Cards provisioned outside the app (e.g. on the Keycard shell) may carry a custom pairing
 * password. Callers set it here for the duration of one composite operation; when unset, the
 * default password is used, which is the only password cards provisioned by the app ever have.
 *
 * Thread safety: the provider callback runs on the card detection/command thread while the RPC
 * thread is blocked inside the composite operation, so every access is mutex-guarded.
 */
class PairingPasswordHolder {
public:
    /// The pairing password every card provisioned by the app is initialized with.
    static const QString DefaultPairingPassword;

    /// Password for the current operation, or the default when none was set.
    QString getOrDefault() const;

    /// An empty password means "use the default".
    void set(const QString& pairingPassword);
    void clear();

private:
    mutable QMutex m_mutex;
    QString m_pairingPassword;
};

/**
 * @brief Sets a pairing password for the current scope and clears it on the way out
 *
 * Composite operations are self-contained: the password arrives as an RPC parameter, is used by
 * whatever pairing the operation triggers, and must not leak into the next operation.
 */
class ScopedPairingPassword {
public:
    ScopedPairingPassword(std::shared_ptr<PairingPasswordHolder> holder, const QString& pairingPassword)
        : m_holder(std::move(holder))
    {
        if (m_holder) {
            m_holder->set(pairingPassword);
        }
    }

    ~ScopedPairingPassword()
    {
        if (m_holder) {
            m_holder->clear();
        }
    }

    ScopedPairingPassword(const ScopedPairingPassword&) = delete;
    ScopedPairingPassword& operator=(const ScopedPairingPassword&) = delete;

private:
    std::shared_ptr<PairingPasswordHolder> m_holder;
};

} // namespace StatusKeycard
