#include "pairing_password_holder.h"

#include <QMutexLocker>

namespace StatusKeycard {

const QString PairingPasswordHolder::DefaultPairingPassword = QStringLiteral("KeycardDefaultPairing");

QString PairingPasswordHolder::getOrDefault() const
{
    QMutexLocker locker(&m_mutex);
    return m_pairingPassword.isEmpty() ? DefaultPairingPassword : m_pairingPassword;
}

void PairingPasswordHolder::set(const QString& pairingPassword)
{
    QMutexLocker locker(&m_mutex);
    m_pairingPassword = pairingPassword;
}

void PairingPasswordHolder::clear()
{
    QMutexLocker locker(&m_mutex);
    m_pairingPassword.clear();
}

} // namespace StatusKeycard
