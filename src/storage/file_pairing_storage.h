#pragma once

#include <keycard-qt/pairing_storage.h>
#include <QString>
#include <QJsonObject>

namespace StatusKeycard {

/**
 * @brief File-based pairing storage implementation
 * 
 * Stores all pairing information in a single JSON file.
 * Format: {"cardUID": {"key": "hex...", "index": 0}, ...}
 */
class FilePairingStorage : public Keycard::IPairingStorage {
public:
    explicit FilePairingStorage();
    ~FilePairingStorage() override = default;
    
    // IPairingStorage interface
    Keycard::PairingInfo load(const QString& cardInstanceUID) override;
    bool save(const QString& cardInstanceUID, const Keycard::PairingInfo& pairing) override;
    bool remove(const QString& cardInstanceUID) override;
    bool setPath(const QString& filePath);

    
private:
    QString m_filePath;

    // Helper methods
    bool ensureStorageExists();
    QJsonObject loadAllPairings();
    bool saveAllPairings(const QJsonObject& pairings);
};

} // namespace StatusKeycard

