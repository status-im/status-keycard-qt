#include "export_public_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <keycard-qt/tlv_utils.h>
#include <QJsonArray>
#include <QCryptographicHash>

namespace StatusKeycard {

ExportPublicFlow::ExportPublicFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ExportPublic, params, parent) {}

QJsonObject ExportPublicFlow::execute()
{
    if (!requirePIN() || !selectKeycard() || !requireKeys()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "ExportPublicFlow: CommunicationManager not available";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-failed";
        return error;
    }

    // Go compatibility:
    // - export-private defaults to false (public-only export)
    // - export-master-address triggers an extra master public export
    const bool exportPrivate = params().value(FlowParams::EXPORT_PRIV).toBool(false);
    const bool exportMasterAddr = params().value(FlowParams::EXPORT_MASTER).toBool(false);

    QJsonObject result = buildCardInfoJson();
    if (exportMasterAddr) {
        auto masterCmd = std::make_unique<Keycard::ExportKeyCommand>(
            true, true, "m", Keycard::APDU::P2ExportKeyPublicOnly);
        Keycard::CommandResult masterResult = commMgr->executeCommandSync(std::move(masterCmd));

        if (!masterResult.success) {
            qCritical() << "ExportPublicFlow: Master export failed:" << masterResult.error;
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "export-failed";
            return error;
        }

        QByteArray masterKeyData = masterResult.data.toMap()["keyData"].toByteArray();
        QByteArray masterPublicKey, masterPrivateKey;
        if (!parseExportedKey(masterKeyData, masterPublicKey, masterPrivateKey)) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "parse-key-failed";
            return error;
        }

        result[FlowParams::MASTER_ADDR] = FlowBase::publicKeyToAddress(masterPublicKey);
    }

    // Match Go exportBIP44Key behavior:
    // - missing path => pause and wait
    // - string => export single key (even empty string)
    // - array => export each path and return array (including empty array)
    // - invalid type => ask for path again
    QStringList paths;
    bool inputWasArray = false;
    while (true) {
        QJsonObject currentParams = params();
        if (!currentParams.contains(FlowParams::BIP44_PATH)) {
            pauseAndWait(FlowSignals::ENTER_PATH, "exporting");
            if (isCancelled()) {
                QJsonObject error;
                error[FlowParams::ERROR_KEY] = "cancelled";
                return error;
            }
            continue;
        }

        QJsonValue pathValue = currentParams.value(FlowParams::BIP44_PATH);
        if (pathValue.isString()) {
            inputWasArray = false;
            paths.clear();
            paths.append(pathValue.toString());
            break;
        }

        if (pathValue.isArray()) {
            inputWasArray = true;
            paths.clear();
            const QJsonArray pathArray = pathValue.toArray();
            for (const QJsonValue& val : pathArray) {
                paths.append(val.toString());
            }
            break;
        }

        pauseAndWait(FlowSignals::ENTER_PATH, "exporting");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
    }

    QJsonArray exportedKeys;
    const uint8_t exportType = exportPrivate
        ? Keycard::APDU::P2ExportKeyPrivateAndPublic
        : Keycard::APDU::P2ExportKeyPublicOnly;

    for (const QString& path : paths) {
        auto cmd = std::make_unique<Keycard::ExportKeyCommand>(true, false, path, exportType);
        Keycard::CommandResult result = commMgr->executeCommandSync(std::move(cmd));

        if (!result.success) {
            qCritical() << "ExportPublicFlow: Export failed for path" << path << ":" << result.error;
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "export-failed";
            return error;
        }

        QByteArray keyData = result.data.toMap()["keyData"].toByteArray();

        if (keyData.isEmpty()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "export-failed";
            return error;
        }

        QByteArray publicKey, privateKey;
        if (!parseExportedKey(keyData, publicKey, privateKey)) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "parse-key-failed";
            return error;
        }

        const QByteArray keyTemplate = Keycard::TLV::findTag(keyData, 0xA1);
        const QByteArray chainCode = Keycard::TLV::findTag(keyTemplate, 0x82);

        QJsonObject keyPair;
        keyPair["publicKey"] = QString("0x") + publicKey.toHex();
        keyPair["address"] = FlowBase::publicKeyToAddress(publicKey);

        if (exportPrivate && !privateKey.isEmpty()) {
            keyPair["privateKey"] = QString("0x") + privateKey.toHex();
        }

        if (!chainCode.isEmpty()) {
            keyPair["chainCode"] = QString("0x") + chainCode.toHex();
        }

        exportedKeys.append(keyPair);
    }

    // Return format matches Go exportBIP44Key:
    // string path => object, array path => array.
    if (inputWasArray) {
        result[FlowParams::EXPORTED_KEY] = exportedKeys;
    } else {
        result[FlowParams::EXPORTED_KEY] = exportedKeys.isEmpty() ? QJsonValue(QJsonObject()) : exportedKeys[0];
    }

    return result;
}

} // namespace StatusKeycard

