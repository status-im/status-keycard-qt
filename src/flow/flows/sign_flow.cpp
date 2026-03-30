#include "sign_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include "../../utils/crypto_utils.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/communication_manager.h>
#include <keycard-qt/card_command.h>
#include <QDebug>

namespace StatusKeycard {

SignFlow::SignFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::Sign, params, parent)
{
}

SignFlow::~SignFlow()
{
}

QJsonObject SignFlow::execute()
{
    qDebug() << "StatusKeycardQt::SignFlow: Starting";

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

    // Get tx hash
    QString txHash = params()[FlowParams::TX_HASH].toString();
    if (txHash.isEmpty()) {
        // Request transaction hash (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_TX_HASH, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        txHash = params()[FlowParams::TX_HASH].toString();
    }

    // Get path
    QString path = params()[FlowParams::BIP44_PATH].toString();
    if (path.isEmpty()) {
        // Request BIP44 path (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_PATH, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        path = params()[FlowParams::BIP44_PATH].toString();
    }

    // Sign with the specified path - use the full response version to get TLV data
    QByteArray hashBytes = QByteArray::fromHex(txHash.toLatin1());

    // Phase 6: CommunicationManager is always available
    auto commMgr = communicationManager();
    if (!commMgr) {
        qCritical() << "SignFlow: CommunicationManager not available";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "sign-failed";
        return error;
    }

    auto cmd = std::make_unique<Keycard::SignCommand>(hashBytes, path, false);
    Keycard::CommandResult cmdResult = commMgr->executeCommandSync(std::move(cmd));

    if (!cmdResult.success) {
        qCritical() << "SignFlow: Sign failed:" << cmdResult.error;
        emitCancelledIfNeeded(cmdResult);
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "sign-failed";
        return error;
    }

    // Extract TLV response from cmdResult
    QVariantMap data = cmdResult.data.toMap();
    QByteArray tlvResponse = data["tlvResponse"].toByteArray();

    qDebug() << "StatusKeycardQt::SignFlow: Sign SUCCESS, response size:" << tlvResponse.size();

    if (tlvResponse.isEmpty()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "sign-failed";
        return error;
    }

    // Extract signature and public key from TLV response
    // The response format (like Go's status-keycard-go):
    // - Template tag 0xA0 or 0xA1 contains:
    //   - Tag 0x80 (65 bytes): Public key
    //   - Tag 0x30 (variable): DER signature
    //
    // Strategy: Find template tag first, then scan inside it

    QByteArray publicKey;
    QByteArray derSignature;
    QByteArray scanData = tlvResponse;

    // First, check if response starts with template tag 0xA0 or 0xA1
        qDebug() << "StatusKeycardQt::SignFlow: tlvResponse size:" << tlvResponse.size() << "first byte:" << QString("0x%1").arg((uint8_t)tlvResponse[0], 2, 16, QChar('0'));
    if (tlvResponse.size() > 2) {
        uint8_t firstTag = static_cast<uint8_t>(tlvResponse[0]);
        qDebug() << "StatusKeycardQt::SignFlow: firstTag:" << QString("0x%1").arg(firstTag, 2, 16, QChar('0'));
        if (firstTag == 0xa0 || firstTag == 0xa1) {
            // Parse the template length and extract the inner data
            int idx = 1;
            uint8_t lenByte = static_cast<uint8_t>(tlvResponse[idx++]);
            int templateLen = 0;
            qDebug() << "StatusKeycardQt::SignFlow: Template lenByte:" << QString("0x%1").arg(lenByte, 2, 16, QChar('0'));

            if (lenByte & 0x80) {
                // Multi-byte length
                int numLenBytes = lenByte & 0x7F;
                qDebug() << "StatusKeycardQt::SignFlow: Multi-byte length, numLenBytes:" << numLenBytes << "idx:" << idx << "tlvResponse.size:" << tlvResponse.size();
                if (numLenBytes <= 3 && idx + numLenBytes <= tlvResponse.size()) {
                    for (int i = 0; i < numLenBytes; i++) {
                        templateLen = (templateLen << 8) | static_cast<uint8_t>(tlvResponse[idx++]);
                    }
                    qDebug() << "StatusKeycardQt::SignFlow: Found template tag, length:" << templateLen << "extracting from idx:" << idx;
                    // Scan inside the template data
                    scanData = tlvResponse.mid(idx, templateLen);
                    qDebug() << "StatusKeycardQt::SignFlow: scanData size:" << scanData.size() << "first byte:" << QString("0x%1").arg((uint8_t)scanData[0], 2, 16, QChar('0'));
                } else {
                    qWarning() << "SignFlow: Template extraction failed - numLenBytes:" << numLenBytes << "check failed";
                }
            } else {
                // Single-byte length
                templateLen = lenByte;
                qDebug() << "StatusKeycardQt::SignFlow: Found template tag, single-byte length:" << templateLen;
                scanData = tlvResponse.mid(idx, templateLen);
            }
        } else {
            qDebug() << "StatusKeycardQt::SignFlow: No template tag found, scanning raw response";
        }
    }

    // Now scan the data (either template contents or raw response) for public key and DER signature
    bool foundPubKey = false;
    bool foundDERSig = false;

    int idx = 0;
    while (idx < scanData.size() - 1 && !(foundPubKey && foundDERSig)) {
        uint8_t tag = static_cast<uint8_t>(scanData[idx++]);

        // Parse length (for ALL tags, even ones we don't care about)
        int length = 0;
        if (idx >= scanData.size()) break;
        uint8_t lenByte = static_cast<uint8_t>(scanData[idx++]);
        if (lenByte & 0x80) {
            int numLenBytes = lenByte & 0x7F;
            if (numLenBytes > 3 || idx + numLenBytes > scanData.size()) {
                qWarning() << "SignFlow: Invalid length encoding at idx" << (idx-1) << "numLenBytes:" << numLenBytes;
                break;
            }
            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | static_cast<uint8_t>(scanData[idx++]);
            }
        } else {
            length = lenByte;
        }

        // Validate length
        if (length < 0 || idx + length > scanData.size()) {
            qWarning() << "SignFlow: TLV length" << length << "exceeds data at idx" << idx;
            break;
        }

        // Process tags we care about (like Go's FindTag matching logic)
        if (tag == 0x80 && length == 65) {
            if (!foundPubKey) {
                publicKey = scanData.mid(idx, 65);
                foundPubKey = true;
                qDebug() << "StatusKeycardQt::SignFlow: Found public key at idx" << idx;
            }
        } else if (tag == 0x30) {
            // DER signature - include tag and length bytes
            int derStart = idx - 2;
            derSignature = scanData.mid(derStart, length + 2);
            foundDERSig = true;
            qDebug() << "StatusKeycardQt::SignFlow: Found DER signature at idx" << derStart << ", length:" << length;
        } else {
            // Unknown tag (including 0x00 null tags) - just log and skip
            qDebug() << "StatusKeycardQt::SignFlow: Skipping tag" << QString("0x%1").arg(tag, 2, 16, QChar('0')) << "length" << length << "at idx" << (idx-2);
        }

        // ALWAYS advance by the data length (critical for proper parsing!)
        idx += length;
    }

    if (!foundDERSig) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-signature-not-found";
        return error;
    }

    // Parse DER signature to extract R and S
    // DER format: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    // Like Go's DERSignatureToRS, find the first and second 0x02 tags
    QByteArray r, s;

    int dIdx = 0;
    if (derSignature.size() < 6 || derSignature[dIdx++] != 0x30) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "invalid-der-format";
        return error;
    }

    // Skip DER sequence length byte
    dIdx++;

    // Find first INTEGER (tag 0x02) for R
    if (dIdx >= derSignature.size() || derSignature[dIdx++] != 0x02) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-r-tag-not-found";
        return error;
    }

    int rLen = static_cast<uint8_t>(derSignature[dIdx++]);
    if (dIdx + rLen > derSignature.size()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-r-length-invalid";
        return error;
    }

    QByteArray rValue = derSignature.mid(dIdx, rLen);
    dIdx += rLen;

    // DER pads with 0x00 if MSB is set - strip it to get 32 bytes
    if (rValue.size() > 32) {
        rValue = rValue.right(32);
    }
    // Pad if needed
    while (rValue.size() < 32) {
        rValue.prepend('\0');
    }
    r = rValue;

    // Find second INTEGER (tag 0x02) for S
    if (dIdx >= derSignature.size() || derSignature[dIdx++] != 0x02) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-s-tag-not-found";
        return error;
    }

    int sLen = static_cast<uint8_t>(derSignature[dIdx++]);
    if (dIdx + sLen > derSignature.size()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-s-length-invalid";
        return error;
    }

    QByteArray sValue = derSignature.mid(dIdx, sLen);

    // DER pads with 0x00 if MSB is set - strip it to get 32 bytes
    if (sValue.size() > 32) {
        sValue = sValue.right(32);
    }
    // Pad if needed
    while (sValue.size() < 32) {
        sValue.prepend('\0');
    }
    s = sValue;

    // Calculate V using ECDSA recovery (like Go's calculateV)
    // Try recovery IDs 0-3 and pick the one that recovers to the correct public key
    uint8_t v = 27; // Default

    if (publicKey.isEmpty()) {
        qWarning() << "SignFlow: No public key found, defaulting V=27";
    } else {
        int recoveryId = CryptoUtils::calculateRecoveryId(hashBytes, r, s, publicKey);
        if (recoveryId == -1) {
            qWarning() << "SignFlow: ECDSA recovery failed, defaulting V=27";
        } else {
            v = static_cast<uint8_t>(recoveryId + 27);
            qDebug() << "StatusKeycardQt::SignFlow: Calculated V=" << v << "(recovery ID" << recoveryId << ")";
        }
    }

    // Build signature object with r, s, v components
    QJsonObject sigObj;
    sigObj["r"] = QString::fromLatin1(r.toHex());
    sigObj["s"] = QString::fromLatin1(s.toHex());
    sigObj["v"] = static_cast<int>(v);

    QJsonObject result = buildCardInfoJson();
    result[FlowParams::TX_SIGNATURE] = sigObj;

    qDebug() << "StatusKeycardQt::SignFlow: Complete";
    return result;
}

} // namespace StatusKeycard

