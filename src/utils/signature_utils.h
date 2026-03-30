#pragma once

#include <QByteArray>

namespace StatusKeycard::SignatureUtils {

bool parseDERSignature(const QByteArray& der, QByteArray& outR, QByteArray& outS);

QByteArray extractTemplateContent(const QByteArray& data);

QByteArray findDERSignature(const QByteArray& data);

} // namespace StatusKeycard::SignatureUtils
