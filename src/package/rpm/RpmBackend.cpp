#include "RpmBackend.h"

RpmBackend::RpmBackend() = default;

QString RpmBackend::name() const
{
    return QStringLiteral("RPM");
}

bool RpmBackend::isAvailable() const
{
    return m_detector.isAvailable();
}

IApplicationDetector *RpmBackend::detector()
{
    return &m_detector;
}

IApplicationRemover *RpmBackend::remover()
{
    return &m_remover;
}
