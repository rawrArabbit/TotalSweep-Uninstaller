#include "FlatpakBackend.h"

FlatpakBackend::FlatpakBackend() = default;

QString FlatpakBackend::name() const
{
    return QStringLiteral("Flatpak");
}

bool FlatpakBackend::isAvailable() const
{
    return m_detector.isAvailable();
}

IApplicationDetector *FlatpakBackend::detector()
{
    return &m_detector;
}

IApplicationRemover *FlatpakBackend::remover()
{
    return &m_remover;
}
