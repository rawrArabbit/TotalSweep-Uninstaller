#pragma once

#include "IApplicationBackend.h"

#include <QList>

class ApplicationBackendManager
{
public:
    ApplicationBackendManager() = default;
    ~ApplicationBackendManager();

    void registerBackend(IApplicationBackend *backend);

    QList<IApplicationBackend *> backends() const;

    QList<ApplicationInfo> detectAllApplications() const;

    QList<ApplicationInfo> searchAllApplications(
        const QString &query) const;

    IApplicationBackend *backendFor(
        const ApplicationInfo &application) const;

private:
    QList<IApplicationBackend *> m_backends;
};
