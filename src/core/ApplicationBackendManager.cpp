#include "ApplicationBackendManager.h"

ApplicationBackendManager::~ApplicationBackendManager()
{
    qDeleteAll(m_backends);
    m_backends.clear();
}

void ApplicationBackendManager::registerBackend(
    IApplicationBackend *backend)
{
    if (!backend)
        return;

    if (m_backends.contains(backend))
        return;

    m_backends.append(backend);
}

QList<IApplicationBackend *>
ApplicationBackendManager::backends() const
{
    return m_backends;
}

QList<ApplicationInfo>
ApplicationBackendManager::detectAllApplications() const
{
    QList<ApplicationInfo> applications;

    for (IApplicationBackend *backend : m_backends) {
        if (!backend)
            continue;

        if (!backend->isAvailable())
            continue;

        IApplicationDetector *detector = backend->detector();

        if (!detector)
            continue;

        applications.append(detector->detectApplications());
    }

    return applications;
}

QList<ApplicationInfo>
ApplicationBackendManager::searchAllApplications(
    const QString &query) const
{
    QList<ApplicationInfo> applications;

    for (IApplicationBackend *backend : m_backends) {
        if (!backend)
            continue;

        if (!backend->isAvailable())
            continue;

        IApplicationDetector *detector = backend->detector();

        if (!detector)
            continue;

        applications.append(
            detector->searchApplications(query)
        );
    }

    return applications;
}

IApplicationBackend *
ApplicationBackendManager::backendFor(
    const ApplicationInfo &application) const
{
    for (IApplicationBackend *backend : m_backends) {
        if (!backend)
            continue;

        if (!backend->isAvailable())
            continue;

        if (backend->remover() &&
            backend->remover()->supports(application)) {
            return backend;
        }
    }

    return nullptr;
}
