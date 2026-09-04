#pragma once

#include "ApplicationBackendManager.h"

#include <QList>
#include <QString>

class ApplicationLibrary
{
public:
    explicit ApplicationLibrary(
        ApplicationBackendManager *backendManager);

    void refresh();

    QList<ApplicationInfo> applications() const;

    QList<ApplicationInfo> search(
        const QString &query) const;

    int count() const;

private:
    ApplicationBackendManager *m_backendManager = nullptr;

    QList<ApplicationInfo> m_applications;

    void normalize();
    void removeDuplicates();
};
