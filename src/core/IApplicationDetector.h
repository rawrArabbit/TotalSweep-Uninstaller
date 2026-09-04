#pragma once

#include "ApplicationInfo.h"

#include <QList>
#include <QString>

class IApplicationDetector
{
public:
    virtual ~IApplicationDetector() = default;

    virtual QString name() const = 0;

    virtual bool isAvailable() const = 0;

    virtual QList<ApplicationInfo> detectApplications() const = 0;

    virtual QList<ApplicationInfo> searchApplications(
        const QString &query) const = 0;
};
