#pragma once

#include "ApplicationInfo.h"

#include <QStringList>

struct LeftoverItem {
    QString path;
    QString category;
    QString reason;

    int risk = 0;

    bool selectedByDefault = false;
    bool protectedItem = false;
};

class ILeftoverScanner
{
public:
    virtual ~ILeftoverScanner() = default;

    virtual QString name() const = 0;

    virtual QStringList scanRoots() const = 0;

    virtual QList<LeftoverItem> scan(
        const ApplicationInfo &application) const = 0;
};
