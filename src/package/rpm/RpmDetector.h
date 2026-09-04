#pragma once

#include "../../core/IApplicationDetector.h"

class RpmDetector final : public IApplicationDetector
{
public:
    QString name() const override;

    bool isAvailable() const override;

    QList<ApplicationInfo> detectApplications() const override;

    QList<ApplicationInfo> searchApplications(
        const QString &query) const override;

private:
    QList<ApplicationInfo> parsePackageList(
        const QStringList &lines) const;

    QStringList runRpm(
        const QStringList &arguments) const;

    ApplicationInfo inspectPackage(
        const QString &packageId) const;
};
