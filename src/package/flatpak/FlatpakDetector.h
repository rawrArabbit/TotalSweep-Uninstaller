#pragma once

#include "../../core/IApplicationDetector.h"

class FlatpakDetector final : public IApplicationDetector
{
public:
    QString name() const override;

    bool isAvailable() const override;

    QList<ApplicationInfo> detectApplications() const override;

    QList<ApplicationInfo> searchApplications(
        const QString &query) const override;

private:
    QStringList runFlatpak(
        const QStringList &arguments) const;

    QList<ApplicationInfo> parsePackageList(
        const QStringList &lines) const;

    ApplicationInfo inspectApplication(
        const QString &applicationId) const;
};
