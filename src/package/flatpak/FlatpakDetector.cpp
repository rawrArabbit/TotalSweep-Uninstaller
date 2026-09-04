#include "FlatpakDetector.h"

#include <QDateTime>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>

namespace
{

QString humanSize(
    quint64 bytes)
{
    static const char *units[] = {
        "B",
        "KiB",
        "MiB",
        "GiB",
        "TiB"
    };

    double value =
        static_cast<double>(bytes);

    int unit = 0;

    while (value >= 1024.0 &&
           unit < 4) {

        value /= 1024.0;
        ++unit;
    }

    if (unit == 0) {

        return QString(
            "%1 %2")
            .arg(bytes)
            .arg(units[unit]);
    }

    return QString(
        "%1 %2")
        .arg(
            value,
            0,
            'f',
            value >= 10.0
                ? 1
                : 2)
        .arg(units[unit]);
}

} // namespace


QString FlatpakDetector::name() const
{
    return QStringLiteral("Flatpak");
}


bool FlatpakDetector::isAvailable() const
{
    return !QStandardPaths::findExecutable(
        QStringLiteral("flatpak")).isEmpty();
}


QStringList FlatpakDetector::runFlatpak(
    const QStringList &arguments) const
{
    QProcess process;

    process.start(
        QStringLiteral("flatpak"),
        arguments);

    if (!process.waitForStarted(5000))
        return {};

    if (!process.waitForFinished(30000)) {

        process.kill();
        process.waitForFinished(1000);

        return {};
    }

    if (process.exitStatus() !=
        QProcess::NormalExit) {

        return {};
    }

    if (process.exitCode() != 0)
        return {};

    return QString::fromLocal8Bit(
        process.readAllStandardOutput())
        .split(
            '\n',
            Qt::SkipEmptyParts);
}


ApplicationInfo
FlatpakDetector::inspectApplication(
    const QString &applicationId) const
{
    ApplicationInfo app;

    app.id =
        applicationId;

    app.type =
        ApplicationType::Flatpak;

    app.packageManager =
        QStringLiteral("Flatpak");

    app.source =
        QStringLiteral("Flatpak");

    app.installed =
        true;

    app.removable =
        true;

    app.systemComponent =
        false;

    app.userInstalled =
        true;

    app.risk =
        RiskLevel::Review;

    const QStringList metadata =
        runFlatpak(
            {
                QStringLiteral("info"),
                QStringLiteral("--show-name"),
                applicationId
            });

    if (!metadata.isEmpty())
        app.name =
            metadata.first().trimmed();

    const QStringList version =
        runFlatpak(
            {
                QStringLiteral("info"),
                QStringLiteral("--show-version"),
                applicationId
            });

    if (!version.isEmpty())
        app.version =
            version.first().trimmed();

    const QStringList description =
        runFlatpak(
            {
                QStringLiteral("info"),
                QStringLiteral("--show-description"),
                applicationId
            });

    if (!description.isEmpty())
        app.description =
            description.first().trimmed();

    const QStringList size =
        runFlatpak(
            {
                QStringLiteral("info"),
                QStringLiteral("--show-size"),
                applicationId
            });

    if (!size.isEmpty()) {

        bool ok = false;

        const quint64 bytes =
            size.first()
                .trimmed()
                .toULongLong(&ok);

        app.installedSize =
            ok
                ? humanSize(bytes)
                : size.first().trimmed();
    }

    if (app.installedSize.isEmpty())
        app.installedSize =
            QStringLiteral("Unknown");

    const QStringList location =
        runFlatpak(
            {
                QStringLiteral("info"),
                QStringLiteral("--show-location"),
                applicationId
            });

    if (!location.isEmpty()) {
        app.installLocation =
            location.first().trimmed();

        if (!app.installLocation.isEmpty())
            app.installLocations.append(
                app.installLocation);

        const QFileInfo locationInfo(
            app.installLocation);

        QDateTime installedDate =
            locationInfo.birthTime();

        if (!installedDate.isValid())
            installedDate =
                locationInfo.lastModified();

        if (installedDate.isValid()) {
            app.installDate =
                installedDate.toLocalTime()
                    .date()
                    .toString(
                        QStringLiteral(
                            "yyyy-MM-dd"));
            app.installDateEstimated =
                true;
        }
    }

    if (app.name.isEmpty())
        app.name =
            applicationId;

    return app;
}


QList<ApplicationInfo>
FlatpakDetector::parsePackageList(
    const QStringList &lines) const
{
    QList<ApplicationInfo> applications;

    for (const QString &line :
         lines) {

        const QString applicationId =
            line.trimmed();

        if (applicationId.isEmpty())
            continue;

        applications.append(
            inspectApplication(
                applicationId));
    }

    return applications;
}


QList<ApplicationInfo>
FlatpakDetector::detectApplications() const
{
    if (!isAvailable())
        return {};

    const QStringList applications =
        runFlatpak(
            {
                QStringLiteral("list"),
                QStringLiteral("--app"),
                QStringLiteral(
                    "--columns=application")
            });

    return parsePackageList(
        applications);
}


QList<ApplicationInfo>
FlatpakDetector::searchApplications(
    const QString &query) const
{
    if (!isAvailable())
        return {};

    const QString needle =
        query.trimmed();

    if (needle.isEmpty())
        return detectApplications();

    const QList<ApplicationInfo> all =
        detectApplications();

    QList<ApplicationInfo> matches;

    for (const ApplicationInfo &app :
         all) {

        if (app.name.contains(
                needle,
                Qt::CaseInsensitive) ||

            app.id.contains(
                needle,
                Qt::CaseInsensitive) ||

            app.description.contains(
                needle,
                Qt::CaseInsensitive)) {

            matches.append(app);
        }
    }

    return matches;
}
