#include "RpmDetector.h"

#include <algorithm>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QSettings>
#include <QStandardPaths>

namespace
{

struct RpmMetadata
{
    QString name;
    QString version;
    QString release;
    QString arch;
    QString summary;
    QString size;
    QString installDate;
    QStringList installRoots;
};

QString displayVersion(
    const RpmMetadata &metadata)
{
    QString version =
        metadata.version;

    if (!metadata.release.isEmpty()) {

        if (!version.isEmpty())
            version += QStringLiteral("-");

        version += metadata.release;
    }

    if (!metadata.arch.isEmpty()) {

        if (!version.isEmpty())
            version += QStringLiteral(".");

        version += metadata.arch;
    }

    return version;
}

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


QString representativeInstallRoot(
    QString directory)
{
    directory =
        QDir::cleanPath(
            directory.trimmed());

    if (directory.isEmpty() ||
        directory == QStringLiteral(".")) {

        return {};
    }

    if (!directory.startsWith('/'))
        return {};

    const auto starts =
        [&directory](const char *prefix) {

            return directory.startsWith(
                QString::fromLatin1(prefix));
        };

    /*
     * Preserve kernel-module version directories because they are
     * substantially more informative than a generic /usr/lib path.
     */
    if (starts("/usr/lib/modules/")) {
        const QStringList parts =
            directory.split(
                '/',
                Qt::SkipEmptyParts);

        if (parts.size() >= 4) {
            return QStringLiteral("/usr/lib/modules/") +
                parts.at(3);
        }

        return QStringLiteral("/usr/lib/modules");
    }

    const QStringList fixedRoots = {
        QStringLiteral("/usr/local/bin"),
        QStringLiteral("/usr/local/sbin"),
        QStringLiteral("/usr/local/lib64"),
        QStringLiteral("/usr/local/lib"),
        QStringLiteral("/usr/local/share"),
        QStringLiteral("/usr/bin"),
        QStringLiteral("/usr/sbin"),
        QStringLiteral("/usr/lib64"),
        QStringLiteral("/usr/lib"),
        QStringLiteral("/usr/share"),
        QStringLiteral("/usr/include"),
        QStringLiteral("/etc"),
        QStringLiteral("/var/lib"),
        QStringLiteral("/var/cache"),
        QStringLiteral("/var/log"),
        QStringLiteral("/boot"),
        QStringLiteral("/lib/firmware")
    };

    for (const QString &root : fixedRoots) {
        if (directory == root ||
            directory.startsWith(root + '/')) {

            return root;
        }
    }

    /*
     * /opt packages normally have one meaningful product directory.
     * Keep that first component: /opt/resolve, /opt/example, etc.
     */
    if (starts("/opt/")) {
        const QStringList parts =
            directory.split(
                '/',
                Qt::SkipEmptyParts);

        if (parts.size() >= 2) {
            return QStringLiteral("/opt/") +
                parts.at(1);
        }

        return QStringLiteral("/opt");
    }

    if (directory == QStringLiteral("/opt"))
        return directory;

    /*
     * For less common system roots, retaining the first two path
     * components is more useful than returning Unknown.
     */
    const QStringList parts =
        directory.split(
            '/',
            Qt::SkipEmptyParts);

    if (parts.isEmpty())
        return QStringLiteral("/");

    if (parts.size() == 1)
        return QStringLiteral("/") + parts.first();

    return QStringLiteral("/") +
        parts.at(0) +
        QStringLiteral("/") +
        parts.at(1);
}


QString summarizeInstallRoots(
    QStringList roots)
{
    roots.removeAll(QString());
    roots.removeDuplicates();

    std::sort(
        roots.begin(),
        roots.end(),
        [](const QString &left,
           const QString &right) {

            return left.compare(
                right,
                Qt::CaseInsensitive) < 0;
        });

    if (roots.isEmpty())
        return {};

    if (roots.size() == 1)
        return roots.first();

    QStringList shown =
        roots.mid(0, 3);

    QString summary =
        QStringLiteral("System-wide (") +
        shown.join(QStringLiteral(", "));

    if (roots.size() > shown.size())
        summary += QStringLiteral(", …");

    summary += QLatin1Char(')');

    return summary;
}


QString expandHomePath(
    QString path)
{
    path = path.trimmed();

    if (path.startsWith(
            QStringLiteral("~/"))) {

        path = QDir::homePath() +
            path.mid(1);
    }

    path.replace(
        QStringLiteral("${HOME}"),
        QDir::homePath());

    path.replace(
        QStringLiteral("$HOME"),
        QDir::homePath());

    return path;
}


QString appImagePathFromCommand(
    const QString &command)
{
    QString value =
        command.trimmed();

    if (value.isEmpty())
        return {};

    /*
     * Desktop launchers do not always quote AppImage paths that
     * contain spaces.  First locate each ".AppImage" suffix and
     * then walk backward to the most plausible path boundary.
     *
     * This also handles commands wrapped in env, shells, pkexec,
     * terminals, or variable assignments.
     */
    const QRegularExpression suffixExpression(
        QStringLiteral(R"TS(\.AppImage)TS"),
        QRegularExpression::CaseInsensitiveOption);

    QRegularExpressionMatchIterator it =
        suffixExpression.globalMatch(value);

    QStringList candidates;

    while (it.hasNext()) {

        const QRegularExpressionMatch match =
            it.next();

        const int suffixEnd =
            match.capturedEnd();

        if (suffixEnd <= 0)
            continue;

        int start = -1;

        /*
         * Prefer explicit home-variable path starts.
         */
        const QStringList homePrefixes = {
            QStringLiteral("${HOME}/"),
            QStringLiteral("$HOME/"),
            QStringLiteral("~/")
        };

        for (const QString &prefix :
             homePrefixes) {

            const int pos =
                value.lastIndexOf(
                    prefix,
                    suffixEnd - 1,
                    Qt::CaseInsensitive);

            if (pos > start)
                start = pos;
        }

        /*
         * Find an absolute-path slash preceded by a command/path
         * boundary. Keep the last such slash before ".AppImage"
         * so wrappers like "/usr/bin/env /home/...AppImage" do
         * not become part of the candidate.
         */
        for (int pos = value.lastIndexOf(
                 '/',
                 suffixEnd - 1);
             pos >= 0;
             pos = value.lastIndexOf(
                 '/',
                 pos - 1)) {

            if (pos == 0) {
                if (start < 0)
                    start = pos;
                break;
            }

            const QChar previous =
                value.at(pos - 1);

            if (previous.isSpace() ||
                previous == '"' ||
                previous == '\'' ||
                previous == '=' ||
                previous == '(' ||
                previous == '[' ||
                previous == '{') {

                if (pos > start)
                    start = pos;

                break;
            }
        }

        if (start < 0)
            continue;

        QString candidate =
            value.mid(
                start,
                suffixEnd - start)
                .trimmed();

        /*
         * If a wrapper executable was accidentally included,
         * keep only the last absolute/home path segment.
         */
        const QStringList separators = {
            QStringLiteral(" /"),
            QStringLiteral("\t/"),
            QStringLiteral(" ~/"),
            QStringLiteral(" $HOME/"),
            QStringLiteral(" ${HOME}/")
        };

        int laterStart = -1;

        for (const QString &separator :
             separators) {

            const int pos =
                candidate.lastIndexOf(
                    separator,
                    -1,
                    Qt::CaseInsensitive);

            if (pos >= 0) {

                const int adjusted =
                    pos + 1;

                if (adjusted > laterStart)
                    laterStart = adjusted;
            }
        }

        if (laterStart > 0)
            candidate =
                candidate.mid(laterStart);

        candidate.replace(
            QStringLiteral("\\ "),
            QStringLiteral(" "));

        if (candidate.startsWith(
                QStringLiteral("file://"),
                Qt::CaseInsensitive)) {

            candidate =
                candidate.mid(
                    QStringLiteral("file://").size());
        }

        candidate =
            expandHomePath(candidate);

        candidate =
            QDir::cleanPath(candidate);

        if (QFileInfo(candidate).isAbsolute())
            candidates.append(candidate);
    }

    if (candidates.isEmpty())
        return {};

    /*
     * Prefer a candidate that exists right now.
     */
    for (auto itCandidate =
             candidates.crbegin();
         itCandidate != candidates.crend();
         ++itCandidate) {

        if (QFileInfo::exists(
                *itCandidate)) {

            return *itCandidate;
        }
    }

    /*
     * The launcher can still be valid even if the file is on a
     * temporarily unavailable/moved mount. Return the best path
     * so TotalSweep can resolve it again at removal time.
     */
    return candidates.last();
}


QString executableFromDesktopExec(
    const QString &exec)
{
    QString value =
        exec.trimmed();

    if (value.isEmpty())
        return {};

    /*
     * AppImage launchers are frequently wrapped in env, bash -c,
     * sh -c, pkexec, or a terminal command. Find the AppImage path
     * first so those wrappers do not hide the real install target.
     */
    const QString appImage =
        appImagePathFromCommand(value);

    if (!appImage.isEmpty())
        return appImage;

    QStringList tokens =
        QProcess::splitCommand(value);

    if (tokens.isEmpty())
        return {};

    /*
     * Remove desktop-entry field codes such as %U, %F and %u.
     */
    tokens.erase(
        std::remove_if(
            tokens.begin(),
            tokens.end(),
            [](const QString &token) {
                return token.startsWith('%');
            }),
        tokens.end());

    if (tokens.isEmpty())
        return {};

    QString first =
        expandHomePath(tokens.first());

    const QString baseName =
        QFileInfo(first).fileName();

    /* env VAR=value command ... */
    if (baseName == QStringLiteral("env")) {

        int index = 1;

        while (index < tokens.size()) {
            const QString token =
                tokens.at(index);

            if (token.startsWith('-') ||
                (token.contains('=') &&
                 !token.startsWith('/'))) {

                ++index;
                continue;
            }

            return executableFromDesktopExec(
                tokens.mid(index).join(' '));
        }

        return {};
    }

    /* shell -c 'real command' */
    const QSet<QString> shells = {
        QStringLiteral("sh"),
        QStringLiteral("bash"),
        QStringLiteral("dash"),
        QStringLiteral("zsh"),
        QStringLiteral("fish")
    };

    if (shells.contains(baseName)) {

        const int commandIndex =
            tokens.indexOf(
                QStringLiteral("-c"));

        if (commandIndex >= 0 &&
            commandIndex + 1 < tokens.size()) {

            return executableFromDesktopExec(
                tokens.at(commandIndex + 1));
        }
    }

    /* privilege wrappers */
    if (baseName == QStringLiteral("pkexec") ||
        baseName == QStringLiteral("sudo")) {

        int index = 1;

        while (index < tokens.size() &&
               tokens.at(index).startsWith('-')) {

            ++index;
        }

        if (index < tokens.size()) {
            return executableFromDesktopExec(
                tokens.mid(index).join(' '));
        }
    }

    /* common terminal wrappers */
    const QSet<QString> terminals = {
        QStringLiteral("konsole"),
        QStringLiteral("xterm"),
        QStringLiteral("kitty"),
        QStringLiteral("alacritty"),
        QStringLiteral("gnome-terminal")
    };

    if (terminals.contains(baseName)) {

        int commandIndex =
            tokens.indexOf(
                QStringLiteral("-e"));

        if (commandIndex < 0) {
            commandIndex =
                tokens.indexOf(
                    QStringLiteral("--"));
        }

        if (commandIndex >= 0 &&
            commandIndex + 1 < tokens.size()) {

            return executableFromDesktopExec(
                tokens.mid(commandIndex + 1)
                    .join(' '));
        }
    }

    first =
        expandHomePath(first);

    if (QFileInfo(first).isAbsolute())
        return QDir::cleanPath(first);

    return {};
}


QString manualInstallRoot(
    const QString &exec)
{
    const QString executable =
        executableFromDesktopExec(exec);

    if (executable.isEmpty())
        return {};

    QFileInfo info(executable);

    if (!info.isAbsolute())
        return {};

    const QString path =
        info.absoluteFilePath();

    /*
     * AppImages are self-contained files. Remove the AppImage
     * itself rather than guessing/deleting its parent directory.
     */
    if (path.endsWith(
            QStringLiteral(".AppImage"),
            Qt::CaseInsensitive)) {

        return path;
    }

    /*
     * Applications installed under /opt normally keep all their
     * files below /opt/<application>.
     */
    if (path.startsWith(
            QStringLiteral("/opt/"))) {

        const QString remainder =
            path.mid(
                QStringLiteral("/opt/").size());

        const QString first =
            remainder.section(
                '/',
                0,
                0);

        if (!first.isEmpty()) {

            return QStringLiteral("/opt/") +
                first;
        }
    }

    /*
     * User-local applications commonly live below
     * ~/.local/share/<application>/...
     */
    const QString localShare =
        QDir::homePath() +
        QStringLiteral("/.local/share/");

    if (path.startsWith(localShare)) {

        const QString remainder =
            path.mid(localShare.size());

        const QString first =
            remainder.section(
                '/',
                0,
                0);

        if (!first.isEmpty()) {

            return localShare + first;
        }
    }

    /*
     * For other manual applications, use the executable itself
     * rather than guessing an unrelated parent directory.
     */
    return path;
}



QDateTime bestExistingPathTimestamp(
    const QString &path)
{
    if (path.trimmed().isEmpty())
        return {};

    const QFileInfo info(
        path);

    if (!info.exists())
        return {};

    /*
     * Birth time is the closest thing to a creation/install time
     * when the filesystem provides it. metadataChangeTime is a
     * useful Linux fallback for copied/installed files whose mtime
     * may still reflect the original build date.
     */
    QDateTime timestamp =
        info.birthTime();

    if (!timestamp.isValid())
        timestamp =
            info.metadataChangeTime();

    if (!timestamp.isValid())
        timestamp =
            info.lastModified();

    return timestamp;
}


QDateTime manualApplicationInstallTimestamp(
    const QString &installLocation,
    const QString &desktopExec,
    const QString &desktopFile)
{
    QStringList candidates;

    auto addCandidate =
        [&candidates](const QString &path) {

            const QString cleaned =
                QDir::cleanPath(
                    path.trimmed());

            if (cleaned.isEmpty() ||
                cleaned == QStringLiteral(".")) {

                return;
            }

            if (!candidates.contains(cleaned))
                candidates.append(cleaned);
        };

    /*
     * Prefer the actual install/removal target.
     */
    addCandidate(
        installLocation);

    /*
     * If the stored install target is stale or a wrapper was used,
     * also try the executable resolved from the .desktop Exec line.
     */
    addCandidate(
        executableFromDesktopExec(
            desktopExec));

    /*
     * A valid .desktop launcher is our last-resort install proxy
     * for locally built/manual apps. This is especially useful for
     * applications installed by a custom setup script, where there
     * is no RPM/Flatpak transaction timestamp.
     */
    addCandidate(
        desktopFile);

    for (const QString &candidate :
         candidates) {

        const QDateTime timestamp =
            bestExistingPathTimestamp(
                candidate);

        if (timestamp.isValid())
            return timestamp;
    }

    return {};
}


QString sizeForManualApplication(
    const QString &exec)
{
    const QString target =
        manualInstallRoot(exec);

    if (target.isEmpty())
        return QStringLiteral("Unknown");

    QFileInfo info(target);

    if (!info.exists())
        return QStringLiteral("Unknown");

    if (info.isFile()) {

        return humanSize(
            static_cast<quint64>(
                info.size()));
    }

    QProcess process;

    process.start(
        QStringLiteral("du"),
        {
            QStringLiteral("-sb"),
            QStringLiteral("--"),
            target
        });

    if (!process.waitForFinished(
            30000)) {

        process.kill();
        process.waitForFinished(
            1000);

        return QStringLiteral("Unknown");
    }

    if (process.exitStatus() !=
            QProcess::NormalExit ||
        process.exitCode() != 0) {

        return QStringLiteral("Unknown");
    }

    const QString output =
        QString::fromLocal8Bit(
            process.readAllStandardOutput())
            .trimmed();

    bool ok = false;

    const quint64 bytes =
        output.section(
            '\t',
            0,
            0)
            .section(
                ' ',
                0,
                0)
            .toULongLong(&ok);

    if (!ok)
        return QStringLiteral("Unknown");

    return humanSize(bytes);
}




bool protectedCorePackage(
    const QString &packageName)
{
    const QString name =
        packageName.trimmed();

    if (name.isEmpty())
        return true;

    static const QStringList exact = {
        QStringLiteral("filesystem"),
        QStringLiteral("setup"),
        QStringLiteral("basesystem"),
        QStringLiteral("rpm"),
        QStringLiteral("dnf"),
        QStringLiteral("dnf5"),
        QStringLiteral("systemd"),
        QStringLiteral("glibc"),
        QStringLiteral("bash"),
        QStringLiteral("coreutils"),
        QStringLiteral("util-linux"),
        QStringLiteral("sudo"),
        QStringLiteral("polkit"),
        QStringLiteral("dbus"),
        QStringLiteral("NetworkManager"),
        QStringLiteral("selinux-policy"),
        QStringLiteral("selinux-policy-targeted")
    };

    if (exact.contains(
            name,
            Qt::CaseInsensitive)) {

        return true;
    }

    const QString lower =
        name.toLower();

    const QStringList protectedPrefixes = {
        QStringLiteral("kernel"),
        QStringLiteral("systemd-"),
        QStringLiteral("glibc-"),
        QStringLiteral("rpm-"),
        QStringLiteral("dnf-"),
        QStringLiteral("dnf5-"),
        QStringLiteral("libdnf"),
        QStringLiteral("grub2-"),
        QStringLiteral("shim-")
    };

    for (const QString &prefix :
         protectedPrefixes) {

        if (lower.startsWith(prefix))
            return true;
    }

    return false;
}


bool safeManualRemovalTarget(
    const QString &target)
{
    const QString cleaned =
        QDir::cleanPath(target);

    if (cleaned.isEmpty() ||
        cleaned == QStringLiteral("/") ||
        cleaned == QDir::homePath() ||
        cleaned == QStringLiteral("/opt") ||
        cleaned == QStringLiteral("/usr") ||
        cleaned == QStringLiteral("/usr/local")) {

        return false;
    }

    const QString home =
        QDir::cleanPath(
            QDir::homePath());

    if (cleaned.startsWith(
            home + QStringLiteral("/"))) {

        return true;
    }

    if (cleaned.startsWith(
            QStringLiteral("/opt/"))) {

        return cleaned.count('/') >= 2;
    }

    if (cleaned.startsWith(
            QStringLiteral("/usr/local/bin/")) ||
        cleaned.startsWith(
            QStringLiteral("/usr/local/sbin/"))) {

        return QFileInfo(cleaned).isFile();
    }

    return cleaned.endsWith(
        QStringLiteral(".AppImage"),
        Qt::CaseInsensitive);
}


QStringList desktopApplicationFiles()
{
    QStringList files;

    const QStringList directories = {
        QDir::homePath() +
            QStringLiteral("/.local/share/applications"),
        QStringLiteral("/usr/share/applications"),
        QStringLiteral("/usr/local/share/applications")
    };

    for (const QString &directoryPath :
         directories) {

        QDir directory(directoryPath);

        if (!directory.exists())
            continue;

        const QFileInfoList entries =
            directory.entryInfoList(
                {QStringLiteral("*.desktop")},
                QDir::Files |
                QDir::Readable,
                QDir::Name);

        for (const QFileInfo &entry :
             entries) {

            QSettings desktop(
                entry.absoluteFilePath(),
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            const QString type =
                desktop.value(
                    QStringLiteral("Type"))
                    .toString()
                    .trimmed();

            const bool hidden =
                desktop.value(
                    QStringLiteral("Hidden"),
                    false)
                    .toBool();

            const bool noDisplay =
                desktop.value(
                    QStringLiteral("NoDisplay"),
                    false)
                    .toBool();

            const QString name =
                desktop.value(
                    QStringLiteral("Name"))
                    .toString()
                    .trimmed();

            desktop.endGroup();

            if (!type.isEmpty() &&
                type.compare(
                    QStringLiteral("Application"),
                    Qt::CaseInsensitive) != 0) {

                continue;
            }

            if (hidden ||
                noDisplay ||
                name.isEmpty()) {

                continue;
            }

            files.append(
                entry.absoluteFilePath());
        }
    }

    files.removeDuplicates();

    return files;
}

} // namespace


QString RpmDetector::name() const
{
    return QStringLiteral("RPM / DNF");
}


bool RpmDetector::isAvailable() const
{
    return !QStandardPaths::findExecutable(
        QStringLiteral("rpm")).isEmpty();
}


QStringList RpmDetector::runRpm(
    const QStringList &arguments) const
{
    QProcess process;

    process.start(
        QStringLiteral("rpm"),
        arguments);

    if (!process.waitForStarted(5000))
        return {};

    if (!process.waitForFinished(120000)) {

        process.kill();
        process.waitForFinished(2000);

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


QList<ApplicationInfo>
RpmDetector::parsePackageList(
    const QStringList &lines) const
{
    Q_UNUSED(lines);

    QList<ApplicationInfo> applications;

    /*
     * One bulk query gets the entire RPM inventory, including
     * installed size, in a single process.
     */
    const QStringList metadataLines =
        runRpm(
            {
                QStringLiteral("-qa"),
                QStringLiteral("--qf"),
                QStringLiteral(
                    "%{NAME}\t"
                    "%{VERSION}\t"
                    "%{RELEASE}\t"
                    "%{ARCH}\t"
                    "%{SIZE:humaniec}\t"
                    "%{INSTALLTIME}\t"
                    "%{SUMMARY}\n")
            });

    QHash<QString, RpmMetadata> metadata;

    for (const QString &line :
         metadataLines) {

        const QStringList fields =
            line.split('\t');

        if (fields.size() < 7)
            continue;

        RpmMetadata value;

        value.name =
            fields.at(0).trimmed();

        value.version =
            fields.at(1).trimmed();

        value.release =
            fields.at(2).trimmed();

        value.arch =
            fields.at(3).trimmed();

        value.size =
            fields.at(4).trimmed();

        bool installTimeOk = false;
        const qint64 installEpoch =
            fields.at(5).trimmed().toLongLong(
                &installTimeOk);

        if (installTimeOk &&
            installEpoch > 0) {

            value.installDate =
                QDateTime::fromSecsSinceEpoch(
                    installEpoch)
                    .toLocalTime()
                    .date()
                    .toString(
                        QStringLiteral(
                            "yyyy-MM-dd"));
        }

        value.summary =
            fields.mid(6)
                .join(
                    QStringLiteral("\t"))
                .trimmed();

        if (!value.name.isEmpty()) {

            metadata.insert(
                value.name,
                value);
        }
    }

    /*
     * Resolve representative install roots for the complete RPM
     * inventory in ONE additional rpm process.
     *
     * %{=NAME} is intentionally forced to scalar form while
     * DIRNAMES is iterated. Without the '=' rpm queryformat can
     * reject the mixed scalar/array expression.
     */
    const QStringList directoryLines =
        runRpm(
            {
                QStringLiteral("-qa"),
                QStringLiteral("--qf"),
                QStringLiteral(
                    "[%{=NAME}\t%{DIRNAMES}\n]")
            });

    QHash<QString, QStringList> installRootsByPackage;

    for (const QString &line :
         directoryLines) {

        const int tab =
            line.indexOf('\t');

        if (tab <= 0)
            continue;

        const QString packageName =
            line.left(tab).trimmed();

        const QString root =
            representativeInstallRoot(
                line.mid(tab + 1));

        if (packageName.isEmpty() ||
            root.isEmpty()) {

            continue;
        }

        QStringList &roots =
            installRootsByPackage[packageName];

        if (!roots.contains(root))
            roots.append(root);
    }

    for (auto it = metadata.begin();
         it != metadata.end();
         ++it) {

        it.value().installRoots =
            installRootsByPackage.value(
                it.key());
    }

    /*
     * Visible desktop launchers become the normal application
     * inventory. This includes both RPM-owned applications and
     * manual/local installations.
     */
    const QStringList desktopFiles =
        desktopApplicationFiles();

    QHash<QString, ApplicationInfo> rpmApplications;
    QHash<QString, ApplicationInfo> manualApplications;

    for (const QString &desktopFile :
         desktopFiles) {

        QSettings desktop(
            desktopFile,
            QSettings::IniFormat);

        desktop.beginGroup(
            QStringLiteral(
                "Desktop Entry"));

        const QString desktopName =
            desktop.value(
                QStringLiteral("Name"))
                .toString()
                .trimmed();

        const QString comment =
            desktop.value(
                QStringLiteral("Comment"))
                .toString()
                .trimmed();

        const QString executable =
            desktop.value(
                QStringLiteral("Exec"))
                .toString()
                .trimmed();

        desktop.endGroup();

        const QStringList owners =
            runRpm(
                {
                    QStringLiteral("-qf"),
                    QStringLiteral("--qf"),
                    QStringLiteral("%{NAME}\n"),
                    desktopFile
                });

        if (!owners.isEmpty()) {

            const QString packageName =
                owners.first().trimmed();

            if (packageName.isEmpty() ||
                rpmApplications.contains(
                    packageName)) {

                continue;
            }

            ApplicationInfo app;

            app.id =
                packageName;

            app.type =
                ApplicationType::RPM;

            app.packageManager =
                QStringLiteral("RPM / DNF");

            app.source =
                QStringLiteral(
                    "RPM database + desktop launcher");

            app.installed =
                true;

            /*
             * A desktop launcher must never bypass the same protected-core
             * policy used for RPMs discovered only through the package
             * database.  Some critical Fedora components own launchers too.
             */
            const bool protectedCore =
                protectedCorePackage(
                    packageName);

            app.removable =
                !protectedCore;

            app.systemComponent =
                protectedCore;

            app.protectedComponent =
                protectedCore;

            app.userInstalled =
                false;

            app.risk =
                protectedCore
                    ? RiskLevel::Danger
                    : RiskLevel::Review;

            app.desktopFile =
                desktopFile;

            app.executable =
                executable;

            app.name =
                desktopName.isEmpty()
                    ? packageName
                    : desktopName;

            if (metadata.contains(
                    packageName)) {

                const RpmMetadata value =
                    metadata.value(
                        packageName);

                app.version =
                    displayVersion(value);

                app.installedSize =
                    value.size.isEmpty()
                        ? QStringLiteral("Unknown")
                        : value.size;

                app.installDate =
                    value.installDate;

                app.installDateEstimated =
                    false;

                app.description =
                    comment.isEmpty()
                        ? value.summary
                        : comment;

                app.installLocations =
                    value.installRoots;
            }
            else {

                app.installedSize =
                    QStringLiteral("Unknown");

                app.description =
                    comment;
            }

            rpmApplications.insert(
                packageName,
                app);

            continue;
        }

        /*
         * A visible launcher that is not owned by RPM is still a
         * real installed application. Keep it in the normal list
         * as Installed / Review until a dedicated safe remover is
         * implemented for its installation method.
         */
        QFileInfo desktopInfo(
            desktopFile);

        QString manualId =
            desktopInfo.completeBaseName();

        if (manualId.isEmpty())
            manualId =
                desktopInfo.fileName();

        if (manualId.isEmpty() ||
            manualApplications.contains(
                manualId)) {

            continue;
        }

        ApplicationInfo app;

        app.id =
            manualId;

        app.name =
            desktopName.isEmpty()
                ? manualId
                : desktopName;

        app.desktopFile =
            desktopFile;

        app.executable =
            executable;

        app.description =
            comment;

        app.source =
            QStringLiteral(
                "Desktop launcher / manual installation");

        app.installed =
            true;

        app.userInstalled =
            desktopFile.startsWith(
                QDir::homePath());

        app.systemComponent =
            false;

        app.protectedComponent =
            false;

        app.risk =
            RiskLevel::Advanced;

        app.installLocation =
            manualInstallRoot(
                executable);

        if (!app.installLocation.isEmpty())
            app.installLocations.append(
                app.installLocation);

        const bool appImage =
            app.installLocation.endsWith(
                QStringLiteral(".AppImage"),
                Qt::CaseInsensitive) ||
            executable.contains(
                QStringLiteral(".AppImage"),
                Qt::CaseInsensitive);

        if (appImage) {

            app.type =
                ApplicationType::AppImage;

            app.packageManager =
                QStringLiteral(
                    "AppImage / Manual");

            /*
             * A launcher already identified as an AppImage is a
             * user-removable application.  Do not hide its
             * checkbox merely because the first-pass path parser
             * could not resolve the target perfectly.
             *
             * The uninstall path performs a second resolution
             * pass and refuses safely if no concrete AppImage can
             * actually be found.
             */
            app.removable = true;
        }
        else {

            app.type =
                ApplicationType::Custom;

            app.packageManager =
                QStringLiteral(
                    "Manual / Desktop");

            app.removable =
                safeManualRemovalTarget(
                    app.installLocation);
        }

        app.installedSize =
            sizeForManualApplication(
                executable);

        /*
         * Manual/AppImage installers do not expose a universal
         * package-manager install timestamp.
         *
         * Resolve the best real filesystem candidate in order:
         *   1. actual install/removal target
         *   2. resolved executable from the .desktop Exec line
         *   3. the .desktop launcher itself
         *
         * This prevents a stale/nonexistent installLocation from
         * causing locally built applications to show "Unknown".
         */
        const QDateTime manualDate =
            manualApplicationInstallTimestamp(
                app.installLocation,
                executable,
                desktopFile);

        if (manualDate.isValid()) {
            app.installDate =
                manualDate.toLocalTime()
                    .date()
                    .toString(
                        QStringLiteral(
                            "yyyy-MM-dd"));

            app.installDateEstimated =
                true;
        }

        manualApplications.insert(
            manualId,
            app);
    }

    for (auto it =
             rpmApplications.cbegin();
         it != rpmApplications.cend();
         ++it) {

        applications.append(
            it.value());
    }

    for (auto it =
             manualApplications.cbegin();
         it != manualApplications.cend();
         ++it) {

        applications.append(
            it.value());
    }

    /*
     * Remaining RPMs are system/dependency inventory. They are
     * retained for TotalSweep's comprehensive view but the main UI
     * keeps them behind an explicit Show button.
     */
    for (auto it =
             metadata.cbegin();
         it != metadata.cend();
         ++it) {

        const QString packageName =
            it.key();

        if (rpmApplications.contains(
                packageName)) {

            continue;
        }

        const RpmMetadata value =
            it.value();

        ApplicationInfo app;

        app.id =
            packageName;

        app.name =
            packageName;

        app.version =
            displayVersion(value);

        app.installedSize =
            value.size.isEmpty()
                ? QStringLiteral("Unknown")
                : value.size;

        app.installDate =
            value.installDate;

        app.installDateEstimated =
            false;

        app.description =
            value.summary;

        app.type =
            ApplicationType::RPM;

        app.packageManager =
            QStringLiteral("RPM / DNF");

        app.source =
            QStringLiteral("RPM database");

        app.installLocations =
            value.installRoots;

        app.installLocation =
            summarizeInstallRoots(
                value.installRoots);

        app.installed =
            true;

        const bool protectedCore =
            protectedCorePackage(
                packageName);

        app.removable =
            !protectedCore;

        app.userInstalled =
            false;

        app.systemComponent =
            true;

        app.protectedComponent =
            protectedCore;

        app.risk =
            protectedCore
                ? RiskLevel::Danger
                : RiskLevel::Advanced;

        applications.append(
            app);
    }

    return applications;
}


ApplicationInfo
RpmDetector::inspectPackage(
    const QString &packageId) const
{
    ApplicationInfo app;

    if (packageId.trimmed().isEmpty())
        return app;

    const QStringList metadata =
        runRpm(
            {
                QStringLiteral("-q"),
                QStringLiteral("--qf"),
                QStringLiteral(
                    "%{NAME}\t"
                    "%{VERSION}\t"
                    "%{RELEASE}\t"
                    "%{ARCH}\t"
                    "%{SIZE:humaniec}\t"
                    "%{INSTALLTIME}\t"
                    "%{SUMMARY}\n"),
                packageId
            });

    if (metadata.isEmpty())
        return app;

    const QStringList fields =
        metadata.first()
            .split('\t');

    app.id =
        packageId;

    app.name =
        fields.isEmpty()
            ? packageId
            : fields.at(0).trimmed();

    if (fields.size() >= 4) {

        RpmMetadata value;

        value.name =
            fields.at(0).trimmed();

        value.version =
            fields.at(1).trimmed();

        value.release =
            fields.at(2).trimmed();

        value.arch =
            fields.at(3).trimmed();

        app.version =
            displayVersion(value);
    }

    if (fields.size() >= 5) {

        app.installedSize =
            fields.at(4).trimmed();
    }

    if (fields.size() >= 6) {

        bool installTimeOk = false;
        const qint64 installEpoch =
            fields.at(5).trimmed().toLongLong(
                &installTimeOk);

        if (installTimeOk &&
            installEpoch > 0) {

            app.installDate =
                QDateTime::fromSecsSinceEpoch(
                    installEpoch)
                    .toLocalTime()
                    .date()
                    .toString(
                        QStringLiteral(
                            "yyyy-MM-dd"));
        }
    }

    if (fields.size() >= 7) {

        app.description =
            fields.mid(6)
                .join(
                    QStringLiteral("\t"))
                .trimmed();
    }

    const QStringList packageDirectories =
        runRpm(
            {
                QStringLiteral("-q"),
                QStringLiteral("--qf"),
                QStringLiteral("[%{DIRNAMES}\n]"),
                packageId
            });

    for (const QString &directory :
         packageDirectories) {

        const QString root =
            representativeInstallRoot(
                directory);

        if (!root.isEmpty() &&
            !app.installLocations.contains(root)) {

            app.installLocations.append(root);
        }
    }

    app.installLocation =
        summarizeInstallRoots(
            app.installLocations);

    app.type =
        ApplicationType::RPM;

    app.packageManager =
        QStringLiteral("RPM / DNF");

    app.source =
        QStringLiteral("RPM database");

    app.installed =
        true;

    const bool protectedCore =
        protectedCorePackage(
            app.id);

    app.removable =
        !protectedCore;

    app.systemComponent =
        protectedCore;

    app.protectedComponent =
        protectedCore;

    app.risk =
        protectedCore
            ? RiskLevel::Danger
            : RiskLevel::Review;

    return app;
}


QList<ApplicationInfo>
RpmDetector::detectApplications() const
{
    if (!isAvailable())
        return {};

    return parsePackageList({});
}


QList<ApplicationInfo>
RpmDetector::searchApplications(
    const QString &query) const
{
    if (!isAvailable())
        return {};

    const QString needle =
        query.trimmed();

    const QList<ApplicationInfo> all =
        detectApplications();

    if (needle.isEmpty())
        return all;

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
                Qt::CaseInsensitive) ||

            app.executable.contains(
                needle,
                Qt::CaseInsensitive)) {

            matches.append(app);
        }
    }

    return matches;
}
