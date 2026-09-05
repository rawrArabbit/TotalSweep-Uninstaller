#include <algorithm>
#include <QApplication>
#include <QAbstractTableModel>
#include <QCheckBox>
#include <QClipboard>
#include <QCryptographicHash>
#include <QButtonGroup>
#include <QBrush>
#include <QColor>
#include <QCloseEvent>
#include <QCollator>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDirIterator>
#include <QEvent>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontMetrics>
#include <QFrame>
#include <QGuiApplication>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QImage>
#include <QMap>
#include <QMenu>
#include <QMouseEvent>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QAction>
#include <QPalette>
#include <QPair>
#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QPushButton>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPixmap>
#include <QProgressBar>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScreen>
#include <QSignalBlocker>
#include <QSettings>
#include <QShortcut>
#include <QSet>
#include <QSize>
#include <QSizePolicy>
#include <QKeySequence>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QScrollArea>
#include <QScrollBar>
#include <QTableView>
#include <QThread>
#include <QTemporaryDir>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>
#include <QVector>
#include <QWidget>
#include <QWidgetAction>
#include <QProgressDialog>
#include <memory>
#include <utility>

#include "src/core/ApplicationBackendManager.h"
#include "src/core/ApplicationLibrary.h"
#include "src/package/rpm/RpmBackend.h"
#include "src/package/flatpak/FlatpakBackend.h"
#include "restore_engine.h"

struct Hit {
    QString path;
    QString category;
    int risk;
};

struct PendingLeftoverItem {
    QTreeWidgetItem *category{};
    QString path;
    int risk = 3;
};

static QStringList runCommand(
    const QString &program,
    const QStringList &args,
    int timeout = 120000)
{
    QProcess process;

    process.start(program, args);

    if (!process.waitForStarted(5000))
        return {};

    if (!process.waitForFinished(timeout)) {
        process.kill();
        process.waitForFinished(2000);
        return {};
    }

    return QString::fromLocal8Bit(
        process.readAllStandardOutput())
    .split('\n', Qt::SkipEmptyParts);
}

static QString totalSweepData()
{
    const QString path =
    QDir::homePath() +
    "/.local/share/TotalSweep Uninstaller";

    QDir().mkpath(path);
    QDir().mkpath(path + "/quarantine");
    QDir().mkpath(path + "/package-cache/rpm/sha256");
    QDir().mkpath(path + "/package-cache/flatpak/sha256");
    QDir().mkpath(path + "/staging");

    return path;
}


static bool isTotalSweepManagedPath(
    const QString &path)
{
    const QString raw = path.trimmed();
    if (raw.isEmpty())
        return false;

    const QString clean = QDir::cleanPath(raw);
    const QString root = QDir::cleanPath(totalSweepData());

    return clean == root ||
        clean.startsWith(root + QLatin1Char('/'));
}


static QString quarantineRootPath()
{
    return QDir::cleanPath(
        totalSweepData() +
        QStringLiteral("/quarantine"));
}


static QString trustedDestructiveRootForPath(
    const QString &path)
{
    const QString cleaned =
        QDir::cleanPath(path.trimmed());
    const QString home =
        QDir::cleanPath(QDir::homePath());

    const QStringList roots = {
        home,
        QStringLiteral("/usr/local"),
        QStringLiteral("/usr/libexec"),
        QStringLiteral("/usr/sbin"),
        QStringLiteral("/usr/bin"),
        QStringLiteral("/usr/share"),
        QStringLiteral("/var/cache"),
        QStringLiteral("/var/lib"),
        QStringLiteral("/var/log"),
        QStringLiteral("/etc"),
        QStringLiteral("/opt")
    };

    for (const QString &root : roots) {
        if (cleaned.startsWith(
                root + QLatin1Char('/'))) {
            return root;
        }
    }

    return {};
}


static bool hasSymlinkedParentBelowRoot(
    const QString &path,
    const QString &root)
{
    const QString cleaned =
        QDir::cleanPath(path.trimmed());
    const QString cleanRoot =
        QDir::cleanPath(root.trimmed());

    if (cleaned.isEmpty() ||
        cleanRoot.isEmpty() ||
        !QDir::isAbsolutePath(cleaned) ||
        !QDir::isAbsolutePath(cleanRoot) ||
        !cleaned.startsWith(
            cleanRoot + QLatin1Char('/'))) {
        return true;
    }

    QString parent =
        QDir::cleanPath(
            QFileInfo(cleaned)
                .absolutePath());

    while (parent != cleanRoot) {
        if (!parent.startsWith(
                cleanRoot + QLatin1Char('/'))) {
            return true;
        }

        const QFileInfo parentInfo(parent);
        if (parentInfo.isSymLink())
            return true;

        const QString next =
            QDir::cleanPath(
                parentInfo.dir()
                    .absolutePath());

        if (next == parent)
            return true;

        parent = next;
    }

    return false;
}


static bool hasUserWritableParentBelowRoot(
    const QString &path,
    const QString &root)
{
    const QString cleaned =
        QDir::cleanPath(path.trimmed());
    const QString cleanRoot =
        QDir::cleanPath(root.trimmed());

    if (cleaned.isEmpty() ||
        cleanRoot.isEmpty() ||
        !QDir::isAbsolutePath(cleaned) ||
        !QDir::isAbsolutePath(cleanRoot) ||
        !cleaned.startsWith(
            cleanRoot + QLatin1Char('/'))) {
        return true;
    }

    QString parent =
        QDir::cleanPath(
            QFileInfo(cleaned)
                .absolutePath());

    while (parent != cleanRoot) {
        if (!parent.startsWith(
                cleanRoot + QLatin1Char('/'))) {
            return true;
        }

        const QFileInfo parentInfo(parent);
        if (parentInfo.isWritable())
            return true;

        const QString next =
            QDir::cleanPath(
                parentInfo.dir()
                    .absolutePath());

        if (next == parent)
            return true;

        parent = next;
    }

    return QFileInfo(cleanRoot).isWritable();
}


static bool isSafePrivilegedPathOperationTarget(
    const QString &path)
{
    const QString trustedRoot =
        trustedDestructiveRootForPath(path);

    if (trustedRoot.isEmpty())
        return false;

    return !hasSymlinkedParentBelowRoot(
               path,
               trustedRoot) &&
        !hasUserWritableParentBelowRoot(
            path,
            trustedRoot);
}


static bool isSafeRpmNameToken(
    const QString &value)
{
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9+._-]*$"));

    return pattern.match(value.trimmed()).hasMatch();
}


static bool isSafeRpmNevraToken(
    const QString &value)
{
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9+._~^:-]*$"));

    return pattern.match(value.trimmed()).hasMatch();
}


static bool isSafeFlatpakIdToken(
    const QString &value)
{
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._-]*$"));

    const QString trimmed = value.trimmed();
    return trimmed.contains(QLatin1Char('.')) &&
        pattern.match(trimmed).hasMatch();
}


static bool isSafeFlatpakRemoteToken(
    const QString &value)
{
    if (value.trimmed().isEmpty())
        return true;

    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._-]*$"));

    return pattern.match(value.trimmed()).hasMatch();
}


static bool isSafeSha256Token(
    const QString &value)
{
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Fa-f0-9]{64}$"));

    return pattern.match(value.trimmed()).hasMatch();
}


static QString packageCacheGroupRoot(
    const QString &group)
{
    if (group != QStringLiteral("rpm") &&
        group != QStringLiteral("flatpak")) {
        return {};
    }

    return QDir::cleanPath(
        totalSweepData() +
        QStringLiteral("/package-cache/") +
        group +
        QStringLiteral("/sha256"));
}


static bool isCanonicalManagedDirectChild(
    const QString &path,
    const QString &root,
    bool requireDirectory)
{
    const QString cleanPath =
        QDir::cleanPath(
            path.trimmed());

    const QString cleanRoot =
        QDir::cleanPath(
            root.trimmed());

    if (cleanPath.isEmpty() ||
        cleanRoot.isEmpty() ||
        !QDir::isAbsolutePath(cleanPath) ||
        !QDir::isAbsolutePath(cleanRoot)) {
        return false;
    }

    const QFileInfo rootInfo(cleanRoot);
    const QFileInfo candidateInfo(cleanPath);

    if (!rootInfo.exists() ||
        !rootInfo.isDir() ||
        !candidateInfo.exists() ||
        candidateInfo.isSymLink()) {
        return false;
    }

    if (requireDirectory &&
        !candidateInfo.isDir()) {
        return false;
    }

    if (!requireDirectory &&
        !candidateInfo.isFile()) {
        return false;
    }

    const QString canonicalRoot =
        rootInfo.canonicalFilePath();

    const QString canonicalCandidate =
        candidateInfo.canonicalFilePath();

    if (canonicalRoot.isEmpty() ||
        canonicalCandidate.isEmpty()) {
        return false;
    }

    return QFileInfo(canonicalCandidate)
               .absolutePath() == canonicalRoot;
}


static bool isManagedQuarantineSession(
    const QString &session)
{
    return isCanonicalManagedDirectChild(
        session,
        quarantineRootPath(),
        true);
}


static bool isManagedQuarantineSourceForMove(
    const QString &source,
    const QString &session)
{
    if (!isManagedQuarantineSession(session))
        return false;

    const QString cleanedSource =
        QDir::cleanPath(
            source.trimmed());

    if (cleanedSource.isEmpty() ||
        !QDir::isAbsolutePath(cleanedSource)) {
        return false;
    }

    const QFileInfo sourceInfo(cleanedSource);

    if (!sourceInfo.exists() &&
        !sourceInfo.isSymLink()) {
        return false;
    }

    const QString canonicalSession =
        QFileInfo(session)
            .canonicalFilePath();

    const QString canonicalParent =
        sourceInfo.dir()
            .canonicalPath();

    if (canonicalSession.isEmpty() ||
        canonicalParent.isEmpty()) {
        return false;
    }

    return canonicalParent == canonicalSession ||
        canonicalParent.startsWith(
            canonicalSession + QLatin1Char('/'));
}


static bool isManagedSnapshotPath(
    const QString &snapshot,
    const QString &group)
{
    const QString root =
        packageCacheGroupRoot(group);

    if (root.isEmpty())
        return false;

    return isCanonicalManagedDirectChild(
        snapshot,
        root,
        false);
}


static bool isManagedSnapshotPath(
    const QString &snapshot)
{
    return isManagedSnapshotPath(
               snapshot,
               QStringLiteral("rpm")) ||
        isManagedSnapshotPath(
               snapshot,
               QStringLiteral("flatpak"));
}


static bool isValidFlatpakScope(
    const QString &scope)
{
    return scope == QStringLiteral("user") ||
        scope == QStringLiteral("system");
}


static bool isStandardUserContentPath(
    const QString &path)
{
    const QString cleaned =
        QDir::cleanPath(
            path.trimmed());

    if (cleaned.isEmpty() ||
        !QDir::isAbsolutePath(cleaned)) {
        return false;
    }

    const QString home =
        QDir::cleanPath(
            QDir::homePath());

    const QList<QStandardPaths::StandardLocation> locations = {
        QStandardPaths::DesktopLocation,
        QStandardPaths::DocumentsLocation,
        QStandardPaths::DownloadLocation,
        QStandardPaths::MusicLocation,
        QStandardPaths::MoviesLocation,
        QStandardPaths::PicturesLocation,
        QStandardPaths::PublicShareLocation,
        QStandardPaths::TemplatesLocation
    };

    for (const QStandardPaths::StandardLocation location :
         locations) {
        const QString root =
            QDir::cleanPath(
                QStandardPaths::writableLocation(
                    location));

        if (root.isEmpty() ||
            root == home) {
            continue;
        }

        if (cleaned == root ||
            cleaned.startsWith(
                root + QLatin1Char('/'))) {
            return true;
        }
    }

    return false;
}

static QString sanitize(const QString &input)
{
    QString result = input;

    for (QChar &c : result) {
        if (!c.isLetterOrNumber() &&
            c != '-' &&
            c != '_') {
            c = '_';
            }
    }

    return result.left(80);
}


static QString wordForCount(
    int count,
    const QString &singular,
    const QString &plural)
{
    return count == 1 ? singular : plural;
}


static QString formatByteSize(qint64 bytes)
{
    if (bytes < 0)
        return QStringLiteral("—");

    const double value = static_cast<double>(bytes);
    if (bytes < 1024)
        return QStringLiteral("%1 B").arg(bytes);
    if (bytes < 1024LL * 1024LL)
        return QStringLiteral("%1 KiB").arg(value / 1024.0, 0, 'f', 1);
    if (bytes < 1024LL * 1024LL * 1024LL)
        return QStringLiteral("%1 MiB").arg(value / (1024.0 * 1024.0), 0, 'f', 1);
    if (bytes < 1024LL * 1024LL * 1024LL * 1024LL)
        return QStringLiteral("%1 GiB").arg(value / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);

    return QStringLiteral("%1 TiB").arg(
        value / (1024.0 * 1024.0 * 1024.0 * 1024.0),
        0, 'f', 1);
}


static QString sha256File(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray block = file.read(1024 * 1024);
        if (block.isEmpty() && file.error() != QFile::NoError)
            return {};
        hash.addData(block);
    }

    return QString::fromLatin1(hash.result().toHex());
}

static bool writeJsonObjectAtomic(
    const QString &path,
    const QJsonObject &object)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    return file.commit();
}

static QJsonObject readJsonObject(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}


static QJsonObject readManagedQuarantineMetadata(
    const QString &session)
{
    if (!isManagedQuarantineSession(session))
        return {};

    const QString metadataPath =
        QDir(session).filePath(
            QStringLiteral("metadata.json"));

    const QFileInfo sessionInfo(session);
    const QFileInfo metadataInfo(metadataPath);

    if (!metadataInfo.exists() ||
        !metadataInfo.isFile() ||
        metadataInfo.isSymLink()) {
        return {};
    }

    const QString canonicalSession =
        sessionInfo.canonicalFilePath();

    const QString canonicalMetadata =
        metadataInfo.canonicalFilePath();

    if (canonicalSession.isEmpty() ||
        canonicalMetadata.isEmpty() ||
        QFileInfo(canonicalMetadata)
                .absolutePath() != canonicalSession) {
        return {};
    }

    return readJsonObject(metadataPath);
}

static QJsonArray readJsonArray(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(file.readAll()).array();
}

static bool writeJsonArrayAtomic(
    const QString &path,
    const QJsonArray &array)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.write(QJsonDocument(array).toJson(QJsonDocument::Indented));
    return file.commit();
}

static QString cacheIndexPath()
{
    return totalSweepData() + QStringLiteral("/package-cache/index.json");
}

static QString cachedPayloadForIdentity(
    const QString &group,
    const QString &identity)
{
    const QJsonObject root = readJsonObject(cacheIndexPath());
    const QJsonObject entries = root[group].toObject();
    const QJsonObject entry = entries[identity].toObject();
    const QString path = entry[QStringLiteral("path")].toString();
    const QString expected = entry[QStringLiteral("sha256")].toString();

    if (path.isEmpty() ||
        expected.isEmpty() ||
        !isManagedSnapshotPath(path, group)) {
        return {};
    }

    if (sha256File(path) != expected)
        return {};

    return path;
}

static void rememberCachedPayload(
    const QString &group,
    const QString &identity,
    const QString &path,
    const QString &sha256)
{
    QJsonObject root = readJsonObject(cacheIndexPath());
    QJsonObject entries = root[group].toObject();
    QJsonObject entry;
    entry[QStringLiteral("path")] = path;
    entry[QStringLiteral("sha256")] = sha256;
    entries[identity] = entry;
    root[group] = entries;
    writeJsonObjectAtomic(cacheIndexPath(), root);
}

static bool moveIntoContentCache(
    const QString &source,
    const QString &kind,
    const QString &extension,
    QString &cachedPath,
    QString &sha256,
    QString &error)
{
    sha256 = sha256File(source);
    if (sha256.isEmpty()) {
        error = QStringLiteral("Could not calculate the snapshot checksum.");
        return false;
    }

    const QString directory =
        totalSweepData() + QStringLiteral("/package-cache/") + kind +
        QStringLiteral("/sha256");
    QDir().mkpath(directory);
    cachedPath = QDir(directory).filePath(sha256 + extension);

    if (QFileInfo::exists(cachedPath)) {
        QFile::remove(source);
        return true;
    }

    if (QFile::rename(source, cachedPath))
        return true;

    if (QFile::copy(source, cachedPath)) {
        QFile::remove(source);
        return true;
    }

    error = QStringLiteral("Could not move the snapshot into TotalSweep's package cache.");
    return false;
}


static bool copyIntoContentCache(
    const QString &source,
    const QString &kind,
    const QString &extension,
    QString &cachedPath,
    QString &sha256,
    QString &error)
{
    sha256 = sha256File(source);
    if (sha256.isEmpty()) {
        error = QStringLiteral("Could not calculate the snapshot checksum.");
        return false;
    }

    const QString directory =
        totalSweepData() + QStringLiteral("/package-cache/") + kind +
        QStringLiteral("/sha256");
    QDir().mkpath(directory);
    cachedPath = QDir(directory).filePath(sha256 + extension);
    if (QFileInfo::exists(cachedPath))
        return true;

    if (!QFile::copy(source, cachedPath)) {
        error = QStringLiteral("Could not copy the cached package into TotalSweep's package cache.");
        return false;
    }
    return true;
}

struct ProcessResult {
    bool started = false;
    bool success = false;
    int exitCode = -1;
    QString standardOutput;
    QString standardError;
};


struct RpmRemovalPreview {
    bool available = false;
    QStringList allPackages;
    QStringList additionalPackages;
    QStringList dependentPackages;
    QStringList unusedDependencies;
    QString freedSpace;
    QString rawOutput;
    QString error;
};


static RpmRemovalPreview parseRpmRemovalPreview(
    QString output,
    const QStringList &requestedPackages)
{
    RpmRemovalPreview preview;
    preview.rawOutput = output;

    output.remove(
        QRegularExpression(
            QStringLiteral("\\x1B\\[[0-9;?]*[ -/]*[@-~]")));

    enum class Section {
        None,
        Direct,
        Dependent,
        Unused
    };
    Section section = Section::None;

    QStringList packages;
    QStringList dependentPackages;
    QStringList unusedDependencies;

    const QStringList lines =
        output.split(QLatin1Char('\n'));

    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        const QString lower = line.toLower();

        if (line == QStringLiteral("Removing:")) {
            section = Section::Direct;
            continue;
        }

        if (lower.startsWith(QStringLiteral("removing dependent")) &&
            line.endsWith(QLatin1Char(':'))) {
            section = Section::Dependent;
            continue;
        }

        if (lower.startsWith(QStringLiteral("removing unused")) &&
            line.endsWith(QLatin1Char(':'))) {
            section = Section::Unused;
            continue;
        }

        if (line.startsWith(QStringLiteral("Removing ")) &&
            line.endsWith(QLatin1Char(':'))) {
            section = Section::Direct;
            continue;
        }

        if (line == QStringLiteral("Transaction Summary:") ||
            line.startsWith(QStringLiteral("Transaction Summary"))) {
            section = Section::None;
            continue;
        }

        if (line.startsWith(QStringLiteral("After this operation,"))) {
            const QRegularExpression freedExpression(
                QStringLiteral(
                    "After this operation,\\s+(.+?)\\s+will be freed"));
            const QRegularExpressionMatch match =
                freedExpression.match(line);
            if (match.hasMatch())
                preview.freedSpace = match.captured(1).trimmed();
            continue;
        }

        if (section == Section::None || line.isEmpty())
            continue;

        if (line.startsWith(QStringLiteral("Package ")) ||
            line == QStringLiteral("Package") ||
            line.startsWith(QStringLiteral("Arch ")) ||
            line.startsWith(QStringLiteral("Repository "))) {
            continue;
        }

        const QString packageName =
            line.section(
                QRegularExpression(QStringLiteral("\\s+")),
                0,
                0)
                .trimmed();

        if (packageName.isEmpty() ||
            packageName.endsWith(QLatin1Char(':')) ||
            !QRegularExpression(
                QStringLiteral("^[A-Za-z0-9_.+~-]+$"))
                 .match(packageName)
                 .hasMatch()) {
            continue;
        }

        packages.append(packageName);
        if (section == Section::Dependent)
            dependentPackages.append(packageName);
        else if (section == Section::Unused)
            unusedDependencies.append(packageName);
    }

    packages.removeDuplicates();
    dependentPackages.removeDuplicates();
    unusedDependencies.removeDuplicates();
    preview.allPackages = packages;

    QSet<QString> requested;
    for (const QString &package : requestedPackages)
        requested.insert(package.trimmed().toCaseFolded());

    for (const QString &package : packages) {
        if (!requested.contains(package.toCaseFolded()))
            preview.additionalPackages.append(package);
    }

    for (const QString &package : dependentPackages) {
        if (!requested.contains(package.toCaseFolded()))
            preview.dependentPackages.append(package);
    }

    for (const QString &package : unusedDependencies) {
        if (!requested.contains(package.toCaseFolded()))
            preview.unusedDependencies.append(package);
    }

    preview.available = !preview.allPackages.isEmpty();
    if (!preview.available) {
        preview.error = QStringLiteral(
            "DNF did not return a parseable removal transaction preview.");
    }

    return preview;
}


static ProcessResult runProcessResponsive(
    QWidget *parent,
    const QString &title,
    const QString &label,
    const QString &program,
    const QStringList &arguments,
    int timeoutMs = 300000,
    const QProcessEnvironment &environment = QProcessEnvironment(),
    const QString &standardInputFile = QString())
{
    ProcessResult result;
    QProcess process;
    QProgressDialog progress(label, QStringLiteral("Cancel"), 0, 0, parent);
    progress.setWindowTitle(title);
    progress.setWindowModality(Qt::WindowModal);
    progress.setMinimumDuration(250);
    progress.setAutoClose(false);
    progress.setAutoReset(false);

    progress.setWindowIcon(
        parent ? parent->windowIcon() : QApplication::windowIcon());
    const QScreen *progressScreen =
        progress.screen()
            ? progress.screen()
            : QApplication::primaryScreen();

    const int progressAvailableWidth =
        progressScreen
            ? progressScreen->availableGeometry().width()
            : 1280;

    const int progressMaximumWidth =
        qMax(
            720,
            qMin(
                1120,
                progressAvailableWidth - 120));

    const int progressMinimumWidth =
        qMin(
            progressMaximumWidth,
            qMax(
                760,
                qMax(
                    QFontMetrics(progress.font())
                        .horizontalAdvance(title) + 460,
                    progress.sizeHint().width() + 80)));

    progress.setMinimumWidth(progressMinimumWidth);
    progress.resize(
        progressMinimumWidth,
        progress.sizeHint().height());

    if (!environment.isEmpty())
        process.setProcessEnvironment(environment);
    if (!standardInputFile.isEmpty())
        process.setStandardInputFile(standardInputFile);

    process.start(program, arguments);
    if (!process.waitForStarted(5000)) {
        result.standardError = process.errorString();
        return result;
    }
    result.started = true;

    QElapsedTimer timer;
    timer.start();
    while (process.state() != QProcess::NotRunning) {
        process.waitForFinished(40);
        QApplication::processEvents(QEventLoop::AllEvents, 40);
        if (progress.wasCanceled() || timer.elapsed() > timeoutMs) {
            process.kill();
            process.waitForFinished(1000);
            result.standardError = progress.wasCanceled()
                ? QStringLiteral("Operation cancelled.")
                : QStringLiteral("Operation timed out.");
            return result;
        }
    }

    result.exitCode = process.exitCode();
    result.standardOutput = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
    result.standardError = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
    result.success = process.exitStatus() == QProcess::NormalExit && result.exitCode == 0;
    return result;
}


static QString applicationCachePath()
{
    return totalSweepData() +
        QStringLiteral("/application-cache.json");
}


static QJsonArray stringListToJson(
    const QStringList &values)
{
    QJsonArray array;

    for (const QString &value : values)
        array.append(value);

    return array;
}


static QStringList jsonToStringList(
    const QJsonValue &value)
{
    QStringList result;

    const QJsonArray array =
        value.toArray();

    for (const QJsonValue &item : array) {
        if (item.isString())
            result.append(item.toString());
    }

    return result;
}


static QJsonObject applicationToJson(
    const ApplicationInfo &app)
{
    QJsonObject object;

    object["name"] = app.name;
    object["id"] = app.id;
    object["version"] = app.version;
    object["installedSize"] = app.installedSize;
    object["installDate"] = app.installDate;
    object["installDateEstimated"] = app.installDateEstimated;
    object["description"] = app.description;
    object["executable"] = app.executable;
    object["desktopFile"] = app.desktopFile;
    object["installLocation"] = app.installLocation;
    object["packageManager"] = app.packageManager;
    object["source"] = app.source;
    object["dependencies"] =
        stringListToJson(app.dependencies);
    object["files"] =
        stringListToJson(app.files);
    object["installLocations"] =
        stringListToJson(app.installLocations);

    object["type"] =
        static_cast<int>(app.type);
    object["risk"] =
        static_cast<int>(app.risk);

    object["installed"] = app.installed;
    object["removable"] = app.removable;
    object["userInstalled"] = app.userInstalled;
    object["systemComponent"] = app.systemComponent;
    object["protectedComponent"] = app.protectedComponent;

    return object;
}


static ApplicationInfo applicationFromJson(
    const QJsonObject &object)
{
    ApplicationInfo app;

    app.name = object["name"].toString();
    app.id = object["id"].toString();
    app.version = object["version"].toString();
    app.installedSize =
        object["installedSize"].toString();
    app.installDate =
        object["installDate"].toString();
    app.installDateEstimated =
        object["installDateEstimated"].toBool(false);
    app.description =
        object["description"].toString();
    app.executable =
        object["executable"].toString();
    app.desktopFile =
        object["desktopFile"].toString();
    app.installLocation =
        object["installLocation"].toString();
    app.packageManager =
        object["packageManager"].toString();
    app.source = object["source"].toString();
    app.dependencies =
        jsonToStringList(object["dependencies"]);
    app.files =
        jsonToStringList(object["files"]);
    app.installLocations =
        jsonToStringList(
            object["installLocations"]);

    app.type = static_cast<ApplicationType>(
        object["type"].toInt(
            static_cast<int>(ApplicationType::Unknown)));

    app.risk = static_cast<RiskLevel>(
        object["risk"].toInt(
            static_cast<int>(RiskLevel::Unknown)));

    app.installed =
        object["installed"].toBool();
    app.removable =
        object["removable"].toBool();
    app.userInstalled =
        object["userInstalled"].toBool();
    app.systemComponent =
        object["systemComponent"].toBool();
    app.protectedComponent =
        object["protectedComponent"].toBool();

    return app;
}


static bool saveApplicationCacheFile(
    const QList<ApplicationInfo> &applications)
{
    if (applications.isEmpty())
        return false;

    QJsonArray array;

    for (const ApplicationInfo &app : applications)
        array.append(applicationToJson(app));

    QJsonObject root;
    root["schema"] = 1;
    root["savedAt"] =
        QDateTime::currentDateTimeUtc()
            .toString(Qt::ISODate);
    root["applications"] = array;

    QSaveFile file(
        applicationCachePath());

    if (!file.open(QIODevice::WriteOnly))
        return false;

    file.write(
        QJsonDocument(root)
            .toJson(QJsonDocument::Compact));

    return file.commit();
}


static QList<ApplicationInfo>
loadApplicationCacheFile(
    bool *ok = nullptr)
{
    if (ok)
        *ok = false;

    QFile file(
        applicationCachePath());

    if (!file.open(QIODevice::ReadOnly))
        return {};

    QJsonParseError parseError;

    const QJsonDocument document =
        QJsonDocument::fromJson(
            file.readAll(),
            &parseError);

    if (parseError.error !=
            QJsonParseError::NoError ||
        !document.isObject()) {

        return {};
    }

    const QJsonObject root =
        document.object();

    if (root["schema"].toInt() != 1)
        return {};

    QList<ApplicationInfo> applications;

    for (const QJsonValue &value :
         root["applications"].toArray()) {

        if (!value.isObject())
            continue;

        ApplicationInfo app =
            applicationFromJson(
                value.toObject());

        if (app.id.isEmpty() &&
            app.name.isEmpty()) {

            continue;
        }

        applications.append(app);
    }

    if (applications.isEmpty())
        return {};

    if (ok)
        *ok = true;

    return applications;
}


enum ApplicationFilterMode {
    FilterAllVisible = 0,
    FilterApplications = 1,
    FilterRemovableApplications = 2,
    FilterManualLocal = 3,
    FilterSystemAll = 4,
    FilterSystemRemovable = 5,
    FilterProtected = 6,
    FilterReview = 7
};


class ApplicationTableModel final : public QAbstractTableModel
{
public:
    explicit ApplicationTableModel(
        QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
        m_collator.setCaseSensitivity(
            Qt::CaseInsensitive);

        m_collator.setNumericMode(true);
    }

    void setApplications(
        const QList<ApplicationInfo> *applications)
    {
        beginResetModel();

        m_applications = applications;
        m_checked.clear();
        rebuildSortCaches();
        rebuildVisibleRows();

        endResetModel();
    }

    void setQuery(
        const QString &query)
    {
        const QString normalized =
            query.trimmed();

        if (m_query == normalized)
            return;

        beginResetModel();
        m_query = normalized;
        rebuildVisibleRows();
        endResetModel();
    }

    void setShowSystemItems(
        bool show)
    {
        if (m_showSystemItems == show)
            return;

        beginResetModel();
        m_showSystemItems = show;
        rebuildVisibleRows();
        endResetModel();
    }

    void setFilterMode(
        int mode)
    {
        if (m_filterMode == mode)
            return;

        beginResetModel();
        m_filterMode = mode;
        rebuildVisibleRows();
        endResetModel();
    }

    int filterMode() const
    {
        return m_filterMode;
    }

    bool showSystemItems() const
    {
        return m_showSystemItems;
    }

    void setHoveredRow(
        int row)
    {
        if (row < -1 ||
            row >= m_visibleRows.size()) {

            row = -1;
        }

        if (m_hoveredRow == row)
            return;

        const int oldRow =
            m_hoveredRow;

        m_hoveredRow = row;

        if (oldRow >= 0 &&
            oldRow < rowCount()) {

            emit dataChanged(
                index(oldRow, 0),
                index(oldRow, columnCount() - 1),
                {Qt::BackgroundRole});
        }

        if (m_hoveredRow >= 0 &&
            m_hoveredRow < rowCount()) {

            emit dataChanged(
                index(m_hoveredRow, 0),
                index(m_hoveredRow, columnCount() - 1),
                {Qt::BackgroundRole});
        }
    }

    void refreshTheme()
    {
        if (rowCount() <= 0 ||
            columnCount() <= 0) {

            return;
        }

        emit dataChanged(
            index(0, 0),
            index(rowCount() - 1, columnCount() - 1),
            {Qt::BackgroundRole,
             Qt::ForegroundRole,
             Qt::DecorationRole});
    }


    int visibleApplicationCount() const
    {
        return m_visibleRows.size();
    }

    int checkedCount() const
    {
        return m_checked.size();
    }

    QList<int> checkedSourceIndexes() const
    {
        QList<int> indexes;

        for (int sourceIndex : m_checked)
            indexes.append(sourceIndex);

        std::sort(
            indexes.begin(),
            indexes.end());

        return indexes;
    }

    void sort(
        int column,
        Qt::SortOrder order = Qt::AscendingOrder) override
    {
        if (column < 0 ||
            column >= columnCount()) {

            return;
        }

        m_sortColumn = column;
        m_sortOrder = order;

        beginResetModel();
        applySort();
        endResetModel();
    }


    bool isVisibleRowSelectable(
        int row) const
    {
        if (!m_applications ||
            row < 0 ||
            row >= m_visibleRows.size()) {

            return false;
        }

        const int sourceIndex =
            m_visibleRows.at(row);

        return isSelectable(
            m_applications->at(sourceIndex));
    }

    bool toggleVisibleRow(
        int row)
    {
        if (!isVisibleRowSelectable(row))
            return false;

        const int sourceIndex =
            m_visibleRows.at(row);

        if (m_checked.contains(sourceIndex))
            m_checked.remove(sourceIndex);
        else
            m_checked.insert(sourceIndex);

        emit dataChanged(
            index(row, 0),
            index(row, columnCount() - 1),
            {Qt::CheckStateRole, Qt::BackgroundRole});

        return true;
    }

    void clearChecks()
    {
        if (m_checked.isEmpty())
            return;

        m_checked.clear();

        if (rowCount() > 0) {
            emit dataChanged(
                index(0, 0),
                index(rowCount() - 1, columnCount() - 1),
                {Qt::CheckStateRole, Qt::BackgroundRole});
        }
    }

    void selectRecommended()
    {
        if (!m_applications)
            return;

        bool changed = false;

        for (int sourceIndex : m_visibleRows) {

            const ApplicationInfo &app =
                m_applications->at(sourceIndex);

            if (isSelectable(app) &&
                !isSystemInventory(app)) {

                if (!m_checked.contains(sourceIndex)) {
                    m_checked.insert(sourceIndex);
                    changed = true;
                }
            }
        }

        if (changed &&
            rowCount() > 0) {

            emit dataChanged(
                index(0, 0),
                index(rowCount() - 1, columnCount() - 1),
                {Qt::CheckStateRole, Qt::BackgroundRole});
        }
    }

    int rowCount(
        const QModelIndex &parent = QModelIndex()) const override
    {
        if (parent.isValid())
            return 0;

        return m_visibleRows.size();
    }

    int columnCount(
        const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent);
        return 8;
    }

    QVariant headerData(
        int section,
        Qt::Orientation orientation,
        int role = Qt::DisplayRole) const override
    {
        if (orientation != Qt::Horizontal)
            return {};

        if (role == Qt::TextAlignmentRole) {
            return static_cast<int>(
                Qt::AlignLeft |
                Qt::AlignVCenter);
        }

        if (role != Qt::DisplayRole)
            return {};

        switch (section) {
        case 0:
            return QStringLiteral("Application");
        case 1:
            return QStringLiteral("Package Type");
        case 2:
            return QStringLiteral("Version");
        case 3:
            return QStringLiteral("Size");
        case 4:
            return QStringLiteral("Install Location");
        case 5:
            return QStringLiteral("Install Date");
        case 6:
            return QStringLiteral("Description");
        case 7:
            return QStringLiteral("Status");
        default:
            return {};
        }
    }

    QString installLocationFor(
        const ApplicationInfo &app) const
    {
        if (!app.installLocation.trimmed().isEmpty())
            return app.installLocation.trimmed();

        if (isManualLocal(app) &&
            app.installed &&
            !app.removable) {
            return QStringLiteral("Not verified");
        }

        if (app.type == ApplicationType::Flatpak &&
            !app.id.trimmed().isEmpty()) {

            const QString userPath =
                QDir::homePath() +
                QStringLiteral("/.local/share/flatpak/app/") +
                app.id;

            if (QFileInfo::exists(userPath))
                return userPath;

            const QString systemPath =
                QStringLiteral("/var/lib/flatpak/app/") +
                app.id;

            if (QFileInfo::exists(systemPath))
                return systemPath;
        }

        const QStringList parts =
            QProcess::splitCommand(
                app.executable.trimmed());

        for (const QString &part : parts) {
            QString candidate = part.trimmed();

            if (candidate.isEmpty() ||
                candidate.startsWith(QLatin1Char('%')))
                continue;

            if (candidate.startsWith(QStringLiteral("file://")))
                candidate = candidate.mid(7);

            if (QDir::isAbsolutePath(candidate) &&
                QFileInfo::exists(candidate)) {

                return candidate;
            }
        }

        if (!app.desktopFile.trimmed().isEmpty())
            return app.desktopFile.trimmed();

        QStringList roots =
            app.installLocations;

        roots.removeAll(QString());
        roots.removeDuplicates();

        if (roots.size() == 1)
            return roots.first();

        if (!roots.isEmpty()) {
            const QStringList shown =
                roots.mid(0, 3);

            QString summary =
                QStringLiteral("System-wide (") +
                shown.join(QStringLiteral(", "));

            if (roots.size() > shown.size())
                summary += QStringLiteral(", …");

            summary += QLatin1Char(')');
            return summary;
        }

        if (app.type == ApplicationType::RPM ||
            app.systemComponent ||
            app.protectedComponent) {

            return QStringLiteral(
                "System-wide (/usr, /etc, /var…)");
        }

        return QStringLiteral("Unknown");
    }


    QVariant data(
        const QModelIndex &index,
        int role = Qt::DisplayRole) const override
    {
        if (!index.isValid() ||
            !m_applications ||
            index.row() < 0 ||
            index.row() >= m_visibleRows.size()) {

            return {};
        }

        const int sourceIndex =
            m_visibleRows.at(index.row());

        const ApplicationInfo &app =
            m_applications->at(sourceIndex);

        if (role == Qt::DisplayRole) {

            switch (index.column()) {
            case 0:
                return app.name.isEmpty()
                    ? app.id
                    : app.name;
            case 1:
                return app.packageManager;
            case 2:
                return app.version.trimmed().isEmpty()
                    ? QStringLiteral("Unknown")
                    : app.version.trimmed();
            case 3:
                return app.installedSize.isEmpty()
                    ? QStringLiteral("Unknown")
                    : app.installedSize;
            case 4:
                return installLocationFor(app);
            case 5:
                if (app.installDate.trimmed().isEmpty())
                    return QStringLiteral("Unknown");

                return app.installDateEstimated
                    ? QStringLiteral("≈ ") +
                        app.installDate.trimmed()
                    : app.installDate.trimmed();
            case 6:
                return app.description.trimmed().isEmpty()
                    ? QStringLiteral("—")
                    : app.description.trimmed();
            case 7:
                return statusFor(app);
            default:
                return {};
            }
        }

        if (role == Qt::TextAlignmentRole) {
            return static_cast<int>(
                index.column() == 3
                    ? Qt::AlignRight | Qt::AlignVCenter
                    : Qt::AlignLeft | Qt::AlignVCenter);
        }

        if (role == Qt::DecorationRole &&
            index.column() == 0) {

            return iconFor(app);
        }

        if (role == Qt::CheckStateRole &&
            index.column() == 0 &&
            isSelectable(app)) {

            return m_checked.contains(sourceIndex)
                ? Qt::Checked
                : Qt::Unchecked;
        }

        if (role == Qt::ToolTipRole) {

            QString tooltip =
                app.description.trimmed();

            const QString primaryLocation =
                installLocationFor(app);

            if (!primaryLocation.isEmpty() &&
                primaryLocation != QStringLiteral("Unknown")) {

                if (!tooltip.isEmpty())
                    tooltip += QStringLiteral("\n\n");

                tooltip +=
                    QStringLiteral("Primary location: " ) +
                    primaryLocation;
            }

            if (!app.installDate.trimmed().isEmpty()) {
                if (!tooltip.isEmpty())
                    tooltip += QStringLiteral("\n\n");

                tooltip +=
                    QStringLiteral("Install date: ") +
                    app.installDate.trimmed();

                if (app.installDateEstimated) {
                    tooltip +=
                        QStringLiteral(
                            " (estimated from filesystem metadata)");
                }
            }

            QStringList detailedLocations =
                app.installLocations;

            detailedLocations.removeAll(QString());
            detailedLocations.removeDuplicates();

            if (!detailedLocations.isEmpty()) {
                if (!tooltip.isEmpty())
                    tooltip += QStringLiteral("\n\n");

                tooltip +=
                    QStringLiteral("Installed across:");

                for (const QString &location :
                     detailedLocations.mid(0, 8)) {

                    tooltip +=
                        QStringLiteral("\n• " ) +
                        location;
                }

                if (detailedLocations.size() > 8)
                    tooltip += QStringLiteral("\n• …");
            }

            if (app.installed &&
                isManualLocal(app) &&
                !app.removable) {

                if (!tooltip.isEmpty())
                    tooltip += QStringLiteral("\n\n");

                tooltip += QStringLiteral(
                    "Removal location: not verified. TotalSweep kept this entry visible for review but will not offer destructive removal until an unambiguous unmanaged application target can be found.");
            }

            if (!app.desktopFile.isEmpty()) {
                if (!tooltip.isEmpty())
                    tooltip += QStringLiteral("\n\n");

                tooltip +=
                    QStringLiteral("Desktop launcher: " ) +
                    app.desktopFile;
            }

            return tooltip;
        }

        if (role == Qt::BackgroundRole) {

            const bool checked =
                m_checked.contains(sourceIndex);

            const bool hovered =
                index.row() == m_hoveredRow;

            if (checked || hovered) {

                QColor highlight =
                    QApplication::palette()
                        .color(QPalette::Highlight);

                highlight.setAlpha(
                    checked ? 82 : 34);

                return QBrush(highlight);
            }
        }

        if (role == Qt::UserRole)
            return sourceIndex;

        return {};
    }

    Qt::ItemFlags flags(
        const QModelIndex &index) const override
    {
        if (!index.isValid() ||
            !m_applications) {

            return Qt::NoItemFlags;
        }

        Qt::ItemFlags result =
            Qt::ItemIsEnabled |
            Qt::ItemIsSelectable;

        if (index.column() == 0) {

            const int sourceIndex =
                m_visibleRows.at(index.row());

            const ApplicationInfo &app =
                m_applications->at(sourceIndex);

            Q_UNUSED(app);
        }

        return result;
    }

    bool setData(
        const QModelIndex &index,
        const QVariant &value,
        int role = Qt::EditRole) override
    {
        if (!index.isValid() ||
            !m_applications ||
            index.column() != 0 ||
            role != Qt::CheckStateRole) {

            return false;
        }

        const int sourceIndex =
            m_visibleRows.at(index.row());

        const ApplicationInfo &app =
            m_applications->at(sourceIndex);

        if (!isSelectable(app))
            return false;

        if (value.toInt() == Qt::Checked)
            m_checked.insert(sourceIndex);
        else
            m_checked.remove(sourceIndex);

        emit dataChanged(
            this->index(index.row(), 0),
            this->index(index.row(), columnCount() - 1),
            {Qt::CheckStateRole, Qt::BackgroundRole});

        return true;
    }

    static bool isSystemInventory(
        const ApplicationInfo &app)
    {
        return app.systemComponent ||
            app.protectedComponent;
    }

    static bool isSelectable(
        const ApplicationInfo &app)
    {
        return app.removable &&
            !app.protectedComponent;
    }

    static bool isManualLocal(
        const ApplicationInfo &app)
    {
        return app.type == ApplicationType::Custom ||
            app.type == ApplicationType::AppImage ||
            app.type == ApplicationType::Script ||
            app.type == ApplicationType::Binary ||
            app.type == ApplicationType::SourceBuild;
    }


    static QString statusFor(
        const ApplicationInfo &app)
    {
        if (app.protectedComponent)
            return QStringLiteral("Protected Component");

        if (app.systemComponent &&
            app.removable) {

            return QStringLiteral(
                "System Removable — Advanced");
        }

        if (app.systemComponent)
            return QStringLiteral(
                "System / Dependency — Review");

        if (app.removable &&
            isManualLocal(app)) {

            return QStringLiteral(
                "Removable — Manual / Local");
        }

        if (app.removable)
            return QStringLiteral("Removable");

        if (app.installed &&
            isManualLocal(app)) {

            return QStringLiteral(
                "Review — Removal Location Unverified");
        }

        if (app.installed)
            return QStringLiteral("Installed / Review");

        return QStringLiteral(
            "Detected / Not Removable");
    }

private:
    const QList<ApplicationInfo> *m_applications = nullptr;
    QVector<int> m_visibleRows;
    QSet<int> m_checked;
    QString m_query;
    bool m_showSystemItems = true;
    int m_filterMode = FilterRemovableApplications;
    int m_hoveredRow = -1;
    int m_sortColumn = 0;
    Qt::SortOrder m_sortOrder = Qt::AscendingOrder;
    QVector<quint64> m_sizeBytesCache;
    QCollator m_collator;

    void rebuildSortCaches()
    {
        m_sizeBytesCache.clear();

        if (!m_applications)
            return;

        m_sizeBytesCache.reserve(
            m_applications->size());

        for (const ApplicationInfo &app :
             *m_applications) {

            m_sizeBytesCache.append(
                sizeToBytes(
                    app.installedSize));
        }
    }


    quint64 cachedSizeBytes(
        int sourceIndex) const
    {
        if (sourceIndex < 0 ||
            sourceIndex >= m_sizeBytesCache.size()) {

            return 0;
        }

        return m_sizeBytesCache.at(
            sourceIndex);
    }


    bool matchesQuery(
        const ApplicationInfo &app) const
    {
        if (m_query.isEmpty())
            return true;

        const QString status =
            statusFor(app);

        return app.name.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.id.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.description.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.packageManager.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.executable.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.desktopFile.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.installLocation.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            app.installDate.contains(
                    m_query,
                    Qt::CaseInsensitive) ||
            status.contains(
                    m_query,
                    Qt::CaseInsensitive);
    }

    bool matchesMode(
        const ApplicationInfo &app) const
    {
        const bool system =
            isSystemInventory(app);

        const bool selectable =
            isSelectable(app);

        const bool manual =
            isManualLocal(app);

        switch (m_filterMode) {
        case FilterApplications:
            return !system;

        case FilterRemovableApplications:
            return !system && selectable;

        case FilterManualLocal:
            return !system && manual;

        case FilterSystemAll:
            return system;

        case FilterSystemRemovable:
            return system &&
                selectable &&
                !app.protectedComponent;

        case FilterProtected:
            return app.protectedComponent;

        case FilterReview:
            return !app.protectedComponent &&
                !app.removable;

        case FilterAllVisible:
        default:
            break;
        }

        return true;
    }

    static quint64 sizeToBytes(
        const QString &sizeText)
    {
        const QString text =
            sizeText.trimmed();

        if (text.isEmpty() ||
            text.compare(
                QStringLiteral("Unknown"),
                Qt::CaseInsensitive) == 0) {

            return 0;
        }

        const QRegularExpression expression(
            QStringLiteral(
                R"(^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B|bytes?)?\s*$)"),
            QRegularExpression::CaseInsensitiveOption);

        const QRegularExpressionMatch match =
            expression.match(text);

        if (!match.hasMatch())
            return 0;

        bool ok = false;

        const double value =
            match.captured(1).toDouble(&ok);

        if (!ok || value < 0.0)
            return 0;

        const QString unit =
            match.captured(2).toUpper();

        double multiplier = 1.0;

        if (unit == QStringLiteral("KB"))
            multiplier = 1000.0;
        else if (unit == QStringLiteral("KIB"))
            multiplier = 1024.0;
        else if (unit == QStringLiteral("MB"))
            multiplier = 1000.0 * 1000.0;
        else if (unit == QStringLiteral("MIB"))
            multiplier = 1024.0 * 1024.0;
        else if (unit == QStringLiteral("GB"))
            multiplier = 1000.0 * 1000.0 * 1000.0;
        else if (unit == QStringLiteral("GIB"))
            multiplier = 1024.0 * 1024.0 * 1024.0;
        else if (unit == QStringLiteral("TB"))
            multiplier = 1000.0 * 1000.0 * 1000.0 * 1000.0;
        else if (unit == QStringLiteral("TIB"))
            multiplier = 1024.0 * 1024.0 * 1024.0 * 1024.0;
        else if (unit == QStringLiteral("PB"))
            multiplier = 1000.0 * 1000.0 * 1000.0 * 1000.0 * 1000.0;
        else if (unit == QStringLiteral("PIB"))
            multiplier = 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0;

        return static_cast<quint64>(
            value * multiplier);
    }


    int compareApplications(
        int leftIndex,
        int rightIndex,
        int column) const
    {
        if (!m_applications)
            return 0;

        const ApplicationInfo &left =
            m_applications->at(leftIndex);

        const ApplicationInfo &right =
            m_applications->at(rightIndex);

        QString leftText;
        QString rightText;

        switch (column) {
        case 0:
            leftText = left.name.isEmpty()
                ? left.id
                : left.name;
            rightText = right.name.isEmpty()
                ? right.id
                : right.name;
            break;

        case 1:
            leftText = left.packageManager;
            rightText = right.packageManager;
            break;

        case 2:
            leftText = left.version;
            rightText = right.version;
            break;

        case 3: {
            const quint64 leftBytes =
                cachedSizeBytes(leftIndex);

            const quint64 rightBytes =
                cachedSizeBytes(rightIndex);

            if (leftBytes < rightBytes)
                return -1;
            if (leftBytes > rightBytes)
                return 1;

            leftText = left.name.isEmpty()
                ? left.id
                : left.name;
            rightText = right.name.isEmpty()
                ? right.id
                : right.name;
            break;
        }

        case 4:
            leftText = installLocationFor(left);
            rightText = installLocationFor(right);
            break;

        case 5:
            leftText = left.installDate;
            rightText = right.installDate;
            break;

        case 6:
            leftText = left.description;
            rightText = right.description;
            break;

        case 7:
            leftText = statusFor(left);
            rightText = statusFor(right);
            break;

        default:
            break;
        }

        const int result =
            m_collator.compare(
                leftText,
                rightText);

        if (result != 0)
            return result;

        return m_collator.compare(
            left.id,
            right.id);
    }


    void applySort()
    {
        if (!m_applications ||
            m_visibleRows.size() < 2) {

            return;
        }

        const int column =
            m_sortColumn;

        const Qt::SortOrder order =
            m_sortOrder;

        std::sort(
            m_visibleRows.begin(),
            m_visibleRows.end(),
            [this, column, order](
                int leftIndex,
                int rightIndex) {

                const int comparison =
                    compareApplications(
                        leftIndex,
                        rightIndex,
                        column);

                if (order == Qt::AscendingOrder)
                    return comparison < 0;

                return comparison > 0;
            });
    }


    void rebuildVisibleRows()
    {
        m_hoveredRow = -1;
        m_visibleRows.clear();

        if (!m_applications)
            return;

        for (int i = 0;
             i < m_applications->size();
             ++i) {

            const ApplicationInfo &app =
                m_applications->at(i);

            if (!matchesMode(app) ||
                !matchesQuery(app)) {

                continue;
            }

            m_visibleRows.append(i);
        }

        applySort();
    }

    QIcon iconFor(
        const ApplicationInfo &app) const
    {
        if (isSystemInventory(app)) {

            QIcon icon =
                QIcon::fromTheme(
                    QStringLiteral(
                        "package-x-generic"));

            if (!icon.isNull())
                return icon;
        }

        QString iconName;

        if (!app.desktopFile.isEmpty() &&
            QFileInfo::exists(
                app.desktopFile)) {

            QSettings desktop(
                app.desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            iconName =
                desktop.value(
                    QStringLiteral("Icon"))
                    .toString()
                    .trimmed();

            desktop.endGroup();
        }

        if (!iconName.isEmpty()) {

            if (QFileInfo::exists(iconName)) {
                QIcon fileIcon(iconName);
                if (!fileIcon.isNull())
                    return fileIcon;
            }

            QIcon themed =
                QIcon::fromTheme(iconName);

            if (!themed.isNull())
                return themed;
        }

        QIcon generic =
            QIcon::fromTheme(
                QStringLiteral(
                    "application-x-executable"));

        return generic;
    }
};


static QColor applicationColumnSeparatorColor(
    const QPalette &palette)
{
    const QColor base =
        palette.color(
            QPalette::Base);

    const QColor mid =
        palette.color(
            QPalette::Mid);

    const QColor text =
        palette.color(
            QPalette::Text);

    if (base.lightness() < 128) {

        return QColor(
            (base.red() * 90 +
             text.red() * 10) / 100,
            (base.green() * 90 +
             text.green() * 10) / 100,
            (base.blue() * 90 +
             text.blue() * 10) / 100);
    }

    return QColor(
        (base.red() + mid.red()) / 2,
        (base.green() + mid.green()) / 2,
        (base.blue() + mid.blue()) / 2);
}


static constexpr int kSecondaryRowHoveredRole =
    Qt::UserRole + 90;


class AutoScrollTreeHeader final
    : public QHeaderView
{
public:
    explicit AutoScrollTreeHeader(
        QTreeWidget *tree)
        : QHeaderView(Qt::Horizontal, tree),
          m_tree(tree)
    {
        m_autoScrollTimer.setInterval(24);

        connect(
            &m_autoScrollTimer,
            &QTimer::timeout,
            this,
            [this]() {
                continueEdgeResize();
            });
    }

protected:
    void mousePressEvent(
        QMouseEvent *event) override
    {
        finishCustomResize();

        if (event &&
            event->button() == Qt::LeftButton) {

            const int x =
                qRound(event->position().x());

            for (int visual = 0;
                 visual < count();
                 ++visual) {

                const int logical =
                    logicalIndex(visual);

                if (logical < 0 ||
                    isSectionHidden(logical)) {
                    continue;
                }

                const int boundary =
                    sectionViewportPosition(logical) +
                    sectionSize(logical);

                if (qAbs(x - boundary) <= 7) {
                    m_resizeLogical = logical;
                    m_customResizeActive = true;
                    m_lastPointerX = x;
                    m_edgeGrowthActive = false;
                    setCursor(Qt::SplitHCursor);
                    event->accept();
                    return;
                }
            }
        }

        QHeaderView::mousePressEvent(event);
    }


    void mouseMoveEvent(
        QMouseEvent *event) override
    {
        if (!m_customResizeActive) {
            QHeaderView::mouseMoveEvent(event);
            return;
        }

        if (!event ||
            !(event->buttons() & Qt::LeftButton) ||
            m_resizeLogical < 0) {

            finishCustomResize();
            if (event)
                QHeaderView::mouseMoveEvent(event);
            return;
        }

        const int x =
            qRound(event->position().x());

        const int deltaX =
            m_lastPointerX >= 0
                ? x - m_lastPointerX
                : 0;

        m_lastPointerX = x;

        constexpr int edgeZone = 20;
        const int rightEdgeStart =
            qMax(0, width() - edgeZone);

        if (deltaX < 0) {
            stopEdgeGrowth();
            resizeActiveSectionBy(deltaX);
            event->accept();
            return;
        }

        if (deltaX > 0)
            resizeActiveSectionBy(deltaX);

        if (x >= rightEdgeStart &&
            deltaX >= 0) {

            m_edgeGrowthActive = true;

            if (!m_autoScrollTimer.isActive())
                m_autoScrollTimer.start();
        }
        else {
            stopEdgeGrowth();
        }

        event->accept();
    }


    void mouseReleaseEvent(
        QMouseEvent *event) override
    {
        if (m_customResizeActive) {
            finishCustomResize();
            if (event)
                event->accept();
            return;
        }

        QHeaderView::mouseReleaseEvent(event);
    }


    void leaveEvent(
        QEvent *event) override
    {
        if (m_customResizeActive &&
            !(QApplication::mouseButtons() & Qt::LeftButton)) {

            finishCustomResize();
        }

        QHeaderView::leaveEvent(event);
    }

private:
    void resizeActiveSectionBy(
        int delta)
    {
        if (m_resizeLogical < 0 ||
            delta == 0) {
            return;
        }

        const int currentWidth =
            sectionSize(m_resizeLogical);

        const int nextWidth =
            qMax(
                minimumSectionSize(),
                currentWidth + delta);

        if (nextWidth != currentWidth)
            resizeSection(m_resizeLogical, nextWidth);
    }


    void stopEdgeGrowth()
    {
        m_edgeGrowthActive = false;
        m_autoScrollTimer.stop();
    }


    void finishCustomResize()
    {
        stopEdgeGrowth();
        m_customResizeActive = false;
        m_resizeLogical = -1;
        m_lastPointerX = -1;
        unsetCursor();
    }


    void continueEdgeResize()
    {
        if (!m_tree ||
            !m_customResizeActive ||
            !m_edgeGrowthActive ||
            m_resizeLogical < 0 ||
            !(QApplication::mouseButtons() & Qt::LeftButton)) {

            if (!(QApplication::mouseButtons() & Qt::LeftButton))
                finishCustomResize();
            else
                stopEdgeGrowth();
            return;
        }

        QScrollBar *bar =
            m_tree->horizontalScrollBar();

        if (!bar) {
            stopEdgeGrowth();
            return;
        }

        constexpr int growStep = 14;

        const int oldWidth =
            sectionSize(m_resizeLogical);

        resizeSection(
            m_resizeLogical,
            oldWidth + growStep);

        bar->setValue(
            bar->value() + growStep);
    }

    QTreeWidget *m_tree{};
    QTimer m_autoScrollTimer;
    int m_resizeLogical = -1;
    int m_lastPointerX = -1;
    bool m_customResizeActive = false;
    bool m_edgeGrowthActive = false;
};

class EmptyStateTreeWidget final
    : public QTreeWidget
{
public:
    explicit EmptyStateTreeWidget(
        QWidget *parent = nullptr)
        : QTreeWidget(parent)
    {
        setHeader(
            new AutoScrollTreeHeader(this));
    }

    void setColumnSeparatorsEnabled(
        bool enabled)
    {
        if (m_columnSeparatorsEnabled == enabled)
            return;

        m_columnSeparatorsEnabled = enabled;
        if (viewport())
            viewport()->update();
    }

    void setRowSeparatorsEnabled(
        bool enabled)
    {
        if (m_rowSeparatorsEnabled == enabled)
            return;

        m_rowSeparatorsEnabled = enabled;
        if (viewport())
            viewport()->update();
    }

    void setEmptyMessage(
        const QString &message)
    {
        if (m_emptyMessage == message)
            return;

        m_emptyMessage = message;

        if (viewport())
            viewport()->update();
    }

protected:
    void drawRow(
        QPainter *painter,
        const QStyleOptionViewItem &option,
        const QModelIndex &index) const override
    {
        QStyleOptionViewItem paintedOption(
            option);

        QTreeWidgetItem *item =
            itemFromIndex(index);

        const Qt::CheckState state =
            item &&
            (item->flags() & Qt::ItemIsUserCheckable)
                ? item->checkState(0)
                : Qt::Unchecked;

        const bool checked =
            state != Qt::Unchecked;

        const bool hovered =
            item &&
            item->data(
                0,
                kSecondaryRowHoveredRole)
                .toBool();

        paintedOption.state &=
            ~QStyle::State_Selected;

        if (checked || hovered) {
            paintedOption.features &=
                ~QStyleOptionViewItem::Alternate;
        }

        QTreeWidget::drawRow(
            painter,
            paintedOption,
            index);

        if (checked || hovered) {
            QColor highlight =
                palette().color(
                    QPalette::Highlight);

            const int alpha = checked
                ? (state == Qt::PartiallyChecked ? 58 : 72)
                : 28;

            highlight.setAlpha(alpha);

            painter->save();
            painter->fillRect(
                QRect(
                    0,
                    option.rect.top(),
                    viewport()
                        ? viewport()->width()
                        : option.rect.width(),
                    option.rect.height()),
                highlight);
            painter->restore();
        }
    }


    void paintEvent(
        QPaintEvent *event) override
    {
        QTreeWidget::paintEvent(event);

        if (!viewport())
            return;

        bool hasVisibleItems = false;

        for (int i = 0;
             i < topLevelItemCount();
             ++i) {

            QTreeWidgetItem *item =
                topLevelItem(i);

            if (item && !item->isHidden()) {
                hasVisibleItems = true;
                break;
            }
        }

        if (!hasVisibleItems &&
            !m_emptyMessage.isEmpty()) {

            QPainter emptyPainter(viewport());
            emptyPainter.setPen(
                viewport()->palette().color(
                    QPalette::PlaceholderText));

            emptyPainter.drawText(
                viewport()->rect().adjusted(
                    24,
                    24,
                    -24,
                    -24),
                Qt::AlignCenter |
                Qt::TextWordWrap,
                m_emptyMessage);
        }

        if ((!m_columnSeparatorsEnabled &&
             !m_rowSeparatorsEnabled) ||
            !header()) {
            return;
        }

        QPainter painter(viewport());
        painter.setRenderHint(
            QPainter::Antialiasing,
            false);

        QPen pen(
            applicationColumnSeparatorColor(
                viewport()->palette()));
        pen.setWidth(0);
        pen.setCosmetic(true);
        painter.setPen(pen);

        if (m_columnSeparatorsEnabled) {
            QVector<int> visibleColumns;
            visibleColumns.reserve(header()->count());

            for (int visual = 0;
                 visual < header()->count();
                 ++visual) {

                const int logical =
                    header()->logicalIndex(visual);

                if (logical < 0 ||
                    isColumnHidden(logical)) {
                    continue;
                }

                visibleColumns.append(logical);
            }

            const int bottom =
                qMax(0, viewport()->height() - 1);

            for (int i = 0;
                 i < visibleColumns.size() - 1;
                 ++i) {

                const int logical =
                    visibleColumns.at(i);
                const int x =
                    header()->sectionViewportPosition(logical) +
                    header()->sectionSize(logical) - 1;

                if (x >= 0 &&
                    x < viewport()->width()) {
                    painter.drawLine(x, 0, x, bottom);
                }
            }
        }

        if (m_rowSeparatorsEnabled && hasVisibleItems) {
            QTreeWidgetItemIterator iterator(this);
            while (*iterator) {
                QTreeWidgetItem *item = *iterator;
                ++iterator;

                if (!item || item->isHidden())
                    continue;

                const QRect rect = visualItemRect(item);
                if (!rect.isValid() ||
                    rect.bottom() < 0 ||
                    rect.top() >= viewport()->height()) {
                    continue;
                }

                const int y = rect.bottom();
                if (y >= 0 && y < viewport()->height()) {
                    painter.drawLine(
                        0,
                        y,
                        qMax(0, viewport()->width() - 1),
                        y);
                }
            }
        }
    }

private:
    bool m_columnSeparatorsEnabled = false;
    bool m_rowSeparatorsEnabled = false;
    QString m_emptyMessage;
};

class AutoScrollApplicationHeader final
    : public QHeaderView
{
public:
    explicit AutoScrollApplicationHeader(
        QTableView *table)
        : QHeaderView(Qt::Horizontal, table),
          m_table(table)
    {
        m_autoScrollTimer.setInterval(24);

        connect(
            &m_autoScrollTimer,
            &QTimer::timeout,
            this,
            [this]() {
                continueEdgeResize();
            });
    }

protected:
    void mousePressEvent(
        QMouseEvent *event) override
    {
        finishCustomResize();

        if (event &&
            event->button() == Qt::LeftButton) {

            const int x =
                qRound(event->position().x());

            for (int visual = 0;
                 visual < count();
                 ++visual) {

                const int logical =
                    logicalIndex(visual);

                if (logical != 4 &&
                    logical != 6) {

                    continue;
                }

                const int boundary =
                    sectionViewportPosition(logical) +
                    sectionSize(logical);

                if (qAbs(x - boundary) <= 7) {
                    m_resizeLogical = logical;
                    m_customResizeActive = true;
                    m_lastPointerX = x;
                    m_edgeGrowthActive = false;
                    setCursor(Qt::SplitHCursor);
                    event->accept();
                    return;
                }
            }
        }

        QHeaderView::mousePressEvent(event);
    }


    void mouseMoveEvent(
        QMouseEvent *event) override
    {
        if (!m_customResizeActive) {
            QHeaderView::mouseMoveEvent(event);
            return;
        }

        if (!event ||
            !(event->buttons() & Qt::LeftButton) ||
            m_resizeLogical < 0) {

            finishCustomResize();
            if (event)
                QHeaderView::mouseMoveEvent(event);
            return;
        }

        const int x =
            qRound(event->position().x());

        const int deltaX =
            m_lastPointerX >= 0
                ? x - m_lastPointerX
                : 0;

        m_lastPointerX = x;

        constexpr int edgeZone = 20;
        const int rightEdgeStart =
            qMax(0, width() - edgeZone);

        if (deltaX < 0) {
            stopEdgeGrowth();
            resizeLongSectionBy(deltaX);
            event->accept();
            return;
        }

        if (deltaX > 0)
            resizeLongSectionBy(deltaX);

        if (x >= rightEdgeStart) {
            m_edgeGrowthActive = true;
            if (!m_autoScrollTimer.isActive())
                m_autoScrollTimer.start();
        }
        else {
            stopEdgeGrowth();
        }

        event->accept();
    }


    void mouseReleaseEvent(
        QMouseEvent *event) override
    {
        if (m_customResizeActive) {
            finishCustomResize();
            if (event)
                event->accept();
            return;
        }

        QHeaderView::mouseReleaseEvent(event);
    }


    void leaveEvent(
        QEvent *event) override
    {
        if (m_customResizeActive &&
            !(QApplication::mouseButtons() & Qt::LeftButton)) {

            finishCustomResize();
        }

        QHeaderView::leaveEvent(event);
    }

private:
    void resizeLongSectionBy(
        int delta)
    {
        if (m_resizeLogical < 0 ||
            delta == 0) {

            return;
        }

        const int currentWidth =
            sectionSize(m_resizeLogical);

        const int nextWidth =
            qMax(
                minimumSectionSize(),
                currentWidth + delta);

        if (nextWidth != currentWidth)
            resizeSection(m_resizeLogical, nextWidth);
    }


    void stopEdgeGrowth()
    {
        m_edgeGrowthActive = false;
        m_autoScrollTimer.stop();
    }


    void finishCustomResize()
    {
        stopEdgeGrowth();
        m_customResizeActive = false;
        m_resizeLogical = -1;
        m_lastPointerX = -1;
        unsetCursor();
    }


    void continueEdgeResize()
    {
        if (!m_table ||
            !m_customResizeActive ||
            !m_edgeGrowthActive ||
            m_resizeLogical < 0 ||
            !(QApplication::mouseButtons() & Qt::LeftButton)) {

            if (!(QApplication::mouseButtons() & Qt::LeftButton))
                finishCustomResize();
            else
                stopEdgeGrowth();
            return;
        }

        QScrollBar *bar =
            m_table->horizontalScrollBar();

        if (!bar) {
            stopEdgeGrowth();
            return;
        }

        constexpr int growStep = 14;

        const int oldWidth =
            sectionSize(m_resizeLogical);

        resizeSection(
            m_resizeLogical,
            oldWidth + growStep);

        bar->setValue(
            bar->value() + growStep);
    }

    QTableView *m_table{};
    QTimer m_autoScrollTimer;
    int m_resizeLogical = -1;
    int m_lastPointerX = -1;
    bool m_customResizeActive = false;
    bool m_edgeGrowthActive = false;
};

class ApplicationTableView final
    : public QTableView
{
public:
    explicit ApplicationTableView(
        QWidget *parent = nullptr)
        : QTableView(parent)
    {
    }

    void setColumnSeparatorsEnabled(
        bool enabled)
    {
        if (m_columnSeparatorsEnabled == enabled)
            return;

        m_columnSeparatorsEnabled = enabled;

        if (viewport())
            viewport()->update();
    }

    void setRowSeparatorsEnabled(
        bool enabled)
    {
        if (m_rowSeparatorsEnabled == enabled)
            return;

        m_rowSeparatorsEnabled = enabled;

        if (viewport())
            viewport()->update();
    }

    void setEmptyMessage(
        const QString &message)
    {
        if (m_emptyMessage == message)
            return;

        m_emptyMessage = message;

        if (viewport())
            viewport()->update();
    }

protected:
    void paintEvent(
        QPaintEvent *event) override
    {
        QTableView::paintEvent(event);

        if (viewport() &&
            model() &&
            model()->rowCount() == 0 &&
            !m_emptyMessage.isEmpty()) {

            QPainter emptyPainter(viewport());
            emptyPainter.setPen(
                viewport()->palette().color(
                    QPalette::PlaceholderText));

            emptyPainter.drawText(
                viewport()->rect().adjusted(
                    24,
                    24,
                    -24,
                    -24),
                Qt::AlignCenter |
                Qt::TextWordWrap,
                m_emptyMessage);
        }

        if ((!m_columnSeparatorsEnabled &&
             !m_rowSeparatorsEnabled) ||
            !viewport() ||
            !horizontalHeader()) {

            return;
        }

        QHeaderView *header =
            horizontalHeader();

        QPainter painter(viewport());
        painter.setRenderHint(
            QPainter::Antialiasing,
            false);

        QPen pen(
            applicationColumnSeparatorColor(
                viewport()->palette()));
        pen.setWidth(0);
        pen.setCosmetic(true);
        painter.setPen(pen);

        if (m_columnSeparatorsEnabled) {
            QVector<int> visibleColumns;
            visibleColumns.reserve(
                header->count());

            for (int visual = 0;
                 visual < header->count();
                 ++visual) {

                const int logical =
                    header->logicalIndex(visual);

                if (logical < 0 ||
                    isColumnHidden(logical)) {

                    continue;
                }

                visibleColumns.append(logical);
            }

            if (visibleColumns.size() >= 2) {
                const int bottom =
                    qMax(0,
                         viewport()->height() - 1);

                for (int i = 0;
                     i < visibleColumns.size() - 1;
                     ++i) {

                    const int logical =
                        visibleColumns.at(i);

                    const int position =
                        header->sectionViewportPosition(
                            logical);

                    const int width =
                        header->sectionSize(
                            logical);

                    const int x =
                        position + width - 1;

                    if (x < 0 ||
                        x >= viewport()->width()) {

                        continue;
                    }

                    painter.drawLine(
                        x,
                        0,
                        x,
                        bottom);
                }
            }
        }

        if (m_rowSeparatorsEnabled && model()) {
            const int right =
                qMax(0, viewport()->width() - 1);

            for (int row = 0;
                 row < model()->rowCount();
                 ++row) {

                const QModelIndex index =
                    model()->index(row, 0);
                const QRect rect =
                    visualRect(index);

                if (!rect.isValid() ||
                    rect.bottom() < 0 ||
                    rect.top() >= viewport()->height()) {
                    continue;
                }

                painter.drawLine(
                    0,
                    rect.bottom(),
                    right,
                    rect.bottom());
            }
        }
    }

private:
    bool m_columnSeparatorsEnabled = false;
    bool m_rowSeparatorsEnabled = false;
    QString m_emptyMessage;
};


class ApplicationTableDelegate final
    : public QStyledItemDelegate
{
public:
    explicit ApplicationTableDelegate(
        QTableView *view)
        : QStyledItemDelegate(view)
    {
    }

    void paint(
        QPainter *painter,
        const QStyleOptionViewItem &option,
        const QModelIndex &index) const override
    {
        QStyleOptionViewItem paintedOption(
            option);

        paintedOption.state &=
            ~QStyle::State_HasFocus;

        QStyledItemDelegate::paint(
            painter,
            paintedOption,
            index);
    }
};

class Window final : public QWidget
{
public:

    Window()
    {
        setWindowTitle("TotalSweep Uninstaller");

        const QIcon appIcon = totalSweepIcon();
        setWindowIcon(appIcon);
        QApplication::setWindowIcon(appIcon);

        resize(1250, 820);

        settings =
        new QSettings(
            QSettings::NativeFormat,
            QSettings::UserScope,
            "TotalSweep",
            "Uninstaller");

        const bool firstEverLaunch =
            settings->allKeys().isEmpty();

        if (firstEverLaunch)
            initializeFirstLaunchPresentationPreferences();

        loadRestorePreferences();
        loadViewPreferences();

        backendManager.registerBackend(new RpmBackend);
        backendManager.registerBackend(new FlatpakBackend);

        buildInterface();

        if (firstEverLaunch)
            applyFirstLaunchPresentationProfile();

        refreshMonochromeIcons();

        qApp->installEventFilter(this);

        restoreWindowState();
        loadApplicationCache();
        scheduleFirstRunExperience();

        QTimer::singleShot(
            100,
            this,
            [this]() {
                refreshApplications();
            });
    }

protected:

    void closeEvent(QCloseEvent *event) override
    {
        saveHeader();
        saveQuarantineHeader();
        saveApplicationHeader();
        saveWindowState();

        QWidget::closeEvent(event);
    }

    void restoreWindowState()
    {
        if (!settings)
            return;

        const QString platformName =
            QGuiApplication::platformName()
                .toLower();

        const bool nativeWayland =
            platformName.contains(
                QStringLiteral("wayland"));

        const QByteArray savedGeometry =
            settings->value(
                "window/geometry")
                .toByteArray();

        if (!nativeWayland &&
            !savedGeometry.isEmpty()) {

            restoreGeometry(
                savedGeometry);
        }

        const QRect normalRect =
            settings->value(
                "window/normalGeometry")
                .toRect();

        const bool normalRectValid =
            normalRect.isValid() &&
            normalRect.width() >= 640 &&
            normalRect.height() >= 480;

        const QVariant maximizedValue =
            settings->value(
                "window/maximized");

        if (!maximizedValue.isValid()) {
            QTimer::singleShot(
                0,
                this,
                [this]() {
                    showMaximized();
                });

            return;
        }

        if (maximizedValue.toBool()) {
            QTimer::singleShot(
                0,
                this,
                [this]() {
                    showMaximized();
                });

            return;
        }

        setWindowState(
            windowState() &
            ~Qt::WindowMaximized);

        if (!normalRectValid)
            return;

        resize(
            normalRect.size());

        if (!nativeWayland) {
            move(
                normalRect.topLeft());
        }

        QTimer::singleShot(
            0,
            this,
            [this, normalRect, nativeWayland]() {

                if (isMaximized())
                    return;

                resize(
                    normalRect.size());

                if (!nativeWayland) {
                    move(
                        normalRect.topLeft());
                }
            });
    }


    void scheduleFirstRunExperience()
    {
        if (!settings)
            return;

        if (settings->value(
                "onboarding/welcomeV4DontShowAgain",
                false)
                .toBool()) {

            return;
        }

        QTimer::singleShot(
            250,
            this,
            [this]() {
                showFirstRunSafetyWarning();
            });
    }


    void showFirstRunSafetyWarning()
    {
        if (!settings ||
            settings->value(
                "onboarding/welcomeV4DontShowAgain",
                false)
                .toBool()) {

            return;
        }

        QMessageBox box(this);

        box.setIcon(
            QMessageBox::Information);

        box.setWindowTitle(
            QStringLiteral(
                "Welcome to TotalSweep"));

        box.setText(
            QStringLiteral(
                "<b>An easier way to uninstall applications and clean up what they leave behind.</b>"));

        box.setInformativeText(
            QStringLiteral(
                "TotalSweep is made for people new to Linux and anyone who prefers a "
                "straightforward GUI over managing packages, files, and terminal commands manually. "
                "The same tasks can be performed with standard Linux tools—TotalSweep simply brings "
                "them together and makes them easier and safer to manage.<br><br>"
                "<b>Restore Protection gives you a safety net.</b> For supported removals, TotalSweep "
                "preserves restore information and can move manual-app files and leftovers into a "
                "separate Quarantine location instead of permanently deleting them.<br><br>"
                "From the <b>Quarantine</b> tab, you can restore something if removing it unexpectedly "
                "affects another application or system function, or permanently delete it once you know "
                "everything is working properly. This can save you from performing a much larger system "
                "rollback just to recover one removed item.<br><br>"
                "<b>If you’re unsure what you’re removing, leave Restore Protection enabled.</b> "
                "If you know what you’re doing, you can turn it off for permanent removal—but understand "
                "that TotalSweep may no longer be able to restore something you delete by mistake."));

        auto *doNotShowAgain =
            new QCheckBox(
                QStringLiteral(
                    "Do not show this again"),
                &box);

        box.setCheckBox(
            doNotShowAgain);

        QPushButton *continueButton =
            box.addButton(
                QStringLiteral("Continue"),
                QMessageBox::AcceptRole);

        box.setDefaultButton(
            continueButton);

        prepareMessageBox(box);
        box.exec();

        if (box.clickedButton() ==
            continueButton) {

            settings->setValue(
                "onboarding/welcomeV4DontShowAgain",
                doNotShowAgain->isChecked());
        }

        settings->sync();
    }


    void saveWindowState()
    {
        if (!settings)
            return;

        QRect normalRect;

        if (!isMaximized()) {
            normalRect = geometry();
        }
        else {
            normalRect = normalGeometry();
        }

        if (!normalRect.isValid())
            normalRect = geometry();

        settings->setValue(
            "window/normalGeometry",
            normalRect);

        settings->setValue(
            "window/maximized",
            isMaximized());

        settings->setValue(
            "window/geometry",
            saveGeometry());

        settings->sync();
    }


    bool eventFilter(
        QObject *watched,
        QEvent *event) override
    {
        if (applicationView &&
            watched == applicationView->viewport() &&
            event->type() == QEvent::Leave) {

            if (applicationModel)
                applicationModel->setHoveredRow(-1);
        }

        if (results &&
            watched == results->viewport() &&
            event->type() == QEvent::Leave) {

            setHoveredLeftoverItem(nullptr);
        }

        if (historyTree &&
            watched == historyTree->viewport() &&
            event->type() == QEvent::Leave) {

            setHoveredQuarantineItem(nullptr);
        }

        if (watched == qApp &&
            event->type() ==
                QEvent::ApplicationPaletteChange) {

            QTimer::singleShot(
                0,
                this,
                [this]() {
                    refreshApplicationTheme();
                    refreshSecondaryTreeVisuals();
                });
        }

        if (event->type() == QEvent::KeyPress &&
            isActiveWindow() &&
            !QApplication::activeModalWidget() &&
            !QApplication::activePopupWidget()) {

            auto *keyEvent =
                static_cast<QKeyEvent *>(event);

            const Qt::KeyboardModifiers modifiers =
                keyEvent->modifiers();

            const bool shortcutModifier =
                modifiers.testFlag(Qt::ControlModifier) ||
                modifiers.testFlag(Qt::AltModifier) ||
                modifiers.testFlag(Qt::MetaModifier);

            QWidget *focus =
                QApplication::focusWidget();

            const bool editingText =
                focus &&
                (qobject_cast<QLineEdit *>(focus) ||
                 focus->inherits("QTextEdit") ||
                 focus->inherits("QPlainTextEdit") ||
                 focus->inherits("QAbstractSpinBox"));

            const QString typed =
                keyEvent->text();

            bool printable =
                !typed.isEmpty() &&
                !typed.trimmed().isEmpty();

            for (const QChar character : typed) {
                if (!character.isPrint()) {
                    printable = false;
                    break;
                }
            }

            if (!shortcutModifier &&
                !editingText &&
                printable) {

                if (QLineEdit *field =
                        activeSearchField()) {

                    if (field->isEnabled() &&
                        field->isVisible()) {

                        field->setFocus(
                            Qt::ShortcutFocusReason);

                        if (!field->hasSelectedText())
                            field->setCursorPosition(
                                field->text().size());

                        field->insert(typed);
                        event->accept();
                        return true;
                    }
                }
            }
        }

        return QWidget::eventFilter(
            watched,
            event);
    }

private:

    ApplicationBackendManager backendManager;

    ApplicationLibrary applicationLibrary{
        &backendManager
    };

    QSettings *settings{};
    totalsweep_restore::RestorePolicy restorePreferences;
    bool autoSelectRecommendedLeftovers = true;

    QLineEdit *search{};
    QLineEdit *leftoversSearch{};
    QLineEdit *quarantineSearch{};

    QTimer *uninstallSearchDebounce{};
    QTimer *leftoversSearchDebounce{};
    QTimer *quarantineSearchDebounce{};


    QButtonGroup *navigationGroup{};
    QPushButton *uninstallNavButton{};
    QPushButton *leftoversNavButton{};
    QPushButton *quarantineNavButton{};
    QPushButton *advancedSettingsButton{};
    QLabel *titleIconLabel{};
    QStackedWidget *pages{};

    QWidget *uninstallTab{};
    QWidget *leftoversTab{};
    QWidget *historyTab{};

    ApplicationTableView *applicationView{};
    ApplicationTableDelegate *applicationTableDelegate{};
    QPushButton *pageRefreshBtn{};
    QPushButton *pageOptionsBtn{};
    QMenu *applicationColumnsMenu{};
    QMenu *applicationColumnsSubmenu{};
    QMenu *applicationSeparatorsSubmenu{};
    QMap<int, QCheckBox *> applicationColumnChecks;
    QCheckBox *applicationSeparatorsCheck{};
    QCheckBox *applicationRowSeparatorsCheck{};
    QAction *applicationResetColumnsAction{};
    bool applicationColumnSeparators = true;
    bool applicationRowSeparators = true;
    ApplicationTableModel *applicationModel{};
    QButtonGroup *applicationFilterGroup{};
    QLabel *applicationStatus{};
    QLabel *installInfo{};

    QPushButton *clearApplicationsBtn{};
    QPushButton *uninstallSelectedBtn{};
    QPushButton *showSystemItemsBtn{};

    EmptyStateTreeWidget *results{};
    QLabel *resultStatus{};
    QProgressBar *scanProgress{};
    QPushButton *cancelLeftoverScanBtn{};
    QPushButton *openLeftoverLocationBtn{};
    QPushButton *quarantineSelectedBtn{};
    QMenu *leftoversViewMenu{};
    QMenu *leftoversColumnsSubmenu{};
    QMenu *leftoversSeparatorsSubmenu{};
    QMap<int, QCheckBox *> leftoversColumnChecks;
    QCheckBox *leftoversColumnSeparatorsCheck{};
    QCheckBox *leftoversRowSeparatorsCheck{};
    bool leftoversColumnSeparators = true;
    bool leftoversRowSeparators = true;
    QTreeWidgetItem *pressedLeftoverItem{};
    Qt::CheckState pressedLeftoverCheckState = Qt::Unchecked;
    QTreeWidgetItem *hoveredLeftoverItem{};

    EmptyStateTreeWidget *historyTree{};
    QLabel *quarantineInfoLabel{};
    QPushButton *clearQuarantineSelectionBtn{};
    QPushButton *openQuarantineBtn{};
    QPushButton *restoreQuarantineBtn{};
    QPushButton *deleteQuarantineBtn{};
    QMenu *quarantineViewMenu{};
    QTreeWidgetItem *pressedQuarantineItem{};
    Qt::CheckState pressedQuarantineCheckState = Qt::Unchecked;
    QTreeWidgetItem *hoveredQuarantineItem{};
    QMenu *quarantineColumnsSubmenu{};
    QMenu *quarantineSeparatorsSubmenu{};
    QMap<int, QCheckBox *> quarantineColumnChecks;
    QCheckBox *quarantineColumnSeparatorsCheck{};
    QCheckBox *quarantineRowSeparatorsCheck{};
    bool quarantineColumnSeparators = true;
    bool quarantineRowSeparators = true;

    QString currentApp;
    QStringList activeLeftoverSearchTerms;
    QStringList protectedOtherApplicationRoots;

    QVector<Hit> hits;

    QList<ApplicationInfo> currentApplications;
    QList<ApplicationInfo> allApplications;

    QString committedApplicationSearch;
    QString committedQuarantineSearch;


    bool showSystemItems = true;
    bool applicationInventoryLoaded = false;
    bool applicationDataFresh = false;
    bool applicationRefreshRunning = false;
    bool searchRunning = false;
    bool leftoverScanRunning = false;

    QProcess *leftoverHomeProcess{};
    QProcess *leftoverSystemProcess{};

    QStringList homeScanResults;
    QStringList systemScanResults;

    QVector<PendingLeftoverItem> pendingLeftoverItems;
    int pendingLeftoverIndex = 0;
    int leftoverScanGeneration = 0;
    int completedScanProcesses = 0;
    bool postUninstallLeftoverScan = false;
    QString postUninstallLeftoverDisplayName;

    QList<ApplicationInfo> pendingPostUninstallLeftoverApps;
    int postUninstallBatchTotal = 0;
    int postUninstallBatchCompleted = 0;
    int postUninstallBatchResultCount = 0;
    int postUninstallBatchSkipped = 0;
    bool postUninstallBatchActive = false;
    QTreeWidgetItem *activePostUninstallAppGroup{};

private:

    static bool isManualLocal(
        const ApplicationInfo &app)
    {
        return app.type == ApplicationType::Custom ||
            app.type == ApplicationType::AppImage ||
            app.type == ApplicationType::Script ||
            app.type == ApplicationType::Binary ||
            app.type == ApplicationType::SourceBuild;
    }

    static totalsweep_restore::AppKind restoreKindFor(
        const ApplicationInfo &app)
    {
        if (app.type == ApplicationType::RPM)
            return totalsweep_restore::AppKind::Rpm;
        if (app.type == ApplicationType::Flatpak)
            return totalsweep_restore::AppKind::Flatpak;
        if (app.type == ApplicationType::AppImage)
            return totalsweep_restore::AppKind::AppImage;
        if (app.type == ApplicationType::Script)
            return totalsweep_restore::AppKind::Script;
        if (app.type == ApplicationType::Binary)
            return totalsweep_restore::AppKind::Binary;
        if (app.type == ApplicationType::SourceBuild)
            return totalsweep_restore::AppKind::SourceBuild;
        return totalsweep_restore::AppKind::Custom;
    }

    static QString restoreTypeLabel(
        const ApplicationInfo &app)
    {
        return QString::fromLatin1(
            totalsweep_restore::kindLabel(
                restoreKindFor(app)));
    }

    struct PreparedRestore {
        QJsonObject metadata;
        bool exactAvailable = false;
        bool snapshotAttempted = false;
        bool snapshotDisabled = false;
        QString warning;
    };

    struct ManualRemovalPlan {
        QStringList paths;
        QString primary;
        QString resolution;
        bool ambiguous = false;

        bool resolved() const
        {
            return !primary.isEmpty() &&
                !paths.isEmpty() &&
                !ambiguous;
        }
    };

    void initializeFirstLaunchPresentationPreferences()
    {
        if (!settings)
            return;

        settings->setValue(
            QStringLiteral("applications/columnSeparators"),
            false);
        settings->setValue(
            QStringLiteral("applications/rowSeparators"),
            false);
        settings->setValue(
            QStringLiteral("leftovers/columnSeparators"),
            false);
        settings->setValue(
            QStringLiteral("leftovers/rowSeparators"),
            false);
        settings->setValue(
            QStringLiteral("quarantine/columnSeparators"),
            false);
        settings->setValue(
            QStringLiteral("quarantine/rowSeparators"),
            false);

        settings->setValue(
            QStringLiteral("applications/startupFilter"),
            FilterRemovableApplications);

        settings->setValue(
            QStringLiteral("window/maximized"),
            true);

        settings->setValue(
            QStringLiteral("onboarding/initialPresentationConfigured"),
            true);

        settings->sync();
    }


    void applyFirstLaunchPresentationProfile()
    {
        applyRecommendedApplicationHeaderLayout(true);
        applyRecommendedLeftoversHeaderLayout(true);
        applyRecommendedQuarantineHeaderLayout(true);

        if (applicationView) {
            applicationView->setColumnSeparatorsEnabled(false);
            applicationView->setRowSeparatorsEnabled(false);
        }

        if (results) {
            results->setColumnSeparatorsEnabled(false);
            results->setRowSeparatorsEnabled(false);
        }

        if (historyTree) {
            historyTree->setColumnSeparatorsEnabled(false);
            historyTree->setRowSeparatorsEnabled(false);
        }

        if (applicationSeparatorsCheck) {
            const QSignalBlocker blocker(
                applicationSeparatorsCheck);
            applicationSeparatorsCheck->setChecked(false);
        }

        if (applicationRowSeparatorsCheck) {
            const QSignalBlocker blocker(
                applicationRowSeparatorsCheck);
            applicationRowSeparatorsCheck->setChecked(false);
        }

        if (leftoversColumnSeparatorsCheck) {
            const QSignalBlocker blocker(
                leftoversColumnSeparatorsCheck);
            leftoversColumnSeparatorsCheck->setChecked(false);
        }

        if (leftoversRowSeparatorsCheck) {
            const QSignalBlocker blocker(
                leftoversRowSeparatorsCheck);
            leftoversRowSeparatorsCheck->setChecked(false);
        }

        if (quarantineColumnSeparatorsCheck) {
            const QSignalBlocker blocker(
                quarantineColumnSeparatorsCheck);
            quarantineColumnSeparatorsCheck->setChecked(false);
        }

        if (quarantineRowSeparatorsCheck) {
            const QSignalBlocker blocker(
                quarantineRowSeparatorsCheck);
            quarantineRowSeparatorsCheck->setChecked(false);
        }

        applicationColumnSeparators = false;
        applicationRowSeparators = false;
        leftoversColumnSeparators = false;
        leftoversRowSeparators = false;
        quarantineColumnSeparators = false;
        quarantineRowSeparators = false;

        if (applicationFilterGroup) {
            if (QAbstractButton *removableButton =
                    applicationFilterGroup->button(
                        FilterRemovableApplications)) {

                removableButton->setChecked(true);
            }
        }

        if (applicationModel) {
            applicationModel->setFilterMode(
                FilterRemovableApplications);
        }

        setCurrentPage(0);
        updateApplicationStatus();

        if (settings)
            settings->sync();
    }


    void loadViewPreferences()
    {
        if (!settings)
            return;

        applicationColumnSeparators = settings->value(
            QStringLiteral("applications/columnSeparators"), true).toBool();
        applicationRowSeparators = settings->value(
            QStringLiteral("applications/rowSeparators"), true).toBool();
        leftoversColumnSeparators = settings->value(
            QStringLiteral("leftovers/columnSeparators"), true).toBool();
        leftoversRowSeparators = settings->value(
            QStringLiteral("leftovers/rowSeparators"), true).toBool();
        quarantineColumnSeparators = settings->value(
            QStringLiteral("quarantine/columnSeparators"), true).toBool();
        quarantineRowSeparators = settings->value(
            QStringLiteral("quarantine/rowSeparators"), true).toBool();
    }


    void loadRestorePreferences()
    {
        if (!settings)
            return;

        restorePreferences.restoreProtection = settings->value(
            QStringLiteral("advanced/restoreProtection"), true).toBool();
        restorePreferences.trackApplicationUninstalls = settings->value(
            QStringLiteral("advanced/trackApplicationUninstalls"), true).toBool();
        restorePreferences.preserveExactPackagePayloads = settings->value(
            QStringLiteral("advanced/preserveExactPackagePayloads"), true).toBool();
        restorePreferences.quarantineManualApplications = settings->value(
            QStringLiteral("advanced/quarantineManualApplications"), true).toBool();
        restorePreferences.quarantineLeftovers = settings->value(
            QStringLiteral("advanced/quarantineLeftovers"), true).toBool();
        restorePreferences.keepMetadataOnlyRecords = settings->value(
            QStringLiteral("advanced/keepMetadataOnlyRecords"), true).toBool();
        restorePreferences.preserveFlatpakUserData = settings->value(
            QStringLiteral("advanced/preserveFlatpakUserData"), true).toBool();
        restorePreferences.autoScanLeftoversAfterUninstall = settings->value(
            QStringLiteral("advanced/autoScanLeftoversAfterUninstall"), true).toBool();
        restorePreferences.warnWhenSnapshotUnavailable = settings->value(
            QStringLiteral("advanced/warnWhenSnapshotUnavailable"), true).toBool();
        restorePreferences.offerCurrentVersionFallback = settings->value(
            QStringLiteral("advanced/offerCurrentVersionFallback"), true).toBool();
        autoSelectRecommendedLeftovers = settings->value(
            QStringLiteral("advanced/autoSelectRecommendedLeftovers"), true).toBool();
    }


    void saveRestorePreferences()
    {
        if (!settings)
            return;

        settings->setValue(
            QStringLiteral("advanced/restoreProtection"),
            restorePreferences.restoreProtection);
        settings->setValue(
            QStringLiteral("advanced/trackApplicationUninstalls"),
            restorePreferences.trackApplicationUninstalls);
        settings->setValue(
            QStringLiteral("advanced/preserveExactPackagePayloads"),
            restorePreferences.preserveExactPackagePayloads);
        settings->setValue(
            QStringLiteral("advanced/quarantineManualApplications"),
            restorePreferences.quarantineManualApplications);
        settings->setValue(
            QStringLiteral("advanced/quarantineLeftovers"),
            restorePreferences.quarantineLeftovers);
        settings->setValue(
            QStringLiteral("advanced/keepMetadataOnlyRecords"),
            restorePreferences.keepMetadataOnlyRecords);
        settings->setValue(
            QStringLiteral("advanced/preserveFlatpakUserData"),
            restorePreferences.preserveFlatpakUserData);
        settings->setValue(
            QStringLiteral("advanced/autoScanLeftoversAfterUninstall"),
            restorePreferences.autoScanLeftoversAfterUninstall);
        settings->setValue(
            QStringLiteral("advanced/warnWhenSnapshotUnavailable"),
            restorePreferences.warnWhenSnapshotUnavailable);
        settings->setValue(
            QStringLiteral("advanced/offerCurrentVersionFallback"),
            restorePreferences.offerCurrentVersionFallback);
        settings->setValue(
            QStringLiteral("advanced/autoSelectRecommendedLeftovers"),
            autoSelectRecommendedLeftovers);
        settings->sync();
    }


    bool applicationRestoreTrackingEnabled() const
    {
        return restorePreferences.applicationTrackingEnabled();
    }


    bool exactPackageSnapshotsEnabled() const
    {
        return restorePreferences.exactPackageSnapshotsEnabled();
    }


    bool manualApplicationQuarantineEnabled() const
    {
        return restorePreferences.manualApplicationQuarantineEnabled();
    }


    bool leftoverQuarantineEnabled() const
    {
        return restorePreferences.leftoverQuarantineEnabled();
    }


    void updateQuarantineInfoLabel()
    {
        if (!quarantineInfoLabel)
            return;

        if (historyTree) {
            const QList<QTreeWidgetItem *> selected = selectedQuarantineItems();
            if (selected.size() == 1 && selected.first()) {
                QTreeWidgetItem *item = selected.first();
                const QString application =
                    item->data(0, Qt::UserRole + 25).toString();
                const QString entryKind =
                    item->data(0, Qt::UserRole + 27).toString();
                const int itemCount =
                    item->data(0, Qt::UserRole + 26).toInt();
                const QString status = item->text(5);

                QString countText;
                if (entryKind == QStringLiteral("Leftovers") || itemCount > 1) {
                    countText = QStringLiteral("%1 %2")
                        .arg(itemCount)
                        .arg(wordForCount(
                            itemCount,
                            QStringLiteral("file"),
                            QStringLiteral("files")));
                }
                else {
                    countText = item->text(1);
                }

                quarantineInfoLabel->setText(
                    QStringLiteral("Selected: %1  •  %2  •  %3  •  %4")
                        .arg(application, entryKind, countText, status));
                quarantineInfoLabel->setToolTip(
                    QStringLiteral(
                        "The Restore button applies only to this selected Quarantine entry. Application and Leftovers entries for the same app are separate restore records."));
                return;
            }

            if (selected.size() > 1) {
                quarantineInfoLabel->setText(
                    QStringLiteral("%1 entries selected  •  Restore works one entry at a time  •  Permanent delete applies to all selected")
                        .arg(selected.size()));
                quarantineInfoLabel->setToolTip(
                    QStringLiteral(
                        "Select exactly one entry to restore it. Multiple entries can be permanently deleted together."));
                return;
            }
        }

        if (!restorePreferences.restoreProtection) {
            quarantineInfoLabel->setText(
                QStringLiteral(
                    "Future restore protection: Off  •  Existing Quarantine entries remain available"));
            quarantineInfoLabel->setToolTip(
                QStringLiteral(
                    "Settings currently allow future removals without TotalSweep restore protection. Existing Quarantine entries are unaffected and can still be restored."));
            return;
        }

        const QString apps = applicationRestoreTrackingEnabled()
            ? QStringLiteral("Application restore: On")
            : QStringLiteral("Application restore: Off");
        const QString exact = exactPackageSnapshotsEnabled()
            ? QStringLiteral("Exact package snapshots: On")
            : QStringLiteral("Exact package snapshots: Off");
        const QString leftovers = leftoverQuarantineEnabled()
            ? QStringLiteral("Leftovers: Quarantine")
            : QStringLiteral("Leftovers: Permanent delete");

        quarantineInfoLabel->setText(
            QStringLiteral("%1  •  %2  •  %3")
                .arg(apps, exact, leftovers));
        quarantineInfoLabel->setToolTip(
            QStringLiteral(
                "These settings affect future removals only. Existing Quarantine entries remain available regardless of later Settings changes."));
    }


    void updateLeftoverActionModeUi()
    {
        const bool quarantine = leftoverQuarantineEnabled();

        if (quarantineSelectedBtn) {
            const int count =
                selectedLeftoverActionPaths().size();

            const QString baseText = quarantine
                ? QStringLiteral("Quarantine Selected")
                : QStringLiteral("Delete Selected Permanently");

            quarantineSelectedBtn->setText(
                count > 0
                    ? QStringLiteral("%1 (%2)")
                        .arg(baseText)
                        .arg(count)
                    : baseText);

            quarantineSelectedBtn->setToolTip(
                quarantine
                    ? QStringLiteral("Check one or more leftovers, or highlight one leftover row, to move the current selection into TotalSweep Quarantine.")
                    : QStringLiteral("Check one or more leftovers, or highlight one leftover row, to permanently delete the current selection. TotalSweep will not keep a restore copy."));

            if (quarantine) {
                configureMonochromeButton(
                    quarantineSelectedBtn,
                    {QStringLiteral("document-save"), QStringLiteral("folder-locked")},
                    QStyle::SP_DialogSaveButton);
            }
            else {
                configureMonochromeButton(
                    quarantineSelectedBtn,
                    {QStringLiteral("edit-delete"), QStringLiteral("user-trash")},
                    QStyle::SP_TrashIcon);
            }
        }

    }


    void updateAdvancedSettingsUi()
    {
        updateLeftoverActionModeUi();
        updateQuarantineInfoLabel();

        if (advancedSettingsButton) {
            advancedSettingsButton->setToolTip(
                QStringLiteral(
                    "Configure Restore Protection, Leftovers, app-data and restore behavior."));
        }
    }


    void showAdvancedSettingsDialog()
    {
        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("TotalSweep Settings"));
        dialog.setWindowIcon(totalSweepIcon());
        dialog.setMinimumWidth(720);

        auto *root = new QVBoxLayout(&dialog);
        root->setContentsMargins(14, 12, 14, 12);
        root->setSpacing(8);

        auto *intro = new QLabel(
            QStringLiteral(
                "<b>Choose what TotalSweep keeps recoverable and what happens after an uninstall.</b><br>"
                "These settings affect future removals only. Anything already in Quarantine is not changed."),
            &dialog);
        intro->setWordWrap(false);
        intro->setTextFormat(Qt::RichText);
        root->addWidget(intro);

        auto addSettingDescription = [](
            QVBoxLayout *layout,
            QCheckBox *check,
            const QString &description) -> QLabel * {

            check->setToolTip(description);

            auto *setting = new QVBoxLayout();
            setting->setContentsMargins(0, 0, 0, 0);
            setting->setSpacing(3);
            setting->addWidget(check);

            auto *label = new QLabel(description);
            label->setWordWrap(true);
            label->setContentsMargins(24, 0, 8, 0);

            QPalette secondary = label->palette();
            secondary.setColor(
                QPalette::WindowText,
                secondary.color(QPalette::PlaceholderText));
            label->setPalette(secondary);

            setting->addWidget(label);
            layout->addLayout(setting);
            return label;
        };

        auto makeSecondaryLabel = [](
            QWidget *parent,
            const QString &text) -> QLabel * {

            auto *label = new QLabel(text, parent);
            label->setWordWrap(true);
            label->setContentsMargins(24, 2, 8, 0);

            QPalette secondary = label->palette();
            secondary.setColor(
                QPalette::WindowText,
                secondary.color(QPalette::PlaceholderText));
            label->setPalette(secondary);

            return label;
        };

        auto *scroll = new QScrollArea(&dialog);
        scroll->setWidgetResizable(false);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scroll->setAlignment(Qt::AlignLeft | Qt::AlignTop);

        auto *settingsPage = new QWidget(scroll);
        auto *settingsLayout = new QVBoxLayout(settingsPage);
        settingsLayout->setContentsMargins(0, 0, 6, 0);
        settingsLayout->setSpacing(9);

        auto *master = new QCheckBox(
            QStringLiteral("Enable Restore Protection"),
            settingsPage);
        master->setChecked(restorePreferences.restoreProtection);
        QFont masterFont = master->font();
        masterFont.setBold(true);
        master->setFont(masterFont);

        auto *masterBlock = new QVBoxLayout();
        masterBlock->setContentsMargins(0, 0, 0, 0);
        masterBlock->setSpacing(0);

        const QString masterDescriptionText =
            QStringLiteral(
                "Keeps supported removals recoverable through Quarantine. Turn this off only if you want permanent removal.");

        master->setToolTip(masterDescriptionText);
        masterBlock->addWidget(master);
        masterBlock->addSpacing(3);

        auto *masterDescription = new QLabel(
            masterDescriptionText,
            settingsPage);
        masterDescription->setWordWrap(false);
        masterDescription->setContentsMargins(24, 0, 8, 0);
        masterDescription->setSizePolicy(
            QSizePolicy::Expanding,
            QSizePolicy::Fixed);

        QPalette masterSecondary = masterDescription->palette();
        masterSecondary.setColor(
            QPalette::WindowText,
            masterSecondary.color(QPalette::PlaceholderText));
        masterDescription->setPalette(masterSecondary);

        masterBlock->addWidget(masterDescription);
        masterBlock->addSpacing(5);

        auto *restoreModeStatus = new QLabel(settingsPage);
        restoreModeStatus->setWordWrap(false);
        restoreModeStatus->setContentsMargins(24, 0, 8, 0);
        restoreModeStatus->setSizePolicy(
            QSizePolicy::Expanding,
            QSizePolicy::Fixed);
        QFont restoreStatusFont = restoreModeStatus->font();
        restoreStatusFont.setBold(true);
        restoreModeStatus->setFont(restoreStatusFont);
        masterBlock->addWidget(restoreModeStatus);
        settingsLayout->addLayout(masterBlock);

        auto *appsGroup = new QGroupBox(
            QStringLiteral("Application Recovery"),
            settingsPage);
        auto *appsLayout = new QVBoxLayout(appsGroup);
        appsLayout->setContentsMargins(12, 9, 12, 9);
        appsLayout->setSpacing(7);

        auto *trackApps = new QCheckBox(
            QStringLiteral("Keep uninstalled applications recoverable"),
            appsGroup);
        trackApps->setChecked(restorePreferences.trackApplicationUninstalls);
        auto *trackAppsDescription = addSettingDescription(
            appsLayout,
            trackApps,
            QStringLiteral(
                "Adds supported app removals to Quarantine so TotalSweep can offer restore options later."));

        auto *exactPackages = new QCheckBox(
            QStringLiteral("Save the exact installed version when possible"),
            appsGroup);
        exactPackages->setChecked(restorePreferences.preserveExactPackagePayloads);
        auto *exactPackagesDescription = addSettingDescription(
            appsLayout,
            exactPackages,
            QStringLiteral(
                "Tries to preserve exact restore data when safe. Preserved RPMs are reverified before administrator restore; system-wide Flatpak bundles are preserved for record/recovery purposes but are not elevated from user-writable storage. Uses additional disk space."));

        auto *manualApps = new QCheckBox(
            QStringLiteral("Move manual applications to Quarantine"),
            appsGroup);
        manualApps->setChecked(restorePreferences.quarantineManualApplications);
        auto *manualAppsDescription = addSettingDescription(
            appsLayout,
            manualApps,
            QStringLiteral(
                "Moves supported AppImage, script, binary, and manually installed app files to Quarantine instead of permanently deleting them."));

        auto *metadataOnly = new QCheckBox(
            QStringLiteral("Keep uninstall history when no restore copy is available"),
            appsGroup);
        metadataOnly->setChecked(restorePreferences.keepMetadataOnlyRecords);
        auto *metadataOnlyDescription = addSettingDescription(
            appsLayout,
            metadataOnly,
            QStringLiteral(
                "Records what was removed even when TotalSweep cannot restore the application itself."));

        settingsLayout->addWidget(appsGroup);

        auto *leftoversGroup = new QGroupBox(
            QStringLiteral("Leftovers"),
            settingsPage);
        auto *leftoversLayout = new QVBoxLayout(leftoversGroup);
        leftoversLayout->setContentsMargins(12, 9, 12, 9);
        leftoversLayout->setSpacing(7);

        auto *quarantineLeftovers = new QCheckBox(
            QStringLiteral("Move leftovers to Quarantine instead of permanently deleting them"),
            leftoversGroup);
        quarantineLeftovers->setChecked(restorePreferences.quarantineLeftovers);
        auto *quarantineLeftoversDescription = addSettingDescription(
            leftoversLayout,
            quarantineLeftovers,
            QStringLiteral(
                "Lets you restore a leftover later if removing it causes a problem."));

        auto *autoScan = new QCheckBox(
            QStringLiteral("Automatically scan for leftovers after uninstalling"),
            leftoversGroup);
        autoScan->setChecked(restorePreferences.autoScanLeftoversAfterUninstall);
        auto *autoScanDescription = addSettingDescription(
            leftoversLayout,
            autoScan,
            QStringLiteral(
                "Checks every successfully removed app for files it left behind."));

        auto *autoSelectRecommended = new QCheckBox(
            QStringLiteral("Automatically select Recommended leftovers"),
            leftoversGroup);
        autoSelectRecommended->setChecked(autoSelectRecommendedLeftovers);
        auto *autoSelectRecommendedDescription = addSettingDescription(
            leftoversLayout,
            autoSelectRecommended,
            QStringLiteral(
                "Checks only leftovers TotalSweep considers safe to remove. Review and Danger items stay unchecked."));

        auto *flatpakData = new QCheckBox(
            QStringLiteral("Keep app settings and user data for Leftovers review"),
            leftoversGroup);
        flatpakData->setChecked(restorePreferences.preserveFlatpakUserData);
        auto *flatpakDataDescription = addSettingDescription(
            leftoversLayout,
            flatpakData,
            QStringLiteral(
                "Keeps personal app data when possible so you can review it in Leftovers before deciding whether to remove it."));

        auto *flatpakTechnicalNote = makeSecondaryLabel(
            leftoversGroup,
            QStringLiteral(
                "<b>Technical note:</b> For Flatpak apps, TotalSweep avoids deleting the app’s sandboxed user data during uninstall so it remains available for the Leftovers scan. RPM and manual apps usually leave their user data behind automatically."));
        flatpakTechnicalNote->setTextFormat(Qt::RichText);
        leftoversLayout->addWidget(flatpakTechnicalNote);

        settingsLayout->addWidget(leftoversGroup);

        auto *behaviorGroup = new QGroupBox(
            QStringLiteral("Restore Options"),
            settingsPage);
        auto *behaviorLayout = new QVBoxLayout(behaviorGroup);
        behaviorLayout->setContentsMargins(12, 9, 12, 9);
        behaviorLayout->setSpacing(7);

        auto *snapshotWarning = new QCheckBox(
            QStringLiteral("Warn me if the exact version cannot be saved"),
            behaviorGroup);
        snapshotWarning->setChecked(restorePreferences.warnWhenSnapshotUnavailable);
        auto *snapshotWarningDescription = addSettingDescription(
            behaviorLayout,
            snapshotWarning,
            QStringLiteral(
                "Lets you cancel before uninstalling when TotalSweep cannot preserve the exact installed version."));

        auto *currentFallback = new QCheckBox(
            QStringLiteral("Offer the current version if the exact version cannot be restored"),
            behaviorGroup);
        currentFallback->setChecked(restorePreferences.offerCurrentVersionFallback);
        auto *currentFallbackDescription = addSettingDescription(
            behaviorLayout,
            currentFallback,
            QStringLiteral(
                "During restore, TotalSweep can offer the currently available package version instead. It will never install it without asking you."));

        settingsLayout->addWidget(behaviorGroup);
        settingsLayout->setAlignment(Qt::AlignTop);

        intro->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        masterDescription->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        restoreModeStatus->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        appsGroup->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        leftoversGroup->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        behaviorGroup->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        settingsPage->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

        scroll->setWidget(settingsPage);
        root->addWidget(scroll, 0);

        auto *recommended = new QPushButton(
            QStringLiteral("Restore Recommended Settings"),
            &dialog);
        recommended->setToolTip(
            QStringLiteral(
                "Turns on TotalSweep’s recommended safety and recovery settings."));

        auto updateDependencies = [&]() {
            const bool futureRestore =
                master->isChecked();

            trackApps->setEnabled(futureRestore);
            trackAppsDescription->setEnabled(futureRestore);
            quarantineLeftovers->setEnabled(futureRestore);
            quarantineLeftoversDescription->setEnabled(futureRestore);

            const bool appTracking =
                futureRestore &&
                trackApps->isChecked();

            exactPackages->setEnabled(appTracking);
            exactPackagesDescription->setEnabled(appTracking);
            manualApps->setEnabled(appTracking);
            manualAppsDescription->setEnabled(appTracking);
            metadataOnly->setEnabled(appTracking);
            metadataOnlyDescription->setEnabled(appTracking);
            currentFallback->setEnabled(appTracking);
            currentFallbackDescription->setEnabled(appTracking);

            const bool exactEnabled =
                appTracking &&
                exactPackages->isChecked();

            snapshotWarning->setEnabled(exactEnabled);
            snapshotWarningDescription->setEnabled(exactEnabled);

            autoScan->setEnabled(true);
            autoScanDescription->setEnabled(true);
            autoSelectRecommended->setEnabled(true);
            autoSelectRecommendedDescription->setEnabled(true);
            flatpakData->setEnabled(true);
            flatpakDataDescription->setEnabled(true);
            flatpakTechnicalNote->setEnabled(true);
            masterDescription->setEnabled(true);

            if (!futureRestore) {
                restoreModeStatus->setText(
                    QStringLiteral("Protection: Off"));
            }
            else {
                const bool fullRecommendedProtection =
                    trackApps->isChecked() &&
                    exactPackages->isChecked() &&
                    manualApps->isChecked() &&
                    metadataOnly->isChecked() &&
                    quarantineLeftovers->isChecked() &&
                    snapshotWarning->isChecked() &&
                    currentFallback->isChecked();

                restoreModeStatus->setText(
                    fullRecommendedProtection
                        ? QStringLiteral("Protection: Recommended")
                        : QStringLiteral("Protection: Custom"));
            }
        };

        bool masterWasEnabled =
            master->isChecked();

        connect(
            master,
            &QCheckBox::toggled,
            &dialog,
            [&](bool enabled) {
                if (enabled && !masterWasEnabled) {
                    trackApps->setChecked(true);
                    exactPackages->setChecked(true);
                    manualApps->setChecked(true);
                    metadataOnly->setChecked(true);
                    quarantineLeftovers->setChecked(true);
                    snapshotWarning->setChecked(true);
                    currentFallback->setChecked(true);
                }

                masterWasEnabled = enabled;
                updateDependencies();
            });

        const QList<QCheckBox *> dependencyChecks = {
            trackApps,
            exactPackages,
            manualApps,
            metadataOnly,
            quarantineLeftovers,
            snapshotWarning,
            currentFallback
        };

        for (QCheckBox *check : dependencyChecks) {
            connect(
                check,
                &QCheckBox::toggled,
                &dialog,
                [&](bool) {
                    updateDependencies();
                });
        }

        connect(
            recommended,
            &QPushButton::clicked,
            &dialog,
            [&]() {
                master->setChecked(true);
                trackApps->setChecked(true);
                exactPackages->setChecked(true);
                manualApps->setChecked(true);
                metadataOnly->setChecked(true);
                quarantineLeftovers->setChecked(true);
                autoScan->setChecked(true);
                autoSelectRecommended->setChecked(true);
                flatpakData->setChecked(true);
                snapshotWarning->setChecked(true);
                currentFallback->setChecked(true);
                updateDependencies();
            });

        updateDependencies();

        auto *buttons = new QDialogButtonBox(
            QDialogButtonBox::Save | QDialogButtonBox::Cancel,
            Qt::Horizontal,
            &dialog);

        auto *footer = new QHBoxLayout();
        footer->setContentsMargins(0, 0, 0, 0);
        footer->setSpacing(8);
        footer->addWidget(recommended);
        footer->addStretch(1);
        footer->addWidget(buttons);
        root->addLayout(footer);

        connect(
            buttons,
            &QDialogButtonBox::rejected,
            &dialog,
            &QDialog::reject);
        connect(
            buttons,
            &QDialogButtonBox::accepted,
            &dialog,
            &QDialog::accept);

        const QScreen *settingsScreen =
            dialog.screen()
                ? dialog.screen()
                : QApplication::primaryScreen();

        const QRect available =
            settingsScreen
                ? settingsScreen->availableGeometry()
                : QRect(0, 0, 1280, 800);

        const int maximumWidth =
            qMax(680, available.width() - 80);
        const int maximumHeight =
            qMax(480, available.height() - 80);

        const int targetWidth =
            qMin(maximumWidth, 920);

        const QMargins rootMargins =
            root->contentsMargins();

        const int settingsPageWidth =
            qMax(640, targetWidth - rootMargins.left() - rootMargins.right() - 8);

        settingsPage->setFixedWidth(settingsPageWidth);

        const int measurementHeight =
            qMax(2000, maximumHeight * 2);

        settingsPage->resize(
            settingsPageWidth,
            measurementHeight);

        settingsLayout->invalidate();
        settingsLayout->activate();

        appsLayout->invalidate();
        leftoversLayout->invalidate();
        behaviorLayout->invalidate();
        appsLayout->activate();
        leftoversLayout->activate();
        behaviorLayout->activate();
        settingsLayout->invalidate();
        settingsLayout->activate();

        const QMargins settingsMargins =
            settingsLayout->contentsMargins();

        const int naturalSettingsHeight =
            behaviorGroup->geometry().bottom() +
            1 +
            settingsMargins.bottom();

        settingsPage->setFixedHeight(
            qMax(1, naturalSettingsHeight));

        intro->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        intro->adjustSize();

        const int chromeHeight =
            rootMargins.top() +
            rootMargins.bottom() +
            intro->sizeHint().height() +
            footer->sizeHint().height() +
            (root->spacing() * 2);

        const int availableScrollHeight =
            qMax(260, maximumHeight - chromeHeight);

        const int scrollHeight =
            qMin(naturalSettingsHeight + 2, availableScrollHeight);

        scroll->setFixedHeight(scrollHeight);
        scroll->setSizePolicy(
            QSizePolicy::Expanding,
            QSizePolicy::Fixed);

        const int targetHeight =
            qMin(maximumHeight, chromeHeight + scrollHeight);

        dialog.setFixedHeight(targetHeight);
        dialog.resize(targetWidth, targetHeight);
        if (dialog.exec() != QDialog::Accepted)
            return;

        totalsweep_restore::RestorePolicy updated =
            restorePreferences;

        updated.restoreProtection =
            master->isChecked();
        updated.trackApplicationUninstalls =
            trackApps->isChecked();
        updated.preserveExactPackagePayloads =
            exactPackages->isChecked();
        updated.quarantineManualApplications =
            manualApps->isChecked();
        updated.quarantineLeftovers =
            quarantineLeftovers->isChecked();
        updated.keepMetadataOnlyRecords =
            metadataOnly->isChecked();
        updated.preserveFlatpakUserData =
            flatpakData->isChecked();
        updated.autoScanLeftoversAfterUninstall =
            autoScan->isChecked();
        updated.warnWhenSnapshotUnavailable =
            snapshotWarning->isChecked();
        updated.offerCurrentVersionFallback =
            currentFallback->isChecked();

        const bool futurePermanentRemoval =
            !updated.restoreProtection ||
            !updated.trackApplicationUninstalls ||
            !updated.quarantineManualApplications ||
            !updated.quarantineLeftovers ||
            !updated.preserveFlatpakUserData;

        if (futurePermanentRemoval) {
            QMessageBox warning(this);
            warning.setWindowIcon(totalSweepIcon());
            warning.setIcon(QMessageBox::Warning);
            warning.setWindowTitle(
                QStringLiteral("Permanent Removal Warning"));
            warning.setText(
                QStringLiteral(
                    "Some future removals may not be recoverable."));
            warning.setInformativeText(
                QStringLiteral(
                    "One or more recovery options are off. TotalSweep may not be able to restore some application files, leftovers, or user data after they are removed.\n\nSave these settings?"));
            warning.setStandardButtons(
                QMessageBox::Yes |
                QMessageBox::No);
            warning.setDefaultButton(
                QMessageBox::No);
            prepareMessageBox(warning);

            if (warning.exec() != QMessageBox::Yes)
                return;
        }

        const bool enableAutoSelectNow =
            autoSelectRecommended->isChecked() &&
            !autoSelectRecommendedLeftovers;

        restorePreferences = updated;
        autoSelectRecommendedLeftovers =
            autoSelectRecommended->isChecked();
        saveRestorePreferences();

        if (enableAutoSelectNow && results)
            setRecommended();

        updateAdvancedSettingsUi();
    }


    void prepareMessageBox(
        QMessageBox &box) const
    {
        box.setWindowIcon(totalSweepIcon());

        const QString title =
            box.windowTitle().trimmed();

        const int titleWidth =
            title.isEmpty()
                ? 0
                : QFontMetrics(box.font())
                    .horizontalAdvance(title);

        const QScreen *targetScreen =
            box.screen()
                ? box.screen()
                : QApplication::primaryScreen();

        const int availableWidth =
            targetScreen
                ? targetScreen->availableGeometry().width()
                : 1280;

        const int maximumWidth =
            qMax(
                680,
                qMin(
                    1100,
                    availableWidth - 120));

        const int targetWidth =
            qMin(
                maximumWidth,
                qMax(
                    720,
                    qMax(
                        titleWidth + 460,
                        box.sizeHint().width() + 80)));

        box.setMinimumWidth(targetWidth);
        box.resize(
            targetWidth,
            qMax(
                box.height(),
                box.sizeHint().height()));

        QTimer::singleShot(
            0,
            &box,
            [&box, targetWidth]() {
                box.setMinimumWidth(targetWidth);
                box.resize(
                    targetWidth,
                    qMax(
                        box.height(),
                        box.sizeHint().height()));
            });
    }


    QMessageBox::StandardButton showTotalSweepMessage(
        QMessageBox::Icon icon,
        const QString &title,
        const QString &text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok,
        QMessageBox::StandardButton defaultButton = QMessageBox::NoButton)
    {
        QMessageBox box(this);
        box.setIcon(icon);
        box.setWindowTitle(title);
        box.setText(text);
        box.setStandardButtons(buttons);
        if (defaultButton != QMessageBox::NoButton &&
            buttons.testFlag(defaultButton)) {
            box.setDefaultButton(defaultButton);
        }
        prepareMessageBox(box);
        return static_cast<QMessageBox::StandardButton>(box.exec());
    }


    QMessageBox::StandardButton totalSweepWarning(
        QWidget *,
        const QString &title,
        const QString &text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok,
        QMessageBox::StandardButton defaultButton = QMessageBox::NoButton)
    {
        return showTotalSweepMessage(
            QMessageBox::Warning,
            title,
            text,
            buttons,
            defaultButton);
    }


    QMessageBox::StandardButton totalSweepInformation(
        QWidget *,
        const QString &title,
        const QString &text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok,
        QMessageBox::StandardButton defaultButton = QMessageBox::NoButton)
    {
        return showTotalSweepMessage(
            QMessageBox::Information,
            title,
            text,
            buttons,
            defaultButton);
    }


    void showTransientInformation(
        const QString &title,
        const QString &text,
        int durationMs = 5000)
    {
        auto *dialog = new QDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose, true);
        dialog->setWindowTitle(title);
        dialog->setWindowIcon(totalSweepIcon());
        dialog->setModal(false);
        dialog->setWindowModality(Qt::NonModal);

        auto *layout = new QVBoxLayout(dialog);
        layout->setContentsMargins(20, 18, 20, 16);
        layout->setSpacing(14);

        auto *message = new QLabel(text, dialog);
        message->setWordWrap(true);
        message->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(message);

        auto *buttons = new QHBoxLayout();
        buttons->addStretch();

        auto *okButton = new QPushButton(dialog);
        okButton->setDefault(true);
        buttons->addWidget(okButton);
        layout->addLayout(buttons);

        const int safeDuration = qMax(1000, durationMs);
        const qint64 deadline =
            QDateTime::currentMSecsSinceEpoch() + safeDuration;

        auto updateCountdown =
            [dialog, okButton, deadline]() -> bool {
                const qint64 remainingMs =
                    deadline - QDateTime::currentMSecsSinceEpoch();

                if (remainingMs <= 0) {
                    dialog->accept();
                    return false;
                }

                const int seconds =
                    qMax(1, static_cast<int>((remainingMs + 999) / 1000));

                const QString label =
                    QStringLiteral("OK (%1)").arg(seconds);

                if (okButton->text() != label) {
                    okButton->setText(label);
                    okButton->update();
                }

                return true;
            };

        updateCountdown();

        auto *countdown = new QTimer(dialog);
        countdown->setInterval(100);

        connect(
            countdown,
            &QTimer::timeout,
            dialog,
            [countdown, updateCountdown]() mutable {
                if (!updateCountdown())
                    countdown->stop();
            });

        connect(
            okButton,
            &QPushButton::clicked,
            dialog,
            [dialog, countdown]() {
                countdown->stop();
                dialog->accept();
            });

        const QScreen *targetScreen =
            dialog->screen()
                ? dialog->screen()
                : QApplication::primaryScreen();
        const int availableWidth = targetScreen
            ? targetScreen->availableGeometry().width()
            : 1280;
        const int width =
            qMax(520, qMin(760, availableWidth - 140));
        dialog->setMinimumWidth(qMin(width, 620));
        dialog->resize(width, dialog->sizeHint().height());

        dialog->show();
        dialog->raise();
        countdown->start();
    }

    QMessageBox::StandardButton totalSweepCritical(
        QWidget *,
        const QString &title,
        const QString &text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok,
        QMessageBox::StandardButton defaultButton = QMessageBox::NoButton)
    {
        return showTotalSweepMessage(
            QMessageBox::Critical,
            title,
            text,
            buttons,
            defaultButton);
    }


    QIcon totalSweepIcon() const
    {
        const QStringList candidates = {
            QDir::current().filePath(
                QStringLiteral("org.kde.totalsweep.svg")),
            QDir(
                QApplication::applicationDirPath())
                .filePath(
                    QStringLiteral("../org.kde.totalsweep.svg")),
            QStringLiteral(
                "/usr/local/share/icons/hicolor/scalable/apps/org.kde.totalsweep.svg"),
            QDir::homePath() +
                QStringLiteral(
                    "/.local/share/icons/hicolor/scalable/apps/org.kde.totalsweep.svg"),
            QStringLiteral(
                "/usr/share/icons/hicolor/scalable/apps/org.kde.totalsweep.svg")
        };

        for (const QString &path : candidates) {
            if (!QFileInfo::exists(path))
                continue;

            QIcon fileIcon(path);

            if (!fileIcon.isNull())
                return fileIcon;
        }

        QIcon themed =
            QIcon::fromTheme(
                QStringLiteral(
                    "org.kde.totalsweep"));

        if (!themed.isNull())
            return themed;

        return style()->standardIcon(
            QStyle::SP_ComputerIcon);
    }


    QIcon navigationIcon(
        const QStringList &themeNames,
        QStyle::StandardPixmap fallback) const
    {
        for (const QString &name : themeNames) {

            const QIcon icon =
                QIcon::fromTheme(name);

            if (!icon.isNull())
                return icon;
        }

        return style()->standardIcon(
            fallback);
    }


    QIcon monochromeSemanticIcon(
        const QStringList &themeNames,
        QStyle::StandardPixmap fallback) const
    {
        return tintedIcon(
            navigationIcon(
                themeNames,
                fallback),
            QApplication::palette().color(
                QPalette::Text));
    }


    QIcon tintedIcon(
        const QIcon &source,
        const QColor &color) const
    {
        if (source.isNull())
            return source;

        QIcon result;

        const QList<int> sizes = {
            16, 18, 20, 22, 24, 32, 48, 64
        };

        for (int edge : sizes) {

            QImage image(
                edge,
                edge,
                QImage::Format_ARGB32_Premultiplied);

            image.fill(
                Qt::transparent);

            {
                QPainter painter(&image);

                painter.setRenderHint(
                    QPainter::Antialiasing,
                    true);

                source.paint(
                    &painter,
                    QRect(
                        0,
                        0,
                        edge,
                        edge),
                    Qt::AlignCenter,
                    QIcon::Normal,
                    QIcon::Off);

                painter.setCompositionMode(
                    QPainter::CompositionMode_SourceIn);

                painter.fillRect(
                    image.rect(),
                    color);
            }

            QPixmap pixmap =
                QPixmap::fromImage(image);

            pixmap.setDevicePixelRatio(
                1.0);

            result.addPixmap(
                pixmap,
                QIcon::Normal,
                QIcon::Off);
        }

        return result;
    }


    QColor monochromeIconColor(
        const QPushButton *button) const
    {
        Q_UNUSED(button);

        const QPalette palette =
            QApplication::palette();

        return palette.color(
            QPalette::ButtonText);
    }


    void refreshMonochromeButtonIcon(
        QPushButton *button)
    {
        if (!button)
            return;

        const QVariant namesValue =
            button->property(
                "totalsweepIconNames");

        if (!namesValue.isValid())
            return;

        const QStringList names =
            namesValue.toStringList();

        const int fallbackValue =
            button->property(
                "totalsweepIconFallback")
                .toInt();

        const QIcon sourceIcon =
            navigationIcon(
                names,
                static_cast<QStyle::StandardPixmap>(
                    fallbackValue));

        button->setIcon(
            tintedIcon(
                sourceIcon,
                monochromeIconColor(
                    button)));
    }


    void configureMonochromeButton(
        QPushButton *button,
        const QStringList &themeNames,
        QStyle::StandardPixmap fallback,
        const QSize &iconSize = QSize(18, 18))
    {
        if (!button)
            return;

        button->setProperty(
            "totalsweepIconNames",
            themeNames);

        button->setProperty(
            "totalsweepIconFallback",
            static_cast<int>(fallback));

        button->setIconSize(
            iconSize);

        refreshMonochromeButtonIcon(
            button);
    }


    void refreshMonochromeIcons()
    {
        const QList<QPushButton *> buttons =
            findChildren<QPushButton *>();

        for (QPushButton *button : buttons) {

            if (button->property(
                    "totalsweepIconNames")
                    .isValid()) {

                refreshMonochromeButtonIcon(
                    button);
            }
        }

        if (titleIconLabel) {
            titleIconLabel->setPixmap(
                totalSweepIcon().pixmap(
                    QSize(38, 38)));
        }

        setWindowIcon(
            totalSweepIcon());
    }


    QLineEdit *activeSearchField() const
    {
        if (!pages)
            return nullptr;

        switch (pages->currentIndex()) {
        case 0:
            return search;
        case 1:
            return leftoversSearch;
        case 2:
            return quarantineSearch;
        default:
            return nullptr;
        }
    }


    void focusActiveSearchField()
    {
        if (QLineEdit *field =
                activeSearchField()) {

            if (!field->isEnabled())
                return;

            field->setFocus(
                Qt::ShortcutFocusReason);
            field->selectAll();
        }
    }


    void clearActiveSearchField()
    {
        if (QLineEdit *field =
                activeSearchField()) {

            if (!field->isEnabled())
                return;

            field->clear();
            field->setFocus(
                Qt::ShortcutFocusReason);
        }
    }


    void updatePageToolbar()
    {
        if (!pages || !pageRefreshBtn || !pageOptionsBtn)
            return;

        const int page = pages->currentIndex();

        QMenu *menu = nullptr;
        QString refreshToolTip;
        QString optionsToolTip;
        bool refreshEnabled = true;
        QString refreshText = QStringLiteral("Refresh");

        switch (page) {
        case 0:
            menu = applicationColumnsMenu;
            refreshToolTip = QStringLiteral(
                "Reload the installed-application inventory from the current system state.");
            optionsToolTip = QStringLiteral(
                "Customize the Uninstall table or open TotalSweep settings.");
            refreshEnabled = !applicationRefreshRunning;
            if (applicationRefreshRunning)
                refreshText = QStringLiteral("Refreshing…");
            break;
        case 1:
            menu = leftoversViewMenu;
            refreshToolTip = QStringLiteral(
                "Run the current Leftovers search again against the live filesystem.");
            optionsToolTip = QStringLiteral(
                "Customize the Leftovers table or open TotalSweep settings.");
            refreshEnabled =
                !leftoverScanRunning &&
                !postUninstallBatchActive;
            if (leftoverScanRunning ||
                postUninstallBatchActive) {
                refreshText = QStringLiteral("Scanning…");
            }
            break;
        case 2:
            menu = quarantineViewMenu;
            refreshToolTip = QStringLiteral(
                "Reload Quarantine entries from disk.");
            optionsToolTip = QStringLiteral(
                "Customize the Quarantine table or open TotalSweep settings.");
            break;
        default:
            refreshEnabled = false;
            break;
        }

        pageRefreshBtn->setText(refreshText);
        pageRefreshBtn->setEnabled(refreshEnabled);
        pageRefreshBtn->setToolTip(refreshToolTip);

        pageOptionsBtn->setMenu(menu);
        pageOptionsBtn->setEnabled(menu != nullptr);
        pageOptionsBtn->setToolTip(optionsToolTip);
    }


    void refreshCurrentLeftoversSearch()
    {
        if (!leftoversSearch)
            return;

        if (leftoversSearchDebounce)
            leftoversSearchDebounce->stop();

        const QString query =
            leftoversSearch->text().trimmed();

        if (query.isEmpty()) {
            if (postUninstallBatchActive ||
                leftoverScanRunning ||
                leftoverHomeProcess ||
                leftoverSystemProcess ||
                !pendingLeftoverItems.isEmpty()) {

                stopLeftoverScan();
            }

            if (results) {
                setHoveredLeftoverItem(nullptr);
                pressedLeftoverItem = nullptr;
                results->clear();
                results->setEmptyMessage(
                    QStringLiteral(
                        "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
            }

            if (resultStatus) {
                resultStatus->setText(
                    QStringLiteral(
                        "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
            }

            return;
        }

        scanLeftoversAsync(query);
    }


    void setCurrentPage(
        int index)
    {
        if (!pages ||
            index < 0 ||
            index >= pages->count()) {

            return;
        }

        if (index != 0 && uninstallSearchDebounce)
            uninstallSearchDebounce->stop();

        if (index != 1 && leftoversSearchDebounce)
            leftoversSearchDebounce->stop();

        if (index != 2 && quarantineSearchDebounce)
            quarantineSearchDebounce->stop();

        pages->setCurrentIndex(index);

        if (navigationGroup) {
            if (QAbstractButton *button =
                    navigationGroup->button(index)) {

                button->setChecked(true);
            }
        }

        const QList<QPushButton *> navigationButtons = {
            uninstallNavButton,
            leftoversNavButton,
            quarantineNavButton
        };

        for (QPushButton *button :
             navigationButtons) {

            if (!button)
                continue;

            if (button->property(
                    "totalsweepIconNames")
                    .isValid()) {

                refreshMonochromeButtonIcon(
                    button);
            }
        }

        updatePageToolbar();
    }


    void buildInterface()
    {
        auto *root =
        new QVBoxLayout(this);

        root->setContentsMargins(
            18,
            18,
            18,
            18);

        root->setSpacing(10);

        auto *titleRow =
            new QHBoxLayout();

        titleRow->setContentsMargins(
            0,
            0,
            0,
            0);

        titleRow->setSpacing(10);

        titleIconLabel =
            new QLabel();

        titleIconLabel->setFixedSize(
            42,
            42);

        titleIconLabel->setAlignment(
            Qt::AlignCenter);

        titleIconLabel->setPixmap(
            totalSweepIcon().pixmap(
                QSize(38, 38)));

        auto *title =
            new QLabel(
                "TotalSweep Uninstaller");

        QFont titleFont =
            title->font();

        titleFont.setBold(true);
        titleFont.setPointSize(
            titleFont.pointSize() + 8);

        title->setFont(titleFont);

        titleRow->addWidget(titleIconLabel);
        titleRow->addWidget(title);
        titleRow->addStretch();

        root->addLayout(titleRow);

        auto *subtitle =
        new QLabel(
            "Uninstall applications, sweep for remnants, "
            "and safely quarantine what you remove.");

        subtitle->setWordWrap(true);

        root->addWidget(subtitle);


        auto *navigationRow =
            new QHBoxLayout();

        navigationRow->setContentsMargins(
            0,
            2,
            0,
            2);

        navigationRow->setSpacing(6);

        navigationGroup =
            new QButtonGroup(this);

        navigationGroup->setExclusive(true);

        uninstallNavButton =
            new QPushButton(
                QStringLiteral("Uninstall"));

        uninstallNavButton->setToolTip(
            QStringLiteral(
                "Browse installed applications and remove selected items."));

        leftoversNavButton =
            new QPushButton(
                QStringLiteral("Leftovers"));

        leftoversNavButton->setToolTip(
            QStringLiteral(
                "Scan for leftover files, configuration, caches, "
                "launchers, and other remnants."));

        quarantineNavButton =
            new QPushButton(
                QStringLiteral("Quarantine"));

        quarantineNavButton->setToolTip(
            QStringLiteral(
                "Review removed applications and quarantined files, then restore them when needed."));

        const QList<QPushButton *> navigationButtons = {
            uninstallNavButton,
            leftoversNavButton,
            quarantineNavButton
        };

        for (QPushButton *button :
             navigationButtons) {

            button->setCheckable(true);
            button->setAutoExclusive(true);
            button->setMinimumHeight(34);
            button->setIconSize(
                QSize(18, 18));

            navigationRow->addWidget(button);
        }

        navigationGroup->addButton(
            uninstallNavButton,
            0);

        navigationGroup->addButton(
            leftoversNavButton,
            1);

        navigationGroup->addButton(
            quarantineNavButton,
            2);

        navigationRow->addStretch();

        pageRefreshBtn =
            new QPushButton(
                QStringLiteral("Refresh"));

        pageRefreshBtn->setToolTip(
            QStringLiteral(
                "Refresh the current TotalSweep page."));

        configureMonochromeButton(
            pageRefreshBtn,
            { QStringLiteral("view-refresh") },
            QStyle::SP_BrowserReload,
            QSize(18, 18));

        pageOptionsBtn =
            new QPushButton(
                QStringLiteral("Options"));

        pageOptionsBtn->setToolTip(
            QStringLiteral(
                "Customize the current table or open TotalSweep settings."));

        configureMonochromeButton(
            pageOptionsBtn,
            {
                QStringLiteral("view-list-details"),
                QStringLiteral("configure")
            },
            QStyle::SP_FileDialogDetailedView,
            QSize(18, 18));

        navigationRow->addWidget(pageRefreshBtn);
        navigationRow->addWidget(pageOptionsBtn);

        root->addLayout(navigationRow);

        pages =
            new QStackedWidget();

        root->addWidget(
            pages,
            1);

        buildUninstallTab();
        buildLeftoversTab();
        buildHistoryTab();

        connect(
            pageRefreshBtn,
            &QPushButton::clicked,
            this,
            [this]() {
                if (!pages)
                    return;

                switch (pages->currentIndex()) {
                case 0:
                    refreshApplications();
                    break;
                case 1:
                    refreshCurrentLeftoversSearch();
                    break;
                case 2:
                    loadHistory();
                    break;
                default:
                    break;
                }
            });

        auto *findShortcut =
            new QShortcut(
                QKeySequence(
                    QKeySequence::Find),
                this);

        findShortcut->setContext(
            Qt::WindowShortcut);

        connect(
            findShortcut,
            &QShortcut::activated,
            this,
            [this]() {
                focusActiveSearchField();
            });

        auto *clearSearchShortcut =
            new QShortcut(
                QKeySequence(Qt::Key_Escape),
                this);

        clearSearchShortcut->setContext(
            Qt::WindowShortcut);

        connect(
            clearSearchShortcut,
            &QShortcut::activated,
            this,
            [this]() {
                clearActiveSearchField();
            });

        const QList<QLabel *> textLabels =
            findChildren<QLabel *>();

        for (QLabel *label :
             textLabels) {

            if (!label ||
                label->text().isEmpty()) {

                continue;
            }

            label->setTextInteractionFlags(
                Qt::TextSelectableByMouse |
                Qt::TextSelectableByKeyboard);
        }

        setCurrentPage(0);

        configureMonochromeButton(
            uninstallNavButton,
            {
                QStringLiteral("edit-delete"),
                QStringLiteral("edit-delete-shred"),
                QStringLiteral("user-trash")
            },
            QStyle::SP_TrashIcon,
            QSize(20, 20));

        configureMonochromeButton(
            leftoversNavButton,
            {
                QStringLiteral("edit-clear-all"),
                QStringLiteral("edit-clear"),
                QStringLiteral("edit-find")
            },
            QStyle::SP_DialogResetButton,
            QSize(20, 20));

        configureMonochromeButton(
            quarantineNavButton,
            {
                QStringLiteral("view-history"),
                QStringLiteral("edit-undo"),
                QStringLiteral("document-revert")
            },
            QStyle::SP_BrowserReload,
            QSize(20, 20));

        updateAdvancedSettingsUi();

        connect(
            navigationGroup,
            &QButtonGroup::idClicked,
            this,
            [this](int page) {
                setCurrentPage(page);
            });

        uninstallSearchDebounce =
            new QTimer(this);

        uninstallSearchDebounce->setSingleShot(true);
        uninstallSearchDebounce->setInterval(140);

        connect(
            uninstallSearchDebounce,
            &QTimer::timeout,
            this,
            [this]() {
                if (pages &&
                    pages->currentIndex() == 0) {

                    searchApplication();
                }
            });

        connect(
            search,
            &QLineEdit::textChanged,
            this,
            [this](const QString &text) {
                if (uninstallSearchDebounce)
                    uninstallSearchDebounce->stop();

                if (!applicationInventoryLoaded)
                    return;

                if (text.trimmed().isEmpty()) {
                    showFullApplicationList(false);
                    return;
                }

                if (pages &&
                    pages->currentIndex() == 0 &&
                    uninstallSearchDebounce) {

                    uninstallSearchDebounce->start();
                }
            });

        connect(
            search,
            &QLineEdit::returnPressed,
            this,
            [this]() {
                if (uninstallSearchDebounce)
                    uninstallSearchDebounce->stop();

                searchApplication();
            });
    }

    void buildUninstallTab()
    {
        uninstallTab =
            new QWidget();

        auto *layout =
            new QVBoxLayout(
                uninstallTab);

        auto *searchRow =
            new QHBoxLayout();

        search =
            new QLineEdit(uninstallTab);

        search->setPlaceholderText(
            QStringLiteral(
                "Search installed applications…"));

        search->setClearButtonEnabled(true);

        search->setToolTip(
            QStringLiteral(
                "Results update automatically as you type. "
                "You can start typing anywhere in TotalSweep while "
                "this page is active. Ctrl+F focuses this field and "
                "Escape clears it. This search is limited to the "
                "Uninstall page."));

        searchRow->addWidget(search, 1);
        layout->addLayout(searchRow);

        installInfo =
            new QLabel(
                "Loading installed applications...",
                uninstallTab);

        installInfo->hide();

        applicationStatus =
            new QLabel(
                "Preparing application inventory...");

        applicationStatus->setWordWrap(false);
        applicationStatus->setTextInteractionFlags(
            Qt::TextSelectableByMouse |
            Qt::TextSelectableByKeyboard);
        applicationStatus->setSizePolicy(
            QSizePolicy::Expanding,
            QSizePolicy::Preferred);
        applicationStatus->setMinimumWidth(0);

        auto *filterRow =
            new QHBoxLayout();

        auto *filterLabel =
            new QLabel("Filter:");

        applicationFilterGroup =
            new QButtonGroup(this);

        applicationFilterGroup->setExclusive(
            true);

        auto *removableFilterBtn =
            new QPushButton("Removable");

        removableFilterBtn->setToolTip(
            QStringLiteral(
                "Recommended everyday view. Shows removable "
                "non-system applications only."));

        auto *allFilterBtn =
            new QPushButton("All");

        allFilterBtn->setToolTip(
            QStringLiteral(
                "Show every detected item, including system packages, "
                "dependencies, removable system items, and protected components."));

        auto *systemRemovableFilterBtn =
            new QPushButton("System Removable");

        systemRemovableFilterBtn->setToolTip(
            QStringLiteral(
                "Show advanced system/dependency packages that "
                "TotalSweep considers technically removable."));

        auto *protectedFilterBtn =
            new QPushButton("Protected");

        protectedFilterBtn->setToolTip(
            QStringLiteral(
                "Show protected/core components that TotalSweep "
                "does not allow you to remove."));

        const QList<QPushButton *> filterButtons = {
            removableFilterBtn,
            systemRemovableFilterBtn,
            protectedFilterBtn,
            allFilterBtn
        };

        for (QPushButton *button : filterButtons) {
            button->setCheckable(true);
            button->setAutoExclusive(true);
        }

        applicationFilterGroup->addButton(
            removableFilterBtn,
            FilterRemovableApplications);

        applicationFilterGroup->addButton(
            allFilterBtn,
            FilterAllVisible);

        applicationFilterGroup->addButton(
            systemRemovableFilterBtn,
            FilterSystemRemovable);

        applicationFilterGroup->addButton(
            protectedFilterBtn,
            FilterProtected);

        int startupFilter =
            settings
                ? settings->value(
                    "applications/startupFilter",
                    FilterRemovableApplications)
                    .toInt()
                : FilterRemovableApplications;

        if (startupFilter != FilterRemovableApplications &&
            startupFilter != FilterAllVisible &&
            startupFilter != FilterSystemRemovable &&
            startupFilter != FilterProtected) {

            startupFilter =
                FilterRemovableApplications;
        }

        if (QAbstractButton *startupButton =
                applicationFilterGroup->button(
                    startupFilter)) {

            startupButton->setChecked(true);
        }
        else {
            removableFilterBtn->setChecked(true);
        }

        filterRow->addWidget(filterLabel);

        for (QPushButton *button : filterButtons)
            filterRow->addWidget(button);

        filterRow->addStretch();

        applicationColumnsMenu =
            new QMenu(this);

        applicationColumnsSubmenu =
            applicationColumnsMenu->addMenu(
                QStringLiteral(
                    "Columns"));

        applicationColumnsSubmenu->setToolTip(
            QStringLiteral(
                "Choose which application-table columns are visible."));

        const QStringList columnNames = {
            QStringLiteral("Application"),
            QStringLiteral("Package Type"),
            QStringLiteral("Version"),
            QStringLiteral("Size"),
            QStringLiteral("Install Location"),
            QStringLiteral("Install Date"),
            QStringLiteral("Description"),
            QStringLiteral("Status")
        };

        for (int column = 0;
             column < columnNames.size();
             ++column) {

            auto *check =
                new QCheckBox(
                    columnNames.at(column),
                    applicationColumnsSubmenu);

            check->setChecked(true);
            check->setContentsMargins(
                8,
                4,
                12,
                4);

            if (column == 0) {
                check->setEnabled(false);
                check->setToolTip(
                    QStringLiteral(
                        "Application is always visible."));
            }

            auto *widgetAction =
                new QWidgetAction(
                    applicationColumnsSubmenu);

            widgetAction->setDefaultWidget(
                check);

            applicationColumnsSubmenu->addAction(
                widgetAction);

            applicationColumnChecks.insert(
                column,
                check);

            connect(
                check,
                &QCheckBox::toggled,
                this,
                [this, column](bool visible) {

                    if (!applicationView ||
                        column == 0) {

                        return;
                    }

                    applicationView->setColumnHidden(
                        column,
                        !visible);

                    syncApplicationHorizontalScrollBar();

                    if (settings) {
                        settings->setValue(
                            QString(
                                "applications/column-visible/%1")
                                .arg(column),
                            visible);
                        settings->sync();
                    }
                });
        }

        applicationSeparatorsSubmenu =
            applicationColumnsMenu->addMenu(
                QStringLiteral("Separators"));
        applicationSeparatorsSubmenu->setToolTip(
            QStringLiteral("Choose subtle row and column dividers for the application table."));

        applicationSeparatorsCheck =
            new QCheckBox(
                QStringLiteral("Column separators"),
                applicationSeparatorsSubmenu);
        applicationSeparatorsCheck->setContentsMargins(8, 4, 12, 4);
        applicationSeparatorsCheck->setChecked(applicationColumnSeparators);
        applicationSeparatorsCheck->setToolTip(
            QStringLiteral("Show subtle vertical separators between columns."));

        auto *separatorWidgetAction =
            new QWidgetAction(applicationSeparatorsSubmenu);
        separatorWidgetAction->setDefaultWidget(applicationSeparatorsCheck);
        applicationSeparatorsSubmenu->addAction(separatorWidgetAction);

        connect(
            applicationSeparatorsCheck,
            &QCheckBox::toggled,
            this,
            [this](bool enabled) {
                applicationColumnSeparators = enabled;
                if (settings) {
                    settings->setValue("applications/columnSeparators", enabled);
                    settings->sync();
                }
                applyApplicationTableStyle();
            });

        applicationRowSeparatorsCheck =
            new QCheckBox(
                QStringLiteral("Row separators"),
                applicationSeparatorsSubmenu);
        applicationRowSeparatorsCheck->setContentsMargins(8, 4, 12, 4);
        applicationRowSeparatorsCheck->setChecked(applicationRowSeparators);
        applicationRowSeparatorsCheck->setToolTip(
            QStringLiteral("Show subtle horizontal separators between application rows."));

        auto *rowSeparatorWidgetAction =
            new QWidgetAction(applicationSeparatorsSubmenu);
        rowSeparatorWidgetAction->setDefaultWidget(applicationRowSeparatorsCheck);
        applicationSeparatorsSubmenu->addAction(rowSeparatorWidgetAction);

        connect(
            applicationRowSeparatorsCheck,
            &QCheckBox::toggled,
            this,
            [this](bool enabled) {
                applicationRowSeparators = enabled;
                if (settings) {
                    settings->setValue("applications/rowSeparators", enabled);
                    settings->sync();
                }
                applyApplicationTableStyle();
            });

        auto *setStartupFilterAction =
            applicationColumnsMenu->addAction(
                QStringLiteral(
                    "Set Current Filter as Default"));

        setStartupFilterAction->setToolTip(
            QStringLiteral(
                "Use the currently selected filter automatically "
                "when TotalSweep starts."));

        connect(
            setStartupFilterAction,
            &QAction::triggered,
            this,
            [this]() {

                if (!applicationFilterGroup)
                    return;

                const int mode =
                    applicationFilterGroup
                        ->checkedId();

                QAbstractButton *currentButton =
                    applicationFilterGroup
                        ->checkedButton();

                if (mode < 0 ||
                    !currentButton) {

                    return;
                }

                if (settings) {
                    settings->setValue(
                        "applications/startupFilter",
                        mode);
                    settings->sync();
                }

                applicationStatus->setText(
                    QString(
                        "%1 will be the default filter on startup.")
                        .arg(
                            currentButton->text()));
            });

        applicationColumnsMenu->addSeparator();

        applicationResetColumnsAction =
            applicationColumnsMenu->addAction(
                QStringLiteral(
                    "Reset Table Layout"));

        connect(
            applicationResetColumnsAction,
            &QAction::triggered,
            this,
            [this]() {
                applyRecommendedApplicationHeaderLayout(
                    true);
            });

        applicationColumnsMenu->addSeparator();
        auto *applicationSettingsAction =
            applicationColumnsMenu->addAction(
                QStringLiteral("Settings…"));
        applicationSettingsAction->setToolTip(
            QStringLiteral("Open TotalSweep restore and cleanup settings."));
        connect(
            applicationSettingsAction,
            &QAction::triggered,
            this,
            [this]() {
                showAdvancedSettingsDialog();
            });

        connect(
            applicationColumnsMenu,
            &QMenu::aboutToShow,
            this,
            [this]() {
                syncApplicationColumnMenu();
            });

        layout->addLayout(filterRow);

        applicationModel =
            new ApplicationTableModel(this);

        applicationView =
            new ApplicationTableView();

        applicationView->setHorizontalHeader(
            new AutoScrollApplicationHeader(
                applicationView));

        applicationView->setEmptyMessage(
            QStringLiteral(
                "Loading installed applications…"));

        applicationView->setModel(
            applicationModel);

        applicationTableDelegate =
            new ApplicationTableDelegate(
                applicationView);

        applicationView->setItemDelegate(
            applicationTableDelegate);

        applicationView
            ->setColumnSeparatorsEnabled(
                applicationColumnSeparators);
        applicationView
            ->setRowSeparatorsEnabled(
                applicationRowSeparators);

        applicationView->setFocusPolicy(
            Qt::StrongFocus);

        applicationView->setToolTip(
            "Click anywhere on a removable row to toggle it. "
            "Click a cell and press Ctrl+C to copy its text. "
            "For Install Location and Description, drag the column edge against "
            "the right side of the window to keep expanding while the table auto-scrolls.");

        applicationView->setMouseTracking(true);
        applicationView->viewport()->setMouseTracking(true);
        applicationView->viewport()->installEventFilter(this);

        connect(
            applicationView,
            &QTableView::entered,
            this,
            [this](const QModelIndex &index) {

                if (!applicationModel)
                    return;

                applicationModel->setHoveredRow(
                    index.isValid()
                        ? index.row()
                        : -1);
            });

        applicationView->setAlternatingRowColors(
            true);

        applicationView->setSelectionMode(
            QAbstractItemView::NoSelection);

        applicationView->setShowGrid(false);

        applyApplicationTableStyle();

        applicationView->verticalHeader()
            ->setVisible(false);

        applicationView->verticalHeader()
            ->setDefaultSectionSize(38);

        applicationView->setIconSize(
            QSize(32, 32));

        applicationView->setWordWrap(false);

        applicationView->setTextElideMode(
            Qt::ElideNone);

        applicationView->setHorizontalScrollBarPolicy(
            Qt::ScrollBarAsNeeded);

        applicationView->setHorizontalScrollMode(
            QAbstractItemView::ScrollPerPixel);

        applicationView->setVerticalScrollMode(
            QAbstractItemView::ScrollPerPixel);

        auto *header =
            applicationView->horizontalHeader();

        header->setStretchLastSection(false);
        header->setSectionsMovable(true);
        header->setSectionsClickable(true);
        header->setSortIndicatorShown(true);

        connect(
            header,
            &QHeaderView::sectionResized,
            this,
            [this](int, int, int) {
                syncApplicationHorizontalScrollBar();
            });

        connect(
            header,
            &QHeaderView::sectionMoved,
            this,
            [this](int, int, int) {
                syncApplicationHorizontalScrollBar();
            });

        for (int column = 0;
             column < 8;
             ++column) {

            header->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        applicationView->setColumnWidth(0, 285);
        applicationView->setColumnWidth(1, 145);
        applicationView->setColumnWidth(2, 140);
        applicationView->setColumnWidth(3, 100);
        applicationView->setColumnWidth(4, 360);
        applicationView->setColumnWidth(5, 125);
        applicationView->setColumnWidth(6, 420);
        applicationView->setColumnWidth(7, 225);

        applicationView->setSortingEnabled(true);

        restoreApplicationHeader();

        for (int column = 0;
             column < 8;
             ++column) {

            header->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        restoreApplicationColumnVisibility();
        syncApplicationColumnMenu();

        applicationModel->sort(
            header->sortIndicatorSection(),
            header->sortIndicatorOrder());

        layout->addWidget(
            applicationView,
            1);

        connect(
            applicationView,
            &QTableView::clicked,
            this,
            [this](const QModelIndex &index) {

                if (!applicationModel ||
                    !index.isValid() ||
                    !applicationDataFresh ||
                    applicationRefreshRunning) {

                    return;
                }

                applicationView->setCurrentIndex(
                    index);

                applicationModel
                    ->toggleVisibleRow(
                        index.row());
            });

        auto *copyShortcut =
            new QShortcut(
                QKeySequence(
                    QKeySequence::Copy),
                applicationView);

        copyShortcut->setContext(
            Qt::WidgetWithChildrenShortcut);

        connect(
            copyShortcut,
            &QShortcut::activated,
            this,
            [this]() {

                if (!applicationView ||
                    !applicationModel) {

                    return;
                }

                const QModelIndex current =
                    applicationView
                        ->currentIndex();

                if (!current.isValid())
                    return;

                const QString value =
                    applicationModel
                        ->data(
                            current,
                            Qt::DisplayRole)
                        .toString();

                if (value.isEmpty())
                    return;

                QApplication::clipboard()
                    ->setText(value);
            });


        auto *spaceShortcut =
            new QShortcut(
                QKeySequence(Qt::Key_Space),
                applicationView);

        spaceShortcut->setContext(
            Qt::WidgetWithChildrenShortcut);

        connect(
            spaceShortcut,
            &QShortcut::activated,
            this,
            [this]() {

                if (!applicationView ||
                    !applicationModel ||
                    !applicationDataFresh ||
                    applicationRefreshRunning) {

                    return;
                }

                const QModelIndex current =
                    applicationView
                        ->currentIndex();

                if (!current.isValid())
                    return;

                applicationModel
                    ->toggleVisibleRow(
                        current.row());
            });

        auto *footer =
            new QHBoxLayout();

        footer->setContentsMargins(
            0,
            2,
            0,
            0);

        footer->setSpacing(10);

        clearApplicationsBtn =
            new QPushButton(
                "Clear Selection");

        uninstallSelectedBtn =
            new QPushButton(
                "Uninstall Selected");

        configureMonochromeButton(
            clearApplicationsBtn,
            {
                QStringLiteral("dialog-close"),
                QStringLiteral("window-close")
            },
            QStyle::SP_DialogCloseButton,
            QSize(18, 18));

        clearApplicationsBtn->setFlat(false);
        clearApplicationsBtn->setEnabled(false);
        clearApplicationsBtn->setToolTip(
            QStringLiteral(
                "Clear the current application selection. Nothing is removed."));

        configureMonochromeButton(
            uninstallSelectedBtn,
            {
                QStringLiteral("edit-delete"),
                QStringLiteral("edit-delete-shred")
            },
            QStyle::SP_TrashIcon,
            QSize(18, 18));

        uninstallSelectedBtn->setEnabled(false);
        uninstallSelectedBtn->setToolTip(
            QStringLiteral(
                "Uninstall the selected applications. A confirmation is required before removal."));

        footer->addWidget(
            applicationStatus,
            1);

        auto *applicationActions =
            new QHBoxLayout();
        applicationActions->setContentsMargins(0, 0, 0, 0);
        applicationActions->setSpacing(8);
        applicationActions->addWidget(clearApplicationsBtn);
        applicationActions->addWidget(uninstallSelectedBtn);

        footer->addLayout(applicationActions);

        layout->addLayout(footer);

        pages->addWidget(
            uninstallTab);

        connect(
            applicationFilterGroup,
            &QButtonGroup::idClicked,
            this,
            [this](int mode) {

                if (!applicationModel)
                    return;

                applicationModel->setFilterMode(
                    mode);

                updateApplicationStatus();
            });

        connect(
            clearApplicationsBtn,
            &QPushButton::clicked,
            this,
            [this]() {

                if (applicationModel)
                    applicationModel
                        ->clearChecks();

                updateApplicationSelection();
            });

        connect(
            applicationModel,
            &QAbstractItemModel::dataChanged,
            this,
            [this]() {

                updateApplicationSelection();
            });

        connect(
            uninstallSelectedBtn,
            &QPushButton::clicked,
            this,
            [this]() {

                uninstallSelectedApplications();
            });
    }

    void buildLeftoversTab()
    {
        leftoversTab =
        new QWidget();

        auto *layout =
        new QVBoxLayout(
            leftoversTab);

        auto *leftoversSearchRow =
            new QHBoxLayout();

        leftoversSearch =
            new QLineEdit(leftoversTab);

        leftoversSearch->setPlaceholderText(
            QStringLiteral(
                "Search leftovers by application name…"));

        leftoversSearch->setClearButtonEnabled(true);

        leftoversSearch->setToolTip(
            QStringLiteral(
                "You can start typing anywhere in TotalSweep while "
                "this page is active. Type 3 or more characters for "
                "automatic Leftovers search. For a 1- or 2-character "
                "search, press Enter. Ctrl+F focuses this field and "
                "Escape clears it."));

        leftoversSearchRow->addWidget(
            leftoversSearch,
            1);

        leftoversViewMenu = new QMenu(this);

        leftoversColumnsSubmenu = leftoversViewMenu->addMenu(
            QStringLiteral("Columns"));
        leftoversColumnsSubmenu->setToolTip(
            QStringLiteral("Choose which Leftovers columns are visible."));

        const QStringList leftoverColumnNames = {
            QStringLiteral("Item"),
            QStringLiteral("Location"),
            QStringLiteral("Type"),
            QStringLiteral("Size"),
            QStringLiteral("Last Modified"),
            QStringLiteral("Risk")
        };

        for (int column = 0;
             column < leftoverColumnNames.size();
             ++column) {

            auto *check = new QCheckBox(
                leftoverColumnNames.at(column),
                leftoversColumnsSubmenu);

            const QString key = QString(
                "leftovers/column-visible/%1")
                .arg(column);
            const bool visible = column == 0 ||
                !settings ||
                settings->value(key, true).toBool();

            check->setChecked(visible);
            check->setContentsMargins(8, 4, 12, 4);

            if (column == 0) {
                check->setEnabled(false);
                check->setToolTip(
                    QStringLiteral("Item is always visible."));
            }

            auto *action = new QWidgetAction(
                leftoversColumnsSubmenu);
            action->setDefaultWidget(check);
            leftoversColumnsSubmenu->addAction(action);
            leftoversColumnChecks.insert(column, check);

            connect(
                check,
                &QCheckBox::toggled,
                this,
                [this, column](bool visible) {
                    if (!results || column == 0)
                        return;

                    results->setColumnHidden(column, !visible);
                    updateLeftoversColumnResizeModes();
                    if (settings) {
                        settings->setValue(
                            QString("leftovers/column-visible/%1")
                                .arg(column),
                            visible);
                        settings->sync();
                    }
                });
        }

        leftoversSeparatorsSubmenu = leftoversViewMenu->addMenu(
            QStringLiteral("Separators"));
        leftoversSeparatorsSubmenu->setToolTip(
            QStringLiteral("Choose subtle row and column dividers for Leftovers."));

        auto addLeftoversSeparatorToggle =
            [this](const QString &text,
                   const QString &tooltip,
                   bool checked,
                   QCheckBox *&target,
                   const char *settingsKey,
                   bool &state) {
                target = new QCheckBox(
                    text,
                    leftoversSeparatorsSubmenu);
                target->setChecked(checked);
                target->setContentsMargins(8, 4, 12, 4);
                target->setToolTip(tooltip);
                auto *action = new QWidgetAction(
                    leftoversSeparatorsSubmenu);
                action->setDefaultWidget(target);
                leftoversSeparatorsSubmenu->addAction(action);
                connect(target, &QCheckBox::toggled, this,
                    [this, settingsKey, statePtr = &state](bool enabled) {
                        *statePtr = enabled;
                        if (settings) {
                            settings->setValue(
                                QString::fromLatin1(settingsKey),
                                enabled);
                            settings->sync();
                        }
                        applySecondaryTableSeparators();
                    });
            };

        addLeftoversSeparatorToggle(
            QStringLiteral("Column separators"),
            QStringLiteral("Show subtle vertical separators between Leftovers columns."),
            leftoversColumnSeparators,
            leftoversColumnSeparatorsCheck,
            "leftovers/columnSeparators",
            leftoversColumnSeparators);
        addLeftoversSeparatorToggle(
            QStringLiteral("Row separators"),
            QStringLiteral("Show subtle horizontal separators between Leftovers rows."),
            leftoversRowSeparators,
            leftoversRowSeparatorsCheck,
            "leftovers/rowSeparators",
            leftoversRowSeparators);

        leftoversViewMenu->addSeparator();
        auto *resetLeftoversLayout = leftoversViewMenu->addAction(
            QStringLiteral("Reset Table Layout"));
        connect(
            resetLeftoversLayout,
            &QAction::triggered,
            this,
            [this]() {
                if (!results)
                    return;

                QHeaderView *header = results->header();
                for (int logical = 0; logical < 6; ++logical) {
                    results->setColumnHidden(logical, false);
                    const int visual = header->visualIndex(logical);
                    if (visual >= 0 && visual != logical)
                        header->moveSection(visual, logical);

                    if (QCheckBox *check = leftoversColumnChecks.value(logical)) {
                        const QSignalBlocker blocker(check);
                        check->setChecked(true);
                    }

                    if (settings && logical > 0) {
                        settings->setValue(
                            QString("leftovers/column-visible/%1")
                                .arg(logical),
                            true);
                    }
                }

                applyRecommendedLeftoversHeaderLayout(
                    true);

                if (settings)
                    settings->sync();
            });

        leftoversViewMenu->addSeparator();
        auto *leftoversSettingsAction =
            leftoversViewMenu->addAction(QStringLiteral("Settings…"));
        leftoversSettingsAction->setToolTip(
            QStringLiteral("Open TotalSweep restore and cleanup settings."));
        connect(
            leftoversSettingsAction,
            &QAction::triggered,
            this,
            [this]() {
                showAdvancedSettingsDialog();
            });

        layout->addLayout(
            leftoversSearchRow);

        resultStatus =
        new QLabel(
            "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter.");

        resultStatus->setWordWrap(true);

        layout->addWidget(
            resultStatus);

        leftoversSearchDebounce =
            new QTimer(this);

        leftoversSearchDebounce->setSingleShot(true);
        leftoversSearchDebounce->setInterval(700);

        auto submitLeftoversSearch =
            [this](bool allowShortQuery) {
                if (!leftoversSearch)
                    return;

                const QString query =
                    leftoversSearch->text().trimmed();

                if (query.isEmpty()) {
                    if (postUninstallBatchActive ||
                        leftoverScanRunning ||
                        leftoverHomeProcess ||
                        leftoverSystemProcess ||
                        !pendingLeftoverItems.isEmpty()) {

                        stopLeftoverScan();
                    }

                    if (results) {
                        setHoveredLeftoverItem(nullptr);
                        pressedLeftoverItem = nullptr;
                        results->clear();
                        results->setEmptyMessage(
                            QStringLiteral(
                                "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
                    }

                    resultStatus->setText(
                        QStringLiteral(
                            "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
                    return;
                }

                if (query.size() < 3 &&
                    !allowShortQuery) {

                    if (postUninstallBatchActive ||
                        leftoverScanRunning ||
                        leftoverHomeProcess ||
                        leftoverSystemProcess ||
                        !pendingLeftoverItems.isEmpty()) {

                        stopLeftoverScan();
                    }

                    if (results) {
                        setHoveredLeftoverItem(nullptr);
                        pressedLeftoverItem = nullptr;
                        results->clear();
                        results->setEmptyMessage(
                            QStringLiteral(
                                "Press Enter to search with 1–2 characters, or keep typing for automatic search."));
                    }

                    resultStatus->setText(
                        QStringLiteral(
                            "Press Enter to search with 1–2 characters, or keep typing for automatic search."));
                    return;
                }

                if (leftoverScanRunning &&
                    currentApp.compare(
                        query,
                        Qt::CaseInsensitive) == 0) {

                    return;
                }

                scanLeftoversAsync(query);
            };

        connect(
            leftoversSearchDebounce,
            &QTimer::timeout,
            this,
            [this, submitLeftoversSearch]() {
                if (pages &&
                    pages->currentIndex() == 1) {

                    submitLeftoversSearch(false);
                }
            });

        connect(
            leftoversSearch,
            &QLineEdit::textChanged,
            this,
            [this](const QString &text) {
                if (leftoversSearchDebounce)
                    leftoversSearchDebounce->stop();

                if (postUninstallBatchActive ||
                    leftoverScanRunning ||
                    leftoverHomeProcess ||
                    leftoverSystemProcess ||
                    !pendingLeftoverItems.isEmpty()) {

                    stopLeftoverScan();
                }

                const QString query =
                    text.trimmed();

                if (results) {
                    setHoveredLeftoverItem(nullptr);
                    pressedLeftoverItem = nullptr;
                    results->clear();

                    if (query.isEmpty()) {
                        results->setEmptyMessage(
                            QStringLiteral(
                                "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
                    }
                    else if (query.size() < 3) {
                        results->setEmptyMessage(
                            QStringLiteral(
                                "Press Enter to search with 1–2 characters, or keep typing for automatic search."));
                    }
                    else {
                        results->setEmptyMessage(
                            QStringLiteral(
                                "Waiting for typing to pause…"));
                    }
                }

                if (query.isEmpty()) {
                    resultStatus->setText(
                        QStringLiteral(
                            "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));
                    return;
                }

                if (query.size() < 3) {
                    resultStatus->setText(
                        QStringLiteral(
                            "Press Enter to search with 1–2 characters, or keep typing for automatic search."));
                    return;
                }

                resultStatus->setText(
                    QStringLiteral(
                        "Waiting for typing to pause…"));

                if (pages &&
                    pages->currentIndex() == 1 &&
                    leftoversSearchDebounce) {

                    leftoversSearchDebounce->start();
                }
            });

        connect(
            leftoversSearch,
            &QLineEdit::returnPressed,
            this,
            [this, submitLeftoversSearch]() {
                if (leftoversSearchDebounce)
                    leftoversSearchDebounce->stop();

                submitLeftoversSearch(true);
            });

        scanProgress =
        new QProgressBar();

        scanProgress->setRange(
            0,
            100);

        scanProgress->setValue(0);

        scanProgress->setVisible(false);

        auto *scanRow =
            new QHBoxLayout();

        scanRow->addWidget(
            scanProgress,
            1);

        cancelLeftoverScanBtn =
            new QPushButton(
                QStringLiteral("Cancel Scan"));

        cancelLeftoverScanBtn->setVisible(false);

        configureMonochromeButton(
            cancelLeftoverScanBtn,
            {
                QStringLiteral("process-stop"),
                QStringLiteral("dialog-cancel")
            },
            QStyle::SP_DialogCancelButton,
            QSize(18, 18));

        scanRow->addWidget(
            cancelLeftoverScanBtn);

        layout->addLayout(
            scanRow);

        connect(
            cancelLeftoverScanBtn,
            &QPushButton::clicked,
            this,
            [this]() {
                stopLeftoverScan();

                resultStatus->setText(
                    QStringLiteral(
                        "Leftovers scan cancelled."));

                if (results &&
                    results->topLevelItemCount() == 0) {
                    results->setEmptyMessage(
                        QStringLiteral(
                            "Leftovers scan cancelled."));
                }
            });

        results =
        new EmptyStateTreeWidget();

        results->setColumnCount(6);

        results->setHeaderLabels(
            {
                "Item",
                "Location",
                "Type",
                "Size",
                "Last Modified",
                "Risk"
            });

        results->setAlternatingRowColors(true);
        results->setRootIsDecorated(true);

        results->setSelectionMode(
            QAbstractItemView::NoSelection);
        results->setSelectionBehavior(
            QAbstractItemView::SelectRows);
        results->setMouseTracking(true);
        results->viewport()->setMouseTracking(true);
        results->viewport()->installEventFilter(this);
        results->setIconSize(QSize(24, 24));
        results->setTextElideMode(Qt::ElideNone);
        results->setHorizontalScrollBarPolicy(
            Qt::ScrollBarAsNeeded);
        results->setHorizontalScrollMode(
            QAbstractItemView::ScrollPerPixel);
        results->setVerticalScrollMode(
            QAbstractItemView::ScrollPerPixel);
        results->setColumnSeparatorsEnabled(leftoversColumnSeparators);
        results->setRowSeparatorsEnabled(leftoversRowSeparators);

        results->setEmptyMessage(
            QStringLiteral(
                "Type 3 or more characters for automatic Leftovers search. For 1–2 characters, press Enter."));

        auto *header =
        results->header();

        header->setSectionsMovable(true);
        header->setStretchLastSection(false);

        for (int column = 0; column < 6; ++column) {
            header->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        results->setColumnWidth(0, 260);
        results->setColumnWidth(1, 520);
        results->setColumnWidth(2, 105);
        results->setColumnWidth(3, 100);
        results->setColumnWidth(4, 165);
        results->setColumnWidth(5, 150);

        restoreHeader();

        for (int column = 1; column < 6; ++column) {
            const QString key = QString(
                "leftovers/column-visible/%1")
                .arg(column);
            const bool visible = !settings ||
                settings->value(key, true).toBool();
            results->setColumnHidden(column, !visible);

            if (QCheckBox *check = leftoversColumnChecks.value(column)) {
                const QSignalBlocker blocker(check);
                check->setChecked(visible);
            }
        }
        results->setColumnHidden(0, false);
        updateLeftoversColumnResizeModes();

        connect(
            header,
            &QHeaderView::sectionResized,
            this,
            [this](int, int, int) {
                syncTreeHorizontalScrollBar(results);
                saveHeader();
            });

        connect(
            header,
            &QHeaderView::sectionMoved,
            this,
            [this](int, int, int) {
                syncTreeHorizontalScrollBar(results);
                saveHeader();
            });

        layout->addWidget(
            results,
            1);

        auto *buttons =
        new QHBoxLayout();

        auto *select =
        new QPushButton(
            "Select All Recommended");

        auto *clear =
        new QPushButton(
            "Clear Selection");

        openLeftoverLocationBtn =
        new QPushButton(
            "Open File Location");
        openLeftoverLocationBtn->setEnabled(false);
        openLeftoverLocationBtn->setToolTip(
            QStringLiteral(
                "Click a leftover row to toggle it for cleanup. "
                "The highlighted row can also be opened in Dolphin."));

        quarantineSelectedBtn =
        new QPushButton(
            "Quarantine Selected");

        configureMonochromeButton(
            select,
            { QStringLiteral("edit-select-all") },
            QStyle::SP_DialogApplyButton);

        configureMonochromeButton(
            clear,
            {
                QStringLiteral("dialog-close"),
                QStringLiteral("window-close")
            },
            QStyle::SP_DialogCloseButton,
            QSize(18, 18));

        clear->setToolTip(
            QStringLiteral(
                "Clear every checked Leftovers row. Nothing is deleted."));

        configureMonochromeButton(
            openLeftoverLocationBtn,
            { QStringLiteral("document-open-folder") },
            QStyle::SP_DirOpenIcon);

        configureMonochromeButton(
            quarantineSelectedBtn,
            {
                QStringLiteral("document-save"),
                QStringLiteral("folder-locked")
            },
            QStyle::SP_DialogSaveButton);

        quarantineSelectedBtn->setEnabled(
            false);

        buttons->addWidget(select);
        buttons->addWidget(clear);
        buttons->addStretch();
        buttons->addWidget(openLeftoverLocationBtn);
        buttons->addWidget(
            quarantineSelectedBtn);

        layout->addLayout(buttons);

        connect(
            select,
            &QPushButton::clicked,
            this,
            [this]() {

                setRecommended();
            });

        connect(
            clear,
            &QPushButton::clicked,
            this,
            [this]() {

                setAll(false);
            });

        connect(
            openLeftoverLocationBtn,
            &QPushButton::clicked,
            this,
            [this]() {
                openCurrentLeftoverLocation();
            });

        connect(
            results,
            &QTreeWidget::itemEntered,
            this,
            [this](QTreeWidgetItem *item, int) {
                setHoveredLeftoverItem(item);
            });

        connect(
            results,
            &QTreeWidget::itemPressed,
            this,
            [this](QTreeWidgetItem *item, int) {
                pressedLeftoverItem = nullptr;
                if (!item ||
                    !(item->flags() & Qt::ItemIsUserCheckable)) {
                    return;
                }
                pressedLeftoverItem = item;
                pressedLeftoverCheckState = item->checkState(0);
            });

        connect(
            results,
            &QTreeWidget::itemClicked,
            this,
            [this](QTreeWidgetItem *item, int) {
                if (!item || item != pressedLeftoverItem)
                    return;

                results->setCurrentItem(item);

                if (item->childCount() > 0) {
                    const Qt::CheckState target =
                        pressedLeftoverCheckState == Qt::Checked
                            ? Qt::Unchecked
                            : Qt::Checked;

                    const QSignalBlocker blocker(results);
                    for (int i = 0;
                         i < item->childCount();
                         ++i) {
                        QTreeWidgetItem *child = item->child(i);
                        if (child &&
                            (child->flags() & Qt::ItemIsUserCheckable)) {
                            child->setCheckState(0, target);
                        }
                    }
                    item->setCheckState(0, target);

                    refreshSecondaryTreeVisuals();
                    updateQuarantineButton();
                }
                else if (item->checkState(0) ==
                         pressedLeftoverCheckState) {
                    item->setCheckState(
                        0,
                        pressedLeftoverCheckState == Qt::Checked
                            ? Qt::Unchecked
                            : Qt::Checked);
                }

                pressedLeftoverItem = nullptr;
            });

        connect(
            results,
            &QTreeWidget::itemChanged,
            this,
            [this](QTreeWidgetItem *item, int) {
                if (item) {
                    refreshSecondaryItemVisual(
                        results,
                        item,
                        item == hoveredLeftoverItem);

                    if (item->childCount() == 0 && item->parent()) {
                        refreshSecondaryItemVisual(
                            results,
                            item->parent(),
                            item->parent() == hoveredLeftoverItem);
                    }
                }

                updateQuarantineButton();
            });

        auto *leftoversSpaceShortcut =
            new QShortcut(
                QKeySequence(Qt::Key_Space),
                results);

        leftoversSpaceShortcut->setContext(
            Qt::WidgetWithChildrenShortcut);

        connect(
            leftoversSpaceShortcut,
            &QShortcut::activated,
            this,
            [this]() {
                if (!results)
                    return;

                QTreeWidgetItem *item =
                    results->currentItem();

                if (!item ||
                    !(item->flags() & Qt::ItemIsUserCheckable)) {

                    return;
                }

                if (item->childCount() > 0) {
                    const Qt::CheckState target =
                        item->checkState(0) == Qt::Checked
                            ? Qt::Unchecked
                            : Qt::Checked;
                    const QSignalBlocker blocker(results);
                    for (int i = 0;
                         i < item->childCount();
                         ++i) {
                        QTreeWidgetItem *child = item->child(i);
                        if (child &&
                            (child->flags() & Qt::ItemIsUserCheckable)) {
                            child->setCheckState(0, target);
                        }
                    }
                    item->setCheckState(0, target);
                    refreshSecondaryTreeVisuals();
                    updateQuarantineButton();
                }
                else {
                    item->setCheckState(
                        0,
                        item->checkState(0) == Qt::Checked
                            ? Qt::Unchecked
                            : Qt::Checked);
                }
            });

        connect(
            results,
            &QTreeWidget::itemDoubleClicked,
            this,
            [this](QTreeWidgetItem *, int) {
                openCurrentLeftoverLocation();
            });

        connect(
            quarantineSelectedBtn,
            &QPushButton::clicked,
            this,
            [this]() {

                quarantineSelected();
            });

        pages->addWidget(
            leftoversTab);
    }

    void buildHistoryTab()
    {
        historyTab =
        new QWidget();

        auto *layout =
        new QVBoxLayout(
            historyTab);

        auto *quarantineSearchRow =
            new QHBoxLayout();

        quarantineSearch =
            new QLineEdit(historyTab);

        quarantineSearch->setPlaceholderText(
            QStringLiteral(
                "Search quarantine…"));

        quarantineSearch->setClearButtonEnabled(true);

        quarantineSearch->setToolTip(
            QStringLiteral(
                "Results update automatically as you type. "
                "You can start typing anywhere in TotalSweep while "
                "this page is active. Ctrl+F focuses this field and "
                "Escape clears it. This search is limited to the "
                "Quarantine page."));

        quarantineSearchRow->addWidget(
            quarantineSearch,
            1);

        quarantineViewMenu = new QMenu(this);

        quarantineColumnsSubmenu = quarantineViewMenu->addMenu(
            QStringLiteral("Columns"));
        quarantineColumnsSubmenu->setToolTip(
            QStringLiteral("Choose which Quarantine columns are visible."));

        const QStringList quarantineColumnNames = {
            QStringLiteral("Entry"),
            QStringLiteral("Type"),
            QStringLiteral("Original Location"),
            QStringLiteral("Size"),
            QStringLiteral("Removed"),
            QStringLiteral("Restore Status")
        };

        for (int column = 0;
             column < quarantineColumnNames.size();
             ++column) {

            auto *check = new QCheckBox(
                quarantineColumnNames.at(column),
                quarantineColumnsSubmenu);

            const QString key = QString(
                "quarantine/column-visible/%1")
                .arg(column);
            const bool visible = column == 0 ||
                !settings ||
                settings->value(key, true).toBool();

            check->setChecked(visible);
            check->setContentsMargins(8, 4, 12, 4);

            if (column == 0) {
                check->setEnabled(false);
                check->setToolTip(
                    QStringLiteral("Entry is always visible."));
            }

            auto *action = new QWidgetAction(
                quarantineColumnsSubmenu);
            action->setDefaultWidget(check);
            quarantineColumnsSubmenu->addAction(action);
            quarantineColumnChecks.insert(column, check);

            connect(
                check,
                &QCheckBox::toggled,
                this,
                [this, column](bool visible) {
                    if (!historyTree || column == 0)
                        return;

                    historyTree->setColumnHidden(column, !visible);
                    updateQuarantineColumnResizeModes();
                    if (settings) {
                        settings->setValue(
                            QString("quarantine/column-visible/%1")
                                .arg(column),
                            visible);
                        settings->sync();
                    }
                });
        }

        quarantineSeparatorsSubmenu = quarantineViewMenu->addMenu(
            QStringLiteral("Separators"));
        quarantineSeparatorsSubmenu->setToolTip(
            QStringLiteral("Choose subtle row and column dividers for Quarantine."));

        auto addQuarantineSeparatorToggle =
            [this](const QString &text,
                   const QString &tooltip,
                   bool checked,
                   QCheckBox *&target,
                   const char *settingsKey,
                   bool &state) {
                target = new QCheckBox(
                    text,
                    quarantineSeparatorsSubmenu);
                target->setChecked(checked);
                target->setContentsMargins(8, 4, 12, 4);
                target->setToolTip(tooltip);
                auto *action = new QWidgetAction(
                    quarantineSeparatorsSubmenu);
                action->setDefaultWidget(target);
                quarantineSeparatorsSubmenu->addAction(action);
                connect(target, &QCheckBox::toggled, this,
                    [this, settingsKey, statePtr = &state](bool enabled) {
                        *statePtr = enabled;
                        if (settings) {
                            settings->setValue(
                                QString::fromLatin1(settingsKey),
                                enabled);
                            settings->sync();
                        }
                        applySecondaryTableSeparators();
                    });
            };

        addQuarantineSeparatorToggle(
            QStringLiteral("Column separators"),
            QStringLiteral("Show subtle vertical separators between Quarantine columns."),
            quarantineColumnSeparators,
            quarantineColumnSeparatorsCheck,
            "quarantine/columnSeparators",
            quarantineColumnSeparators);
        addQuarantineSeparatorToggle(
            QStringLiteral("Row separators"),
            QStringLiteral("Show subtle horizontal separators between Quarantine entries."),
            quarantineRowSeparators,
            quarantineRowSeparatorsCheck,
            "quarantine/rowSeparators",
            quarantineRowSeparators);

        quarantineViewMenu->addSeparator();
        auto *resetQuarantineLayout = quarantineViewMenu->addAction(
            QStringLiteral("Reset Table Layout"));
        connect(
            resetQuarantineLayout,
            &QAction::triggered,
            this,
            [this]() {
                if (!historyTree)
                    return;

                QHeaderView *header = historyTree->header();
                for (int logical = 0; logical < 6; ++logical) {
                    historyTree->setColumnHidden(logical, false);
                    const int visual = header->visualIndex(logical);
                    if (visual >= 0 && visual != logical)
                        header->moveSection(visual, logical);

                    if (QCheckBox *check = quarantineColumnChecks.value(logical)) {
                        const QSignalBlocker blocker(check);
                        check->setChecked(true);
                    }

                    if (settings && logical > 0) {
                        settings->setValue(
                            QString("quarantine/column-visible/%1")
                                .arg(logical),
                            true);
                    }
                }

                applyRecommendedQuarantineHeaderLayout(
                    true);

                if (settings)
                    settings->sync();
            });

        quarantineViewMenu->addSeparator();
        auto *quarantineSettingsAction =
            quarantineViewMenu->addAction(QStringLiteral("Settings…"));
        quarantineSettingsAction->setToolTip(
            QStringLiteral("Open TotalSweep restore and cleanup settings."));
        connect(
            quarantineSettingsAction,
            &QAction::triggered,
            this,
            [this]() {
                showAdvancedSettingsDialog();
            });

        layout->addLayout(
            quarantineSearchRow);

        quarantineInfoLabel = new QLabel(historyTab);
        quarantineInfoLabel->setWordWrap(true);
        layout->addWidget(quarantineInfoLabel);
        updateQuarantineInfoLabel();

        quarantineSearchDebounce =
            new QTimer(this);

        quarantineSearchDebounce->setSingleShot(true);
        quarantineSearchDebounce->setInterval(140);

        connect(
            quarantineSearchDebounce,
            &QTimer::timeout,
            this,
            [this]() {
                if (pages &&
                    pages->currentIndex() == 2) {

                    applyQuarantineSearch();
                }
            });

        connect(
            quarantineSearch,
            &QLineEdit::textChanged,
            this,
            [this](const QString &text) {
                if (quarantineSearchDebounce)
                    quarantineSearchDebounce->stop();

                if (text.trimmed().isEmpty()) {
                    applyQuarantineSearch();
                    return;
                }

                if (pages &&
                    pages->currentIndex() == 2 &&
                    quarantineSearchDebounce) {

                    quarantineSearchDebounce->start();
                }
            });

        connect(
            quarantineSearch,
            &QLineEdit::returnPressed,
            this,
            [this]() {
                if (quarantineSearchDebounce)
                    quarantineSearchDebounce->stop();

                applyQuarantineSearch();
            });

        historyTree =
        new EmptyStateTreeWidget();

        historyTree->setColumnCount(6);

        historyTree->setHeaderLabels(
            {
                "Entry",
                "Type",
                "Original Location",
                "Size",
                "Removed",
                "Restore Status"
            });

        historyTree->setEmptyMessage(
            QStringLiteral(
                "Quarantine is empty."));

        historyTree->setRootIsDecorated(false);
        QHeaderView *quarantineHeader = historyTree->header();
        quarantineHeader->setSectionsMovable(true);
        quarantineHeader->setStretchLastSection(false);
        for (int column = 0; column < 6; ++column) {
            quarantineHeader->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        historyTree->setColumnWidth(0, 280);
        historyTree->setColumnWidth(1, 140);
        historyTree->setColumnWidth(2, 420);
        historyTree->setColumnWidth(3, 100);
        historyTree->setColumnWidth(4, 170);
        historyTree->setColumnWidth(5, 260);
        historyTree->setSelectionMode(QAbstractItemView::NoSelection);
        historyTree->setSelectionBehavior(QAbstractItemView::SelectRows);
        historyTree->setMouseTracking(true);
        historyTree->viewport()->setMouseTracking(true);
        historyTree->viewport()->installEventFilter(this);
        historyTree->setIconSize(QSize(24, 24));
        historyTree->setTextElideMode(Qt::ElideNone);
        historyTree->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        historyTree->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        historyTree->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        historyTree->setColumnSeparatorsEnabled(quarantineColumnSeparators);
        historyTree->setRowSeparatorsEnabled(quarantineRowSeparators);

        restoreQuarantineHeader();

        for (int column = 1; column < 6; ++column) {
            const QString key = QString(
                "quarantine/column-visible/%1")
                .arg(column);
            const bool visible = !settings ||
                settings->value(key, true).toBool();
            historyTree->setColumnHidden(column, !visible);

            if (QCheckBox *check = quarantineColumnChecks.value(column)) {
                const QSignalBlocker blocker(check);
                check->setChecked(visible);
            }
        }
        historyTree->setColumnHidden(0, false);
        updateQuarantineColumnResizeModes();

        connect(
            quarantineHeader,
            &QHeaderView::sectionResized,
            this,
            [this](int, int, int) {
                syncTreeHorizontalScrollBar(historyTree);
                saveQuarantineHeader();
            });

        connect(
            quarantineHeader,
            &QHeaderView::sectionMoved,
            this,
            [this](int, int, int) {
                syncTreeHorizontalScrollBar(historyTree);
                saveQuarantineHeader();
            });

        layout->addWidget(
            historyTree,
            1);

        auto *historyButtons = new QHBoxLayout();

        clearQuarantineSelectionBtn =
            new QPushButton(
                QStringLiteral("Clear Selection"));

        openQuarantineBtn = new QPushButton(QStringLiteral("Open Quarantine"));
        restoreQuarantineBtn = new QPushButton(QStringLiteral("Restore Selected"));
        deleteQuarantineBtn = new QPushButton(QStringLiteral("Delete Permanently"));

        configureMonochromeButton(
            clearQuarantineSelectionBtn,
            {
                QStringLiteral("dialog-close"),
                QStringLiteral("window-close")
            },
            QStyle::SP_DialogCloseButton,
            QSize(18, 18));

        configureMonochromeButton(
            openQuarantineBtn,
            { QStringLiteral("document-open-folder") },
            QStyle::SP_DirOpenIcon);
        configureMonochromeButton(
            restoreQuarantineBtn,
            {QStringLiteral("view-history"), QStringLiteral("edit-undo"), QStringLiteral("document-revert")},
            QStyle::SP_BrowserReload);
        configureMonochromeButton(
            deleteQuarantineBtn,
            {QStringLiteral("edit-delete"), QStringLiteral("user-trash")},
            QStyle::SP_TrashIcon);

        clearQuarantineSelectionBtn->setEnabled(false);
        clearQuarantineSelectionBtn->setToolTip(
            QStringLiteral(
                "Clear every checked Quarantine row. Nothing is restored or deleted."));
        openQuarantineBtn->setEnabled(false);
        restoreQuarantineBtn->setEnabled(false);
        deleteQuarantineBtn->setEnabled(false);

        openQuarantineBtn->setToolTip(
            QStringLiteral("Open the selected TotalSweep Quarantine session in Dolphin. Select exactly one entry."));
        restoreQuarantineBtn->setToolTip(
            QStringLiteral("Restore the selected entry. Package restores are intentionally handled one entry at a time so version/fallback decisions stay explicit."));
        deleteQuarantineBtn->setToolTip(
            QStringLiteral("Permanently delete the selected Quarantine entries and their restore records. Shared package snapshots are only removed when nothing else references them."));

        historyButtons->addStretch();
        historyButtons->addWidget(clearQuarantineSelectionBtn);
        historyButtons->addWidget(openQuarantineBtn);
        historyButtons->addWidget(restoreQuarantineBtn);
        historyButtons->addWidget(deleteQuarantineBtn);
        layout->addLayout(historyButtons);

        connect(
            clearQuarantineSelectionBtn,
            &QPushButton::clicked,
            this,
            [this]() {
                clearQuarantineSelection();
            });

        connect(openQuarantineBtn, &QPushButton::clicked, this, [this]() {
            openSelectedQuarantine();
        });
        connect(restoreQuarantineBtn, &QPushButton::clicked, this, [this]() {
            restoreSelectedQuarantine();
        });
        connect(deleteQuarantineBtn, &QPushButton::clicked, this, [this]() {
            deleteSelectedQuarantine();
        });

        connect(
            historyTree,
            &QTreeWidget::itemEntered,
            this,
            [this](QTreeWidgetItem *item, int) {
                setHoveredQuarantineItem(item);
            });

        connect(
            historyTree,
            &QTreeWidget::itemPressed,
            this,
            [this](QTreeWidgetItem *item, int) {
                pressedQuarantineItem = item;
                pressedQuarantineCheckState =
                    item
                        ? item->checkState(0)
                        : Qt::Unchecked;
            });

        connect(
            historyTree,
            &QTreeWidget::itemClicked,
            this,
            [this](QTreeWidgetItem *item, int) {
                if (!item ||
                    item != pressedQuarantineItem ||
                    !(item->flags() & Qt::ItemIsUserCheckable)) {

                    pressedQuarantineItem = nullptr;
                    return;
                }

                historyTree->setCurrentItem(item);

                if (item->checkState(0) ==
                    pressedQuarantineCheckState) {

                    item->setCheckState(
                        0,
                        pressedQuarantineCheckState == Qt::Checked
                            ? Qt::Unchecked
                            : Qt::Checked);
                }

                pressedQuarantineItem = nullptr;
            });

        connect(
            historyTree,
            &QTreeWidget::itemChanged,
            this,
            [this](QTreeWidgetItem *item, int) {
                if (item) {
                    refreshSecondaryItemVisual(
                        historyTree,
                        item,
                        item == hoveredQuarantineItem);
                }

                updateQuarantineContextActions();
            });

        auto *quarantineSpaceShortcut =
            new QShortcut(
                QKeySequence(Qt::Key_Space),
                historyTree);

        quarantineSpaceShortcut->setContext(
            Qt::WidgetWithChildrenShortcut);

        connect(
            quarantineSpaceShortcut,
            &QShortcut::activated,
            this,
            [this]() {
                if (!historyTree)
                    return;

                QTreeWidgetItem *item =
                    historyTree->currentItem();

                if (!item ||
                    !(item->flags() & Qt::ItemIsUserCheckable)) {

                    return;
                }

                item->setCheckState(
                    0,
                    item->checkState(0) == Qt::Checked
                        ? Qt::Unchecked
                        : Qt::Checked);
            });

        pages->addWidget(
            historyTab);

        loadHistory();
    }

    void refreshSecondaryItemVisual(
        QTreeWidget *tree,
        QTreeWidgetItem *item,
        bool hovered)
    {
        if (!tree || !item)
            return;


        {
            const QSignalBlocker blocker(tree);
            item->setData(
                0,
                kSecondaryRowHoveredRole,
                hovered);
        }

        if (tree->viewport()) {
            const QRect rowRect =
                tree->visualItemRect(item);

            tree->viewport()->update(
                QRect(
                    0,
                    rowRect.top(),
                    tree->viewport()->width(),
                    rowRect.height()));
        }
    }


    void setHoveredLeftoverItem(
        QTreeWidgetItem *item)
    {
        if (hoveredLeftoverItem == item)
            return;

        QTreeWidgetItem *old =
            hoveredLeftoverItem;

        hoveredLeftoverItem = item;

        if (old)
            refreshSecondaryItemVisual(
                results,
                old,
                false);

        if (hoveredLeftoverItem)
            refreshSecondaryItemVisual(
                results,
                hoveredLeftoverItem,
                true);
    }


    void setHoveredQuarantineItem(
        QTreeWidgetItem *item)
    {
        if (hoveredQuarantineItem == item)
            return;

        QTreeWidgetItem *old =
            hoveredQuarantineItem;

        hoveredQuarantineItem = item;

        if (old)
            refreshSecondaryItemVisual(
                historyTree,
                old,
                false);

        if (hoveredQuarantineItem)
            refreshSecondaryItemVisual(
                historyTree,
                hoveredQuarantineItem,
                true);
    }


    void refreshSecondaryTreeVisuals()
    {
        if (results) {
            QTreeWidgetItemIterator iterator(results);
            while (*iterator) {
                QTreeWidgetItem *item = *iterator;
                ++iterator;

                if (!item)
                    continue;

                refreshSecondaryItemVisual(
                    results,
                    item,
                    item == hoveredLeftoverItem);
            }

            results->viewport()->update();
        }

        if (historyTree) {
            for (int i = 0;
                 i < historyTree->topLevelItemCount();
                 ++i) {

                QTreeWidgetItem *item =
                    historyTree->topLevelItem(i);

                refreshSecondaryItemVisual(
                    historyTree,
                    item,
                    item == hoveredQuarantineItem);
            }

            historyTree->viewport()->update();
        }
    }


    void syncTreeHorizontalScrollBar(
        QTreeWidget *tree)
    {
        if (!tree ||
            !tree->header() ||
            !tree->horizontalScrollBar() ||
            !tree->viewport()) {

            return;
        }

        const int viewportWidth =
            qMax(
                1,
                tree->viewport()->width());

        const int contentWidth =
            tree->header()->length();

        const int overflow =
            qMax(
                0,
                contentWidth - viewportWidth);

        QScrollBar *bar =
            tree->horizontalScrollBar();

        bar->setPageStep(
            viewportWidth);
        bar->setRange(
            0,
            overflow);

        if (overflow == 0)
            bar->setValue(0);

        bar->setVisible(
            overflow > 0);
    }


    void fitTreeColumnsToViewport(
        QTreeWidget *tree,
        const QList<int> &weights)
    {
        if (!tree ||
            !tree->header() ||
            !tree->viewport() ||
            tree->columnCount() != weights.size()) {

            return;
        }

        const int available =
            tree->viewport()->width();

        if (available < 200)
            return;

        QList<int> visibleColumns;
        int totalWeight = 0;

        for (int column = 0;
             column < weights.size();
             ++column) {

            if (tree->isColumnHidden(column))
                continue;

            visibleColumns.append(column);
            totalWeight += weights.at(column);
        }

        if (visibleColumns.isEmpty() ||
            totalWeight <= 0) {

            return;
        }

        int assigned = 0;

        for (int i = 0;
             i < visibleColumns.size();
             ++i) {

            const int column =
                visibleColumns.at(i);

            int width = 0;

            if (i == visibleColumns.size() - 1) {
                width =
                    available - assigned;
            }
            else {
                width =
                    qRound(
                        static_cast<double>(available) *
                        static_cast<double>(weights.at(column)) /
                        static_cast<double>(totalWeight));

                assigned += width;
            }

            width =
                qMax(
                    tree->header()->minimumSectionSize(),
                    width);

            tree->setColumnWidth(
                column,
                width);
        }

        syncTreeHorizontalScrollBar(tree);
    }


    void fitLeftoversColumnsToViewport()
    {
        fitTreeColumnsToViewport(
            results,
            {260, 520, 105, 100, 165, 150});
    }


    void fitQuarantineColumnsToViewport()
    {
        fitTreeColumnsToViewport(
            historyTree,
            {280, 140, 420, 100, 170, 260});
    }


    void updateLeftoversColumnResizeModes()
    {
        if (!results || !results->header())
            return;

        QHeaderView *header = results->header();
        header->setStretchLastSection(false);

        for (int column = 0;
             column < results->columnCount();
             ++column) {

            header->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        syncTreeHorizontalScrollBar(results);
    }


    void updateQuarantineColumnResizeModes()
    {
        if (!historyTree || !historyTree->header())
            return;

        QHeaderView *header = historyTree->header();
        header->setStretchLastSection(false);

        for (int column = 0;
             column < historyTree->columnCount();
             ++column) {

            header->setSectionResizeMode(
                column,
                QHeaderView::Interactive);
        }

        syncTreeHorizontalScrollBar(historyTree);
    }


    void applySecondaryTableSeparators()
    {
        if (results) {
            results->setColumnSeparatorsEnabled(leftoversColumnSeparators);
            results->setRowSeparatorsEnabled(leftoversRowSeparators);
        }
        if (historyTree) {
            historyTree->setColumnSeparatorsEnabled(quarantineColumnSeparators);
            historyTree->setRowSeparatorsEnabled(quarantineRowSeparators);
        }
    }


    QString applicationTableStyleSheet() const
    {
        return QStringLiteral(
            "QTableView::item {"
            " padding-left: 9px;"
            " padding-right: 9px;"
            "}");
    }


    void applyApplicationTableStyle()
    {
        if (!applicationView)
            return;

        applicationView->setStyleSheet(QString());
        applicationView->setStyleSheet(
            applicationTableStyleSheet());

        applicationView
            ->setColumnSeparatorsEnabled(
                applicationColumnSeparators);
        applicationView
            ->setRowSeparatorsEnabled(
                applicationRowSeparators);

        applicationView->viewport()->update();
        applicationView->horizontalHeader()
            ->viewport()
            ->update();
    }


    void refreshApplicationTheme()
    {
        if (!applicationView)
            return;

        const QPalette currentPalette =
            QApplication::palette();

        applicationView->setPalette(
            currentPalette);

        applicationView->viewport()->setPalette(
            currentPalette);

        applicationView->horizontalHeader()->setPalette(
            currentPalette);

        applicationView->verticalHeader()->setPalette(
            currentPalette);

        applyApplicationTableStyle();

        if (applicationModel)
            applicationModel->refreshTheme();

        refreshMonochromeIcons();

        applicationView->viewport()->update();
        applicationView->horizontalHeader()->viewport()->update();
        applicationView->verticalHeader()->viewport()->update();
        applicationView->update();
    }


    void restoreApplicationColumnVisibility()
    {
        if (!applicationView ||
            !settings) {
            return;
        }

        applicationView->setColumnHidden(
            0,
            false);

        for (int column = 1;
             column < 8;
             ++column) {

            const QString key =
                QString(
                    "applications/column-visible/%1")
                    .arg(column);

            if (!settings->contains(key))
                continue;

            applicationView->setColumnHidden(
                column,
                !settings->value(key, true)
                    .toBool());
        }
    }


    void syncApplicationColumnMenu()
    {
        if (!applicationView)
            return;

        for (auto it =
                 applicationColumnChecks.cbegin();
             it != applicationColumnChecks.cend();
             ++it) {

            QCheckBox *check =
                it.value();

            if (!check)
                continue;

            const int column =
                it.key();

            const bool visible =
                !applicationView
                    ->isColumnHidden(
                        column);

            const QSignalBlocker blocker(
                check);

            check->setChecked(
                visible);
        }

        if (applicationSeparatorsCheck) {

            const QSignalBlocker blocker(
                applicationSeparatorsCheck);

            applicationSeparatorsCheck->setChecked(
                applicationColumnSeparators);
        }

        if (applicationRowSeparatorsCheck) {
            const QSignalBlocker blocker(applicationRowSeparatorsCheck);
            applicationRowSeparatorsCheck->setChecked(applicationRowSeparators);
        }
    }


    void syncApplicationHorizontalScrollBar()
    {
        if (!applicationView)
            return;

        QHeaderView *header =
            applicationView->horizontalHeader();

        QScrollBar *bar =
            applicationView->horizontalScrollBar();

        QWidget *viewport =
            applicationView->viewport();

        if (!header ||
            !bar ||
            !viewport) {

            return;
        }

        const int viewportWidth =
            qMax(
                1,
                viewport->width());

        const int contentWidth =
            header->length();

        const int overflow =
            qMax(
                0,
                contentWidth -
                viewportWidth);

        bar->setPageStep(
            viewportWidth);

        bar->setRange(
            0,
            overflow);

        if (overflow == 0)
            bar->setValue(0);

        bar->setVisible(
            overflow > 0);
    }


    void fitRecommendedApplicationColumnsToViewport()
    {
        if (!applicationView)
            return;

        QHeaderView *header =
            applicationView->horizontalHeader();

        QWidget *viewport =
            applicationView->viewport();

        if (!header ||
            !viewport) {

            return;
        }

        const int available =
            viewport->width();

        if (available < 200)
            return;

        const QList<int> weights = {
            285,  
            145,  
            140,  
            100,  
            360,  
            125,  
            420,  
            225   
        };

        QList<int> visibleColumns;
        int totalWeight = 0;

        for (int column = 0;
             column < weights.size();
             ++column) {

            if (applicationView
                    ->isColumnHidden(
                        column)) {

                continue;
            }

            visibleColumns.append(
                column);

            totalWeight +=
                weights.at(
                    column);
        }

        if (visibleColumns.isEmpty() ||
            totalWeight <= 0) {

            return;
        }

        int assigned = 0;

        for (int i = 0;
             i < visibleColumns.size();
             ++i) {

            const int column =
                visibleColumns.at(i);

            int width = 0;

            if (i ==
                visibleColumns.size() - 1) {

                width =
                    available -
                    assigned;
            }
            else {

                width =
                    qRound(
                        static_cast<double>(
                            available) *
                        static_cast<double>(
                            weights.at(column)) /
                        static_cast<double>(
                            totalWeight));

                assigned +=
                    width;
            }

            width =
                qMax(
                    header->minimumSectionSize(),
                    width);

            applicationView->setColumnWidth(
                column,
                width);
        }

        syncApplicationHorizontalScrollBar();
    }


    void applyRecommendedApplicationHeaderLayout(
        bool resetVisibility = false)
    {
        if (!applicationView)
            return;

        QHeaderView *header =
            applicationView
                ->horizontalHeader();

        if (!header)
            return;

        const QList<int> recommendedOrder = {
            0,  
            7,  
            1,  
            3,  
            5,  
            2,  
            4,  
            6   
        };

        for (int visualIndex = 0;
             visualIndex < recommendedOrder.size();
             ++visualIndex) {

            const int logicalIndex =
                recommendedOrder.at(
                    visualIndex);

            const int currentVisual =
                header->visualIndex(
                    logicalIndex);

            if (currentVisual >= 0 &&
                currentVisual != visualIndex) {

                header->moveSection(
                    currentVisual,
                    visualIndex);
            }
        }

        if (resetVisibility) {

            for (int column = 0;
                 column < 8;
                 ++column) {

                applicationView
                    ->setColumnHidden(
                        column,
                        false);
            }

            syncApplicationColumnMenu();

            if (settings) {

                for (int column = 1;
                     column < 8;
                     ++column) {

                    settings->setValue(
                        QString(
                            "applications/column-visible/%1")
                            .arg(column),
                        true);
                }
            }
        }

        fitRecommendedApplicationColumnsToViewport();

        QTimer::singleShot(
            0,
            this,
            [this]() {
                fitRecommendedApplicationColumnsToViewport();
                saveApplicationHeader();
            });
    }


    void restoreApplicationHeader()
    {
        if (!applicationView)
            return;

        if (!settings) {

            applyRecommendedApplicationHeaderLayout();
            return;
        }

        const QByteArray state =
            settings->value(
                "applications/header-v8.2-eight-columns")
                .toByteArray();

        if (!state.isEmpty()) {

            applicationView
                ->horizontalHeader()
                ->restoreState(state);

            return;
        }

        applyRecommendedApplicationHeaderLayout();
    }


    void saveApplicationHeader()
    {
        if (!applicationView ||
            !settings) {

            return;
        }

        settings->setValue(
            "applications/header-v8.2-eight-columns",
            applicationView
                ->horizontalHeader()
                ->saveState());

        for (int column = 1;
             column < 8;
             ++column) {

            settings->setValue(
                QString(
                    "applications/column-visible/%1")
                    .arg(column),
                !applicationView->isColumnHidden(
                    column));
        }

        settings->setValue(
            "applications/columnSeparators",
            applicationColumnSeparators);
        settings->setValue(
            "applications/rowSeparators",
            applicationRowSeparators);
    }


    void applyRecommendedLeftoversHeaderLayout(
        bool resetVisibility = false)
    {
        if (!results || !results->header())
            return;

        QHeaderView *header =
            results->header();

        const QList<int> recommendedOrder = {
            0,  
            5,  
            2,  
            3,  
            4,  
            1   
        };

        for (int visualIndex = 0;
             visualIndex < recommendedOrder.size();
             ++visualIndex) {

            const int logicalIndex =
                recommendedOrder.at(visualIndex);

            const int currentVisual =
                header->visualIndex(logicalIndex);

            if (currentVisual >= 0 &&
                currentVisual != visualIndex) {

                header->moveSection(
                    currentVisual,
                    visualIndex);
            }
        }

        if (resetVisibility) {
            for (int column = 0;
                 column < results->columnCount();
                 ++column) {

                results->setColumnHidden(
                    column,
                    false);

                if (QCheckBox *check =
                        leftoversColumnChecks.value(column)) {

                    const QSignalBlocker blocker(check);
                    check->setChecked(true);
                }

                if (settings && column > 0) {
                    settings->setValue(
                        QString(
                            "leftovers/column-visible/%1")
                            .arg(column),
                        true);
                }
            }
        }

        updateLeftoversColumnResizeModes();
        fitLeftoversColumnsToViewport();

        QTimer::singleShot(
            0,
            this,
            [this]() {
                fitLeftoversColumnsToViewport();
                saveHeader();
            });
    }


    void applyRecommendedQuarantineHeaderLayout(
        bool resetVisibility = false)
    {
        if (!historyTree || !historyTree->header())
            return;

        QHeaderView *header =
            historyTree->header();

        const QList<int> recommendedOrder = {
            0,  
            5,  
            1,  
            3,  
            4,  
            2   
        };

        for (int visualIndex = 0;
             visualIndex < recommendedOrder.size();
             ++visualIndex) {

            const int logicalIndex =
                recommendedOrder.at(visualIndex);

            const int currentVisual =
                header->visualIndex(logicalIndex);

            if (currentVisual >= 0 &&
                currentVisual != visualIndex) {

                header->moveSection(
                    currentVisual,
                    visualIndex);
            }
        }

        if (resetVisibility) {
            for (int column = 0;
                 column < historyTree->columnCount();
                 ++column) {

                historyTree->setColumnHidden(
                    column,
                    false);

                if (QCheckBox *check =
                        quarantineColumnChecks.value(column)) {

                    const QSignalBlocker blocker(check);
                    check->setChecked(true);
                }

                if (settings && column > 0) {
                    settings->setValue(
                        QString(
                            "quarantine/column-visible/%1")
                            .arg(column),
                        true);
                }
            }
        }

        updateQuarantineColumnResizeModes();
        fitQuarantineColumnsToViewport();

        QTimer::singleShot(
            0,
            this,
            [this]() {
                fitQuarantineColumnsToViewport();
                saveQuarantineHeader();
            });
    }


    void restoreHeader()
    {
        if (!results)
            return;

        if (settings) {
            const QByteArray state =
                settings->value(
                    "results/header-v8.8.7-six-columns")
                    .toByteArray();

            if (!state.isEmpty()) {
                results->header()->restoreState(state);
                updateLeftoversColumnResizeModes();
                return;
            }
        }

        applyRecommendedLeftoversHeaderLayout();
    }


    void saveHeader()
    {
        if (!results ||
            !settings) {

            return;
        }

        settings->setValue(
            "results/header-v8.8.7-six-columns",
            results->header()->saveState());
    }


    void restoreQuarantineHeader()
    {
        if (!historyTree)
            return;

        if (settings) {
            const QByteArray state =
                settings->value(
                    "quarantine/header-v8.8.7-six-columns")
                    .toByteArray();

            if (!state.isEmpty()) {
                historyTree->header()->restoreState(state);
                updateQuarantineColumnResizeModes();
                return;
            }
        }

        applyRecommendedQuarantineHeaderLayout();
    }


    void saveQuarantineHeader()
    {
        if (!historyTree || !settings)
            return;

        settings->setValue(
            "quarantine/header-v8.8.7-six-columns",
            historyTree->header()->saveState());
    }


    void loadApplicationCache()
    {
        bool cacheOk = false;

        QList<ApplicationInfo> cached =
            loadApplicationCacheFile(
                &cacheOk);

        if (!cacheOk ||
            cached.isEmpty()) {

            return;
        }

        allApplications =
            std::move(cached);

        currentApplications =
            allApplications;

        applicationInventoryLoaded = true;
        applicationDataFresh = false;

        if (applicationModel) {
            applicationModel->setApplications(
                &allApplications);

            applicationModel->setShowSystemItems(
                true);

            if (applicationFilterGroup) {
                const int mode =
                    applicationFilterGroup
                        ->checkedId();

                applicationModel->setFilterMode(
                    mode >= 0
                        ? mode
                        : FilterRemovableApplications);
            }
        }

        if (search)
            search->setEnabled(true);

        if (uninstallSelectedBtn)
            uninstallSelectedBtn->setEnabled(false);

        installInfo->setText(
            "Showing the last known application inventory. "
            "TotalSweep is refreshing the current system state...");

        updateSystemItemsButton();
        updateApplicationStatus();
    }


    static QStringList xdgDataDirectories()
    {
        QStringList directories;

        const QString dataHome =
            qEnvironmentVariable("XDG_DATA_HOME").trimmed();

        directories.append(
            dataHome.isEmpty()
                ? QDir::homePath() +
                    QStringLiteral("/.local/share")
                : QDir::cleanPath(dataHome));

        QString dataDirs =
            qEnvironmentVariable("XDG_DATA_DIRS").trimmed();

        if (dataDirs.isEmpty()) {
            dataDirs =
                QStringLiteral(
                    "/usr/local/share:/usr/share");
        }

        for (const QString &directory :
             dataDirs.split(
                 QLatin1Char(':'),
                 Qt::SkipEmptyParts)) {

            const QString cleaned =
                QDir::cleanPath(
                    directory.trimmed());

            if (QDir::isAbsolutePath(cleaned))
                directories.append(cleaned);
        }

        directories.removeAll(QString());
        directories.removeDuplicates();
        return directories;
    }


    static QStringList desktopApplicationDirectories()
    {
        QStringList directories;

        for (const QString &dataDirectory :
             xdgDataDirectories()) {

            directories.append(
                QDir(dataDirectory).filePath(
                    QStringLiteral("applications")));
        }

        directories.append(
            QDir::homePath() +
            QStringLiteral(
                "/.local/share/flatpak/exports/share/applications"));
        directories.append(
            QStringLiteral(
                "/var/lib/flatpak/exports/share/applications"));

        directories.removeAll(QString());
        directories.removeDuplicates();
        return directories;
    }


    static QString locateDesktopFile(
        const ApplicationInfo &app)
    {
        if (!app.desktopFile.trimmed().isEmpty() &&
            QFileInfo::exists(
                app.desktopFile.trimmed())) {

            return QDir::cleanPath(
                app.desktopFile.trimmed());
        }

        QString desktopId =
            app.id.trimmed();

        if (!desktopId.endsWith(
                QStringLiteral(".desktop"),
                Qt::CaseInsensitive)) {

            desktopId +=
                QStringLiteral(".desktop");
        }

        if (!desktopId.isEmpty()) {
            for (const QString &directory :
                 desktopApplicationDirectories()) {

                const QString candidate =
                    QDir(directory).filePath(
                        desktopId);

                if (QFileInfo::exists(candidate))
                    return candidate;
            }
        }

        if (!isManualLocal(app) &&
            app.type != ApplicationType::Unknown) {
            return {};
        }

        const QString wantedName =
            app.name.trimmed();
        const QString wantedId =
            app.id.trimmed();

        for (const QString &directory :
             desktopApplicationDirectories()) {

            QDir dir(directory);
            if (!dir.exists())
                continue;

            const QFileInfoList entries =
                dir.entryInfoList(
                    {QStringLiteral("*.desktop")},
                    QDir::Files | QDir::Readable,
                    QDir::Name);

            for (const QFileInfo &entry : entries) {
                QSettings desktop(
                    entry.absoluteFilePath(),
                    QSettings::IniFormat);

                desktop.beginGroup(
                    QStringLiteral("Desktop Entry"));

                const QString name =
                    desktop.value(
                        QStringLiteral("Name"))
                        .toString()
                        .trimmed();

                const QString exec =
                    desktop.value(
                        QStringLiteral("Exec"))
                        .toString()
                        .trimmed();

                desktop.endGroup();

                if ((!wantedName.isEmpty() &&
                     name.compare(
                         wantedName,
                         Qt::CaseInsensitive) == 0) ||
                    (!wantedId.isEmpty() &&
                     (entry.completeBaseName().compare(
                          wantedId,
                          Qt::CaseInsensitive) == 0 ||
                      exec.contains(
                          wantedId,
                          Qt::CaseInsensitive)))) {

                    return entry.absoluteFilePath();
                }
            }
        }

        return {};
    }


    static QString flatpakScopeForDesktopFile(
        const QString &desktopFile)
    {
        const QString cleaned =
            QDir::cleanPath(desktopFile.trimmed());

        if (cleaned.startsWith(
                QDir::homePath() +
                QStringLiteral(
                    "/.local/share/flatpak/exports/"))) {
            return QStringLiteral("user");
        }

        if (cleaned.startsWith(
                QStringLiteral(
                    "/var/lib/flatpak/exports/"))) {
            return QStringLiteral("system");
        }

        return {};
    }


    static QString flatpakScopeForApplication(
        const ApplicationInfo &app)
    {
        const QString location =
            QDir::cleanPath(
                app.installLocation.trimmed());
        const QString source =
            app.source.trimmed().toLower();

        if (location.startsWith(
                QDir::homePath() +
                QStringLiteral("/.local/share/flatpak/")) ||
            source.contains(QStringLiteral("user")) ||
            flatpakScopeForDesktopFile(app.desktopFile) ==
                QStringLiteral("user")) {
            return QStringLiteral("user");
        }

        if (location.startsWith(
                QStringLiteral("/var/lib/flatpak/")) ||
            source.contains(QStringLiteral("system")) ||
            flatpakScopeForDesktopFile(app.desktopFile) ==
                QStringLiteral("system")) {
            return QStringLiteral("system");
        }

        return {};
    }


    static bool flatpakInstalled(
        const QString &appId,
        const QString &scope = QString())
    {
        if (appId.trimmed().isEmpty())
            return false;

        QStringList arguments;
        if (scope == QStringLiteral("user"))
            arguments.append(QStringLiteral("--user"));
        else if (scope == QStringLiteral("system"))
            arguments.append(QStringLiteral("--system"));

        arguments.append(QStringLiteral("info"));
        arguments.append(appId.trimmed());

        QProcess process;
        process.start(
            QStringLiteral("flatpak"),
            arguments);

        if (!process.waitForStarted(3000))
            return false;

        if (!process.waitForFinished(7000)) {
            process.kill();
            process.waitForFinished(500);
            return false;
        }

        return process.exitStatus() == QProcess::NormalExit &&
            process.exitCode() == 0;
    }


    static QString flatpakMetainfoSummary(
        const QString &appId)
    {
        if (appId.trimmed().isEmpty())
            return {};

        const QStringList locations =
            runCommand(
                QStringLiteral("flatpak"),
                {
                    QStringLiteral("info"),
                    QStringLiteral("--show-location"),
                    appId
                },
                10000);

        if (locations.isEmpty())
            return {};

        const QString deployment =
            locations.first().trimmed();

        if (deployment.isEmpty())
            return {};

        const QStringList directories = {
            deployment +
                QStringLiteral(
                    "/files/share/metainfo"),
            deployment +
                QStringLiteral(
                    "/files/share/appdata")
        };

        QStringList candidates;

        for (const QString &directoryPath :
             directories) {
            QDir directory(directoryPath);

            if (!directory.exists())
                continue;

            const QStringList exactNames = {
                appId +
                    QStringLiteral(
                        ".metainfo.xml"),
                appId +
                    QStringLiteral(
                        ".appdata.xml")
            };

            for (const QString &name :
                 exactNames) {
                const QString candidate =
                    directory.filePath(name);

                if (QFileInfo::exists(candidate))
                    candidates.append(candidate);
            }

            const QStringList discovered =
                directory.entryList(
                    {
                        QStringLiteral(
                            "*.metainfo.xml"),
                        QStringLiteral(
                            "*.appdata.xml")
                    },
                    QDir::Files,
                    QDir::Name);

            for (const QString &name :
                 discovered) {
                const QString candidate =
                    directory.filePath(name);

                if (!candidates.contains(
                        candidate)) {
                    candidates.append(
                        candidate);
                }
            }
        }

        const QRegularExpression summaryExpression(
            QStringLiteral(
                R"(<summary(?:\s[^>]*)?>(.*?)</summary>)"),
            QRegularExpression::CaseInsensitiveOption |
                QRegularExpression::DotMatchesEverythingOption);

        const QRegularExpression tags(
            QStringLiteral(
                R"(<[^>]+>)"));

        for (const QString &candidate :
             candidates) {
            QFile file(candidate);

            if (!file.open(
                    QIODevice::ReadOnly |
                    QIODevice::Text)) {
                continue;
            }

            QString contents =
                QString::fromUtf8(
                    file.readAll());

            file.close();

            const QRegularExpressionMatch match =
                summaryExpression.match(
                    contents);

            if (!match.hasMatch())
                continue;

            QString summary =
                match.captured(1)
                    .trimmed();

            summary.remove(tags);

            summary.replace(
                QStringLiteral("&quot;"),
                QStringLiteral("\""));

            summary.replace(
                QStringLiteral("&apos;"),
                QStringLiteral("'"));

            summary.replace(
                QStringLiteral("&lt;"),
                QStringLiteral("<"));

            summary.replace(
                QStringLiteral("&gt;"),
                QStringLiteral(">"));

            summary.replace(
                QStringLiteral("&amp;"),
                QStringLiteral("&"));

            summary =
                summary.simplified();

            if (!summary.isEmpty())
                return summary;
        }

        return {};
    }


    static QMap<QString, QString>
    installedFlatpakVersions()
    {
        QMap<QString, QString> versions;

        const QStringList lines =
            runCommand(
                QStringLiteral("flatpak"),
                {
                    QStringLiteral("list"),
                    QStringLiteral("--app"),
                    QStringLiteral(
                        "--columns=application,version")
                },
                15000);

        for (const QString &line : lines) {
            const QStringList fields =
                line.split(QLatin1Char('\t'));

            if (fields.size() < 2)
                continue;

            const QString id =
                fields.at(0).trimmed();

            const QString version =
                fields.at(1).trimmed();

            if (!id.isEmpty() &&
                !version.isEmpty()) {
                versions.insert(
                    id,
                    version);
            }
        }

        return versions;
    }


    static void enrichApplicationMetadata(
        QList<ApplicationInfo> &applications)
    {
        const QMap<QString, QString> flatpakVersions =
            installedFlatpakVersions();

        for (ApplicationInfo &app :
             applications) {

            if (app.type ==
                    ApplicationType::Flatpak &&
                app.version.trimmed().isEmpty()) {

                app.version =
                    flatpakVersions.value(
                        app.id.trimmed());
            }

            if (app.type ==
                    ApplicationType::Flatpak &&
                app.description.trimmed().isEmpty()) {

                app.description =
                    flatpakMetainfoSummary(
                        app.id.trimmed());
            }

            const QString desktopFile =
                locateDesktopFile(app);

            if (desktopFile.isEmpty())
                continue;

            app.desktopFile =
                desktopFile;

            QSettings desktop(
                desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            const QString displayName =
                desktop.value(
                    QStringLiteral("Name"))
                    .toString()
                    .trimmed();

            const QString genericName =
                desktop.value(
                    QStringLiteral("GenericName"))
                    .toString()
                    .trimmed();

            const QString description =
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

            if (!displayName.isEmpty())
                app.name = displayName;

            if (!executable.isEmpty())
                app.executable = executable;

            if (app.description.trimmed().isEmpty()) {
                if (!description.isEmpty()) {
                    app.description =
                        description;
                }
                else if (!genericName.isEmpty() &&
                         genericName.compare(
                             app.name,
                             Qt::CaseInsensitive) != 0) {
                    app.description =
                        genericName;
                }
            }
        }
    }


    QIcon applicationIcon(
        const ApplicationInfo &app) const
    {
        QString iconName;

        if (!app.desktopFile.isEmpty() &&
            QFileInfo::exists(
                app.desktopFile)) {

            QSettings desktop(
                app.desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            iconName =
                desktop.value(
                    QStringLiteral("Icon"))
                    .toString()
                    .trimmed();

            desktop.endGroup();
        }

        if (!iconName.isEmpty()) {

            if (QFileInfo::exists(iconName)) {

                const QIcon fileIcon(iconName);

                if (!fileIcon.isNull())
                    return fileIcon;
            }

            const QIcon themed =
                QIcon::fromTheme(iconName);

            if (!themed.isNull())
                return themed;
        }

        const QIcon idIcon =
            QIcon::fromTheme(app.id);

        if (!idIcon.isNull())
            return idIcon;

        const QIcon generic =
            QIcon::fromTheme(
                QStringLiteral(
                    "application-x-executable"));

        if (!generic.isNull())
            return generic;

        return style()->standardIcon(
            QStyle::SP_ComputerIcon);
    }


    QList<ApplicationInfo>
    searchCachedApplications(
        const QString &query) const
    {
        const QString needle =
            query.trimmed();

        if (needle.isEmpty())
            return allApplications;

        QList<ApplicationInfo> matches;

        for (const ApplicationInfo &app :
             allApplications) {

            if (app.name.contains(
                    needle,
                    Qt::CaseInsensitive) ||

                app.id.contains(
                    needle,
                    Qt::CaseInsensitive) ||

                app.description.contains(
                    needle,
                    Qt::CaseInsensitive) ||

                app.packageManager.contains(
                    needle,
                    Qt::CaseInsensitive) ||

                app.executable.contains(
                    needle,
                    Qt::CaseInsensitive) ||

                app.desktopFile.contains(
                    needle,
                    Qt::CaseInsensitive)) {

                matches.append(app);
            }
        }

        return matches;
    }


        int removableApplicationCount() const
    {
        int count = 0;

        for (const ApplicationInfo &app :
             allApplications) {

            if (app.removable &&
                !app.systemComponent &&
                !app.protectedComponent) {

                ++count;
            }
        }

        return count;
    }


    int systemItemCount() const
    {
        int count = 0;

        for (const ApplicationInfo &app :
             allApplications) {

            if (app.systemComponent ||
                app.protectedComponent) {

                ++count;
            }
        }

        return count;
    }


    void updateSystemItemsButton()
    {
    }


    void updateApplicationStatus()
    {
        if (!applicationModel ||
            !applicationStatus) {

            return;
        }

        if (!applicationInventoryLoaded) {
            applicationStatus->setText(
                applicationRefreshRunning
                    ? QStringLiteral(
                        "Loading current application inventory in the background...")
                    : QStringLiteral(
                        "No application inventory is currently available."));

            if (applicationView) {
                applicationView->setEmptyMessage(
                    applicationRefreshRunning
                        ? QStringLiteral(
                            "Loading installed applications…")
                        : QStringLiteral(
                            "No application inventory is available."));
            }
            return;
        }

        const QString query =
            committedApplicationSearch;

        const int visible =
            applicationModel
                ->visibleApplicationCount();

        const int selected =
            applicationModel
                ->checkedCount();

        QString freshness;

        if (applicationRefreshRunning) {
            freshness =
                QStringLiteral(
                    " • Refreshing…");
        }
        else if (applicationDataFresh) {
            freshness.clear();
        }
        else if (applicationInventoryLoaded) {
            freshness =
                QStringLiteral(
                    " • Cached view");
        }

        if (applicationView) {
            if (visible == 0) {
                applicationView->setEmptyMessage(
                    query.isEmpty()
                        ? QStringLiteral(
                            "No applications are available in this view.")
                        : QStringLiteral(
                            "No matching applications found."));
            }
            else {
                applicationView->setEmptyMessage(
                    QString());
            }
        }

        if (!query.isEmpty()) {

            applicationStatus->setText(
                QString(
                    "Showing %1 matching %2 • %3 selected%4")
                    .arg(visible)
                    .arg(wordForCount(
                        visible,
                        QStringLiteral("item"),
                        QStringLiteral("items")))
                    .arg(selected)
                    .arg(freshness));

            return;
        }

        QString filterName =
            QStringLiteral("All");

        if (applicationFilterGroup &&
            applicationFilterGroup->checkedButton()) {

            filterName =
                applicationFilterGroup
                    ->checkedButton()
                    ->text();
        }

        applicationStatus->setText(
            QString(
                "Showing %1 %2 • %3 selected • Filter: %4%5")
                .arg(visible)
                .arg(wordForCount(
                    visible,
                    QStringLiteral("item"),
                    QStringLiteral("items")))
                .arg(selected)
                .arg(filterName)
                .arg(freshness));
    }


void showFullApplicationList(
        bool switchToUninstall)
    {

        if (!applicationInventoryLoaded)
            return;

        currentApplications =
            allApplications;

        committedApplicationSearch.clear();

        if (applicationModel) {
            applicationModel->setQuery(
                QString());

            applicationModel->setShowSystemItems(
                true);
        }

        search->setPlaceholderText(
            applicationDataFresh &&
            !applicationRefreshRunning
                ? QStringLiteral(
                    "Search applications…")
                : QStringLiteral(
                    "Search cached applications while TotalSweep refreshes…"));

        updateSystemItemsButton();
        updateApplicationStatus();

        if (switchToUninstall) {
            setCurrentPage(0);
        }
    }



    static quint64 manualDirectorySize(
        const QString &root)
    {
        const QFileInfo rootInfo(root);

        if (!rootInfo.exists())
            return 0;

        if (rootInfo.isFile())
            return static_cast<quint64>(
                rootInfo.size());

        quint64 total = 0;

        QDirIterator iterator(
            root,
            QDir::Files |
                QDir::Hidden |
                QDir::System |
                QDir::NoDotAndDotDot,
            QDirIterator::Subdirectories);

        while (iterator.hasNext()) {
            iterator.next();

            const QFileInfo info =
                iterator.fileInfo();

            if (info.isSymLink())
                continue;

            const qint64 size =
                info.size();

            if (size > 0)
                total +=
                    static_cast<quint64>(
                        size);
        }

        return total;
    }


    static QString manualSizeText(
        quint64 bytes)
    {
        if (bytes < 1024)
            return QStringLiteral("%1 B")
                .arg(bytes);

        static const char *units[] = {
            "KiB",
            "MiB",
            "GiB",
            "TiB"
        };

        double value =
            static_cast<double>(bytes);

        int unit = -1;

        do {
            value /= 1024.0;
            ++unit;
        }
        while (value >= 1024.0 &&
               unit < 3);

        const int precision =
            value >= 100.0
                ? 0
                : value >= 10.0
                    ? 1
                    : 2;

        return QStringLiteral("%1 %2")
            .arg(
                QString::number(
                    value,
                    'f',
                    precision),
                QString::fromLatin1(
                    units[unit]));
    }


    static QString manualPythonPackageVersion(
        const QString &installRoot,
        const QString &packageId)
    {
        const QStringList pythonCandidates = {
            installRoot +
                QStringLiteral("/venv/bin/python3"),
            installRoot +
                QStringLiteral("/venv/bin/python")
        };

        QString python;

        for (const QString &candidate :
             pythonCandidates) {
            const QFileInfo info(candidate);

            if (info.isFile() &&
                info.isExecutable()) {
                python = candidate;
                break;
            }
        }

        if (python.isEmpty())
            return {};

        QStringList packageNames = {
            packageId.trimmed(),
            QFileInfo(installRoot)
                .fileName()
                .trimmed()
        };

        packageNames.removeAll(QString());
        packageNames.removeDuplicates();

        for (const QString &packageName :
             packageNames) {
            QProcess process;

            process.start(
                python,
                {
                    QStringLiteral("-m"),
                    QStringLiteral("pip"),
                    QStringLiteral("show"),
                    packageName
                });

            if (!process.waitForFinished(8000)) {
                process.kill();
                process.waitForFinished();
                continue;
            }

            if (process.exitStatus() !=
                    QProcess::NormalExit ||
                process.exitCode() != 0) {
                continue;
            }

            const QString output =
                QString::fromUtf8(
                    process.readAllStandardOutput());

            const QStringList lines =
                output.split(
                    QLatin1Char('\n'));

            for (const QString &line :
                 lines) {
                if (!line.startsWith(
                        QStringLiteral("Version:"),
                        Qt::CaseInsensitive)) {
                    continue;
                }

                const QString version =
                    line.mid(
                        line.indexOf(
                            QLatin1Char(':')) + 1)
                        .trimmed();

                if (!version.isEmpty())
                    return version;
            }
        }

        return {};
    }


    static bool isAppImageFile(
        const QString &path)
    {
        const QFileInfo info(path);

        if (!info.isFile())
            return false;

        QFile file(path);

        if (!file.open(QIODevice::ReadOnly))
            return false;

        const QByteArray header =
            file.read(11);

        if (header.size() < 11)
            return false;

        const QByteArray magic =
            header.mid(8, 3);

        return magic ==
                QByteArray::fromHex("414901") ||
            magic ==
                QByteArray::fromHex("414902");
    }


    static QString desktopExecutablePath(
        const QString &exec,
        const QString &tryExec)
    {
        auto usablePath = [](
            QString candidate) -> QString {
            candidate =
                candidate.trimmed();

            if (candidate.startsWith(
                    QStringLiteral("file://"))) {
                candidate =
                    candidate.mid(7);
            }

            if (!QDir::isAbsolutePath(
                    candidate)) {
                return {};
            }

            const QFileInfo info(candidate);

            if (!info.isFile())
                return {};

            const QString canonical =
                info.canonicalFilePath();

            return canonical.isEmpty()
                ? info.absoluteFilePath()
                : canonical;
        };

        const QString tryPath =
            usablePath(tryExec);

        if (!tryPath.isEmpty())
            return tryPath;

        const QStringList parts =
            QProcess::splitCommand(
                exec.trimmed());

        const QRegularExpression assignment(
            QStringLiteral(
                R"(^[A-Za-z_][A-Za-z0-9_]*=.*$)"));

        for (QString part : parts) {
            part = part.trimmed();

            if (part.isEmpty() ||
                part == QStringLiteral("env") ||
                part.startsWith(
                    QLatin1Char('%')) ||
                assignment.match(part)
                    .hasMatch()) {
                continue;
            }

            const QString candidate =
                usablePath(part);

            if (!candidate.isEmpty())
                return candidate;
        }

        return {};
    }


    static QString appImagePathFor(
        const ApplicationInfo &app)
    {
        const QString location =
            app.installLocation.trimmed();

        if (!location.isEmpty() &&
            isAppImageFile(location)) {
            return QFileInfo(location)
                .canonicalFilePath();
        }

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        for (QString part :
             execParts) {
            part = part.trimmed();

            if (part.startsWith(
                    QStringLiteral("file://"))) {
                part = part.mid(7);
            }

            if (isAppImageFile(part)) {
                const QString canonical =
                    QFileInfo(part)
                        .canonicalFilePath();

                return canonical.isEmpty()
                    ? QFileInfo(part)
                        .absoluteFilePath()
                    : canonical;
            }
        }

        for (const QString &candidate :
             app.files) {
            if (!isAppImageFile(candidate))
                continue;

            const QString canonical =
                QFileInfo(candidate)
                    .canonicalFilePath();

            return canonical.isEmpty()
                ? QFileInfo(candidate)
                    .absoluteFilePath()
                : canonical;
        }

        return {};
    }


    static QList<ApplicationInfo>
    detectDesktopAppImages(
        const QList<ApplicationInfo> &existing)
    {
        QList<ApplicationInfo> result;
        QSet<QString> knownDesktopFiles;

        for (const ApplicationInfo &app :
             existing) {
            if (!app.desktopFile
                     .trimmed()
                     .isEmpty()) {
                knownDesktopFiles.insert(
                    QDir::cleanPath(
                        app.desktopFile));
            }
        }

        const QStringList directories = {
            QDir::homePath() +
                QStringLiteral(
                    "/.local/share/applications"),
            QStringLiteral(
                "/usr/local/share/applications"),
            QStringLiteral(
                "/usr/share/applications")
        };

        for (const QString &directoryPath :
             directories) {
            QDir directory(directoryPath);

            if (!directory.exists())
                continue;

            const QFileInfoList entries =
                directory.entryInfoList(
                    {
                        QStringLiteral(
                            "*.desktop")
                    },
                    QDir::Files |
                        QDir::Readable |
                        QDir::NoDotAndDotDot,
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

                const QString name =
                    desktop.value(
                        QStringLiteral("Name"))
                        .toString()
                        .trimmed();

                const QString genericName =
                    desktop.value(
                        QStringLiteral("GenericName"))
                        .toString()
                        .trimmed();

                const QString comment =
                    desktop.value(
                        QStringLiteral("Comment"))
                        .toString()
                        .trimmed();

                const QString exec =
                    desktop.value(
                        QStringLiteral("Exec"))
                        .toString()
                        .trimmed();

                const QString tryExec =
                    desktop.value(
                        QStringLiteral("TryExec"))
                        .toString()
                        .trimmed();

                const QString appImageVersion =
                    desktop.value(
                        QStringLiteral(
                            "X-AppImage-Version"))
                        .toString()
                        .trimmed();

                const QString appImageName =
                    desktop.value(
                        QStringLiteral(
                            "X-AppImage-Name"))
                        .toString()
                        .trimmed();

                const QString flatpakId =
                    desktop.value(
                        QStringLiteral("X-Flatpak"))
                        .toString()
                        .trimmed();

                desktop.endGroup();

                if (hidden ||
                    !flatpakId.isEmpty() ||
                    (!type.isEmpty() &&
                     type !=
                         QStringLiteral(
                             "Application"))) {
                    continue;
                }

                const QString executable =
                    desktopExecutablePath(
                        exec,
                        tryExec);

                if (executable.isEmpty() ||
                    !isAppImageFile(
                        executable)) {
                    continue;
                }

                const QStringList rpmOwner =
                    runCommand(
                        QStringLiteral("rpm"),
                        {
                            QStringLiteral("-qf"),
                            executable
                        },
                        5000);

                if (!rpmOwner.isEmpty())
                    continue;

                ApplicationInfo app;

                app.name =
                    !name.isEmpty()
                        ? name
                        : (!appImageName.isEmpty()
                               ? appImageName
                               : QFileInfo(executable)
                                     .completeBaseName());

                app.id =
                    entry.completeBaseName();

                app.version =
                    appImageVersion;

                if (!comment.isEmpty()) {
                    app.description =
                        comment;
                }
                else if (!genericName.isEmpty() &&
                         genericName.compare(
                             app.name,
                             Qt::CaseInsensitive) != 0) {
                    app.description =
                        genericName;
                }

                const QFileInfo imageInfo(
                    executable);

                app.installedSize =
                    manualSizeText(
                        static_cast<quint64>(
                            imageInfo.size()));

                QDateTime installTime =
                    imageInfo.birthTime();

                if (!installTime.isValid())
                    installTime =
                        imageInfo.lastModified();

                if (installTime.isValid()) {
                    app.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    app.installDateEstimated =
                        true;
                }

                app.executable =
                    executable;

                app.desktopFile =
                    entry.absoluteFilePath();

                app.installLocation =
                    executable;

                app.installLocations = {
                    executable
                };

                app.files = {
                    executable,
                    entry.absoluteFilePath()
                };

                app.packageManager =
                    QStringLiteral("AppImage");

                app.source =
                    QStringLiteral("AppImage");

                app.type =
                    ApplicationType::AppImage;

                app.risk =
                    RiskLevel::Unknown;

                app.installed = true;
                app.removable = true;
                app.userInstalled = true;
                app.systemComponent = false;
                app.protectedComponent = false;

                result.append(app);
            }
        }

        return result;
    }


    static QList<ApplicationInfo>
    detectStandaloneAppImages(
        const QList<ApplicationInfo> &existing)
    {
        QList<ApplicationInfo> result;
        QSet<QString> knownPaths;

        for (const ApplicationInfo &app :
             existing) {
            const QString candidate =
                appImagePathFor(app);

            if (!candidate.isEmpty())
                knownPaths.insert(candidate);
        }

        const QStringList directories = {
            QDir::homePath() +
                QStringLiteral(
                    "/Applications"),
            QDir::homePath() +
                QStringLiteral(
                    "/AppImages"),
            QDir::homePath() +
                QStringLiteral(
                    "/.local/share/AppImages"),
            QDir::homePath() +
                QStringLiteral(
                    "/.local/bin")
        };

        for (const QString &directoryPath :
             directories) {
            QDir directory(directoryPath);

            if (!directory.exists())
                continue;

            const QFileInfoList entries =
                directory.entryInfoList(
                    QDir::Files |
                        QDir::Readable |
                        QDir::NoDotAndDotDot,
                    QDir::Name);

            for (const QFileInfo &entry :
                 entries) {
                const QString path =
                    entry.absoluteFilePath();

                if (!entry.isExecutable() ||
                    !isAppImageFile(path)) {
                    continue;
                }

                QString canonical =
                    entry.canonicalFilePath();

                if (canonical.isEmpty())
                    canonical = path;

                if (knownPaths.contains(
                        canonical)) {
                    continue;
                }

                ApplicationInfo app;

                app.name =
                    entry.completeBaseName();

                app.id =
                    entry.fileName();

                app.installedSize =
                    manualSizeText(
                        static_cast<quint64>(
                            entry.size()));

                QDateTime installTime =
                    entry.birthTime();

                if (!installTime.isValid())
                    installTime =
                        entry.lastModified();

                if (installTime.isValid()) {
                    app.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    app.installDateEstimated =
                        true;
                }

                app.executable =
                    canonical;

                app.installLocation =
                    canonical;

                app.installLocations = {
                    canonical
                };

                app.files = {
                    canonical
                };

                app.packageManager =
                    QStringLiteral("AppImage");

                app.source =
                    QStringLiteral("AppImage");

                app.type =
                    ApplicationType::AppImage;

                app.risk =
                    RiskLevel::Unknown;

                app.installed = true;
                app.removable = true;
                app.userInstalled = true;
                app.systemComponent = false;
                app.protectedComponent = false;

                result.append(app);
                knownPaths.insert(
                    canonical);
            }
        }

        return result;
    }


    static int appImageMetadataScore(
        const ApplicationInfo &app)
    {
        int score = 0;

        if (!app.version
                 .trimmed()
                 .isEmpty()) {
            score += 100;
        }

        if (!app.description
                 .trimmed()
                 .isEmpty()) {
            score += 100;
        }

        if (!app.desktopFile
                 .trimmed()
                 .isEmpty()) {
            score += 50;
        }

        if (!app.name
                 .trimmed()
                 .isEmpty()) {
            score += 20;
        }

        return score;
    }


    static void collapseAppImageApplications(
        QList<ApplicationInfo> &applications)
    {
        QMap<QString, QList<ApplicationInfo>> groups;
        QList<ApplicationInfo> unchanged;

        for (const ApplicationInfo &app :
             applications) {
            if (app.type !=
                    ApplicationType::AppImage) {
                unchanged.append(app);
                continue;
            }

            const QString path =
                appImagePathFor(app);

            if (path.isEmpty()) {
                unchanged.append(app);
                continue;
            }

            groups[path].append(app);
        }

        for (auto it =
                 groups.cbegin();
             it != groups.cend();
             ++it) {
            const QString path =
                it.key();

            const QList<ApplicationInfo> members =
                it.value();

            if (members.isEmpty())
                continue;

            int bestIndex = 0;
            int bestScore =
                appImageMetadataScore(
                    members.first());

            for (int i = 1;
                 i < members.size();
                 ++i) {
                const int score =
                    appImageMetadataScore(
                        members.at(i));

                if (score > bestScore) {
                    bestScore = score;
                    bestIndex = i;
                }
            }

            ApplicationInfo merged =
                members.at(bestIndex);

            QStringList files;

            for (const ApplicationInfo &member :
                 members) {
                if (merged.version
                        .trimmed()
                        .isEmpty() &&
                    !member.version
                         .trimmed()
                         .isEmpty()) {
                    merged.version =
                        member.version.trimmed();
                }

                if (merged.description
                        .trimmed()
                        .isEmpty() &&
                    !member.description
                         .trimmed()
                         .isEmpty()) {
                    merged.description =
                        member.description.trimmed();
                }

                if (merged.desktopFile
                        .trimmed()
                        .isEmpty() &&
                    !member.desktopFile
                         .trimmed()
                         .isEmpty()) {
                    merged.desktopFile =
                        member.desktopFile;
                }

                for (const QString &file :
                     member.files) {
                    if (!file.trimmed().isEmpty() &&
                        !files.contains(file)) {
                        files.append(file);
                    }
                }
            }

            if (!files.contains(path))
                files.append(path);

            if (!merged.desktopFile
                     .trimmed()
                     .isEmpty() &&
                !files.contains(
                    merged.desktopFile)) {
                files.append(
                    merged.desktopFile);
            }

            const QFileInfo info(path);

            merged.installLocation =
                path;

            merged.installLocations = {
                path
            };

            merged.files =
                files;

            merged.executable =
                path;

            merged.installedSize =
                manualSizeText(
                    static_cast<quint64>(
                        info.size()));

            if (merged.installDate
                    .trimmed()
                    .isEmpty()) {
                QDateTime installTime =
                    info.birthTime();

                if (!installTime.isValid())
                    installTime =
                        info.lastModified();

                if (installTime.isValid()) {
                    merged.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    merged.installDateEstimated =
                        true;
                }
            }

            merged.packageManager =
                QStringLiteral("AppImage");

            merged.source =
                QStringLiteral("AppImage");

            merged.type =
                ApplicationType::AppImage;

            merged.installed = true;
            merged.removable = true;
            merged.userInstalled = true;
            merged.systemComponent = false;
            merged.protectedComponent = false;

            unchanged.append(merged);
        }

        applications =
            std::move(unchanged);
    }


    static QString optApplicationRoot(
        const QString &path)
    {
        QString cleaned =
            QDir::cleanPath(path.trimmed());

        if (!cleaned.startsWith(
                QStringLiteral("/opt/"))) {
            return {};
        }

        const QStringList parts =
            cleaned.split(
                QLatin1Char('/'),
                Qt::SkipEmptyParts);

        if (parts.size() < 2 ||
            parts.at(0) !=
                QStringLiteral("opt")) {
            return {};
        }

        return QStringLiteral("/opt/") +
            parts.at(1);
    }


    static QList<ApplicationInfo> detectDesktopOptApplications(
        const QList<ApplicationInfo> &existing)
    {
        QList<ApplicationInfo> result;

        QSet<QString> knownIds;
        QSet<QString> knownRoots;

        for (const ApplicationInfo &app :
             existing) {
            const QString id =
                app.id.trimmed().toLower();

            const QString root =
                QDir::cleanPath(
                    app.installLocation.trimmed());

            if (!id.isEmpty() &&
                (app.type == ApplicationType::RPM ||
                 app.type == ApplicationType::Flatpak)) {
                knownIds.insert(id);
            }

            if (!root.isEmpty() &&
                (app.type == ApplicationType::RPM ||
                 app.type == ApplicationType::Flatpak)) {
                knownRoots.insert(root);
            }
        }

        QMap<QString, ApplicationInfo> bestApps;
        QMap<QString, int> bestScores;
        QMap<QString, QStringList> launchers;

        auto rpmOwns = [](const QString &candidate) {
            if (candidate.trimmed().isEmpty())
                return false;

            QProcess process;

            process.start(
                QStringLiteral("rpm"),
                {
                    QStringLiteral("-qf"),
                    candidate
                });

            if (!process.waitForFinished(5000)) {
                process.kill();
                process.waitForFinished();
                return false;
            }

            return process.exitStatus() ==
                       QProcess::NormalExit &&
                   process.exitCode() == 0;
        };

        const QStringList desktopDirectories = {
            QDir::homePath() +
                QStringLiteral(
                    "/.local/share/applications"),
            QStringLiteral(
                "/usr/local/share/applications"),
            QStringLiteral(
                "/usr/share/applications")
        };

        for (const QString &directoryPath :
             desktopDirectories) {
            QDir directory(directoryPath);

            if (!directory.exists())
                continue;

            const QFileInfoList entries =
                directory.entryInfoList(
                    {
                        QStringLiteral("*.desktop")
                    },
                    QDir::Files |
                        QDir::Readable |
                        QDir::NoDotAndDotDot,
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

                const QString genericName =
                    desktop.value(
                        QStringLiteral("GenericName"))
                        .toString()
                        .trimmed();

                const QString comment =
                    desktop.value(
                        QStringLiteral("Comment"))
                        .toString()
                        .trimmed();

                const QString exec =
                    desktop.value(
                        QStringLiteral("Exec"))
                        .toString()
                        .trimmed();

                desktop.endGroup();

                if (hidden ||
                    (!type.isEmpty() &&
                     type !=
                         QStringLiteral(
                             "Application")) ||
                    name.isEmpty() ||
                    exec.isEmpty()) {
                    continue;
                }

                const QStringList execParts =
                    QProcess::splitCommand(exec);

                QString executable;

                for (QString part :
                     execParts) {
                    part = part.trimmed();

                    if (part.startsWith(
                            QStringLiteral(
                                "file://"))) {
                        part = part.mid(7);
                    }

                    if (!part.startsWith(
                            QStringLiteral(
                                "/opt/"))) {
                        continue;
                    }

                    const QFileInfo info(part);

                    if (!info.exists() ||
                        !info.isFile() ||
                        !info.isExecutable()) {
                        continue;
                    }

                    executable =
                        info.canonicalFilePath();

                    if (executable.isEmpty())
                        executable =
                            info.absoluteFilePath();

                    break;
                }

                if (executable.isEmpty())
                    continue;

                if (isAppImageFile(
                        executable)) {
                    continue;
                }

                const QString installRoot =
                    optApplicationRoot(
                        executable);

                if (installRoot.isEmpty() ||
                    knownRoots.contains(
                        installRoot) ||
                    !QFileInfo(
                        installRoot).isDir()) {
                    continue;
                }

                if (rpmOwns(
                        entry.absoluteFilePath()) ||
                    rpmOwns(executable)) {
                    continue;
                }

                QStringList &rootLaunchers =
                    launchers[installRoot];

                if (!rootLaunchers.contains(
                        entry.absoluteFilePath())) {
                    rootLaunchers.append(
                        entry.absoluteFilePath());
                }

                QString id =
                    entry.completeBaseName()
                        .trimmed();

                if (id.isEmpty())
                    id = name;

                if (knownIds.contains(
                        id.toLower())) {
                    continue;
                }

                const QString rootName =
                    QFileInfo(installRoot)
                        .fileName()
                        .toLower();

                const QString normalizedName =
                    name.toLower();

                const QString normalizedId =
                    id.toLower();

                const QString executableName =
                    QFileInfo(executable)
                        .fileName()
                        .toLower();

                int score = 0;

                if (!comment.isEmpty())
                    score += 40;

                if (!genericName.isEmpty())
                    score += 10;

                if (!rootName.isEmpty() &&
                    normalizedName.contains(
                        rootName)) {
                    score += 50;
                }

                if (!rootName.isEmpty() &&
                    normalizedId.contains(
                        rootName)) {
                    score += 50;
                }

                if (!rootName.isEmpty() &&
                    executableName ==
                        rootName) {
                    score += 80;
                }

                if (executable.contains(
                        QStringLiteral("/bin/"))) {
                    score += 30;
                }

                if (entry.absoluteFilePath()
                        .startsWith(
                            QDir::homePath() +
                            QStringLiteral(
                                "/.local/share/applications/"))) {
                    score += 15;
                }

                const QString helperText =
                    (normalizedName +
                     QLatin1Char(' ') +
                     normalizedId +
                     QLatin1Char(' ') +
                     executableName);

                const QStringList helperTerms = {
                    QStringLiteral("uninstall"),
                    QStringLiteral("installer"),
                    QStringLiteral("setup"),
                    QStringLiteral("updater"),
                    QStringLiteral("update"),
                    QStringLiteral("capture log"),
                    QStringLiteral("diagnostic"),
                    QStringLiteral("helper"),
                    QStringLiteral("daemon")
                };

                for (const QString &term :
                     helperTerms) {
                    if (helperText.contains(term))
                        score -= 200;
                }

                if (noDisplay)
                    score -= 75;

                if (bestScores.contains(
                        installRoot) &&
                    bestScores.value(
                        installRoot) >= score) {
                    continue;
                }

                ApplicationInfo app;

                app.name = name;
                app.id = id;

                if (!comment.isEmpty()) {
                    app.description =
                        comment;
                }
                else if (!genericName.isEmpty() &&
                         genericName.compare(
                             name,
                             Qt::CaseInsensitive) != 0) {
                    app.description =
                        genericName;
                }

                app.version =
                    manualPythonPackageVersion(
                        installRoot,
                        id);

                app.installedSize =
                    manualSizeText(
                        manualDirectorySize(
                            installRoot));

                const QFileInfo rootInfo(
                    installRoot);

                QDateTime installTime =
                    rootInfo.birthTime();

                if (!installTime.isValid())
                    installTime =
                        rootInfo.lastModified();

                if (installTime.isValid()) {
                    app.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    app.installDateEstimated =
                        true;
                }

                app.executable =
                    executable;

                app.desktopFile =
                    entry.absoluteFilePath();

                app.installLocation =
                    installRoot;

                app.packageManager =
                    QStringLiteral(
                        "Manual / Local");

                app.source =
                    QStringLiteral("Local");

                app.installLocations = {
                    installRoot
                };

                app.type =
                    ApplicationType::Custom;

                app.risk =
                    RiskLevel::Unknown;

                app.installed = true;
                app.removable = true;
                app.userInstalled = true;
                app.systemComponent = false;
                app.protectedComponent = false;

                bestApps.insert(
                    installRoot,
                    app);

                bestScores.insert(
                    installRoot,
                    score);
            }
        }

        for (auto it =
                 bestApps.begin();
             it != bestApps.end();
             ++it) {
            ApplicationInfo app =
                it.value();

            QStringList files =
                launchers.value(
                    it.key());

            if (!app.executable.isEmpty() &&
                !files.contains(
                    app.executable)) {
                files.append(
                    app.executable);
            }

            files.removeDuplicates();

            app.files = files;

            result.append(app);
        }

        return result;
    }


    static QString manualOptRootFor(
        const ApplicationInfo &app)
    {
        QString root =
            optApplicationRoot(
                app.installLocation);

        if (!root.isEmpty())
            return root;

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        for (QString part : execParts) {
            part = part.trimmed();

            if (part.startsWith(
                    QStringLiteral("file://"))) {
                part = part.mid(7);
            }

            root =
                optApplicationRoot(part);

            if (!root.isEmpty())
                return root;
        }

        for (const QString &file :
             app.files) {
            root =
                optApplicationRoot(file);

            if (!root.isEmpty())
                return root;
        }

        return {};
    }


    static int manualOptApplicationScore(
        const ApplicationInfo &app,
        const QString &root)
    {
        int score = 0;

        const QString rootName =
            QFileInfo(root)
                .fileName()
                .toLower();

        const QString name =
            app.name.trimmed().toLower();

        const QString id =
            app.id.trimmed().toLower();

        const QString executable =
            app.executable.trimmed();

        QString executableName;

        const QStringList parts =
            QProcess::splitCommand(
                executable);

        for (QString part : parts) {
            part = part.trimmed();

            if (part.startsWith(
                    QStringLiteral("file://"))) {
                part = part.mid(7);
            }

            if (!part.startsWith(root))
                continue;

            executableName =
                QFileInfo(part)
                    .fileName()
                    .toLower();

            break;
        }

        if (!app.description
                 .trimmed()
                 .isEmpty()) {
            score += 100;
        }

        if (!rootName.isEmpty() &&
            name.contains(rootName)) {
            score += 80;
        }

        if (!rootName.isEmpty() &&
            id.contains(rootName)) {
            score += 60;
        }

        if (!rootName.isEmpty() &&
            executableName == rootName) {
            score += 150;
        }

        if (executable.contains(
                QStringLiteral("/bin/"))) {
            score += 40;
        }

        if (!app.desktopFile.isEmpty())
            score += 20;

        const QString helperText =
            name +
            QLatin1Char(' ') +
            id +
            QLatin1Char(' ') +
            executableName;

        const QStringList helperTerms = {
            QStringLiteral("uninstall"),
            QStringLiteral("installer"),
            QStringLiteral("setup"),
            QStringLiteral("updater"),
            QStringLiteral("update"),
            QStringLiteral("capture log"),
            QStringLiteral("diagnostic"),
            QStringLiteral("helper"),
            QStringLiteral("daemon")
        };

        for (const QString &term :
             helperTerms) {
            if (helperText.contains(term))
                score -= 300;
        }

        return score;
    }


    static bool manualOptHelperLike(
        const ApplicationInfo &app)
    {
        const QString text =
            (app.name +
             QLatin1Char(' ') +
             app.id +
             QLatin1Char(' ') +
             QFileInfo(
                 app.executable)
                 .fileName())
                .toLower();

        const QStringList terms = {
            QStringLiteral("uninstall"),
            QStringLiteral("installer"),
            QStringLiteral("setup"),
            QStringLiteral("updater"),
            QStringLiteral("update"),
            QStringLiteral("capture log"),
            QStringLiteral("diagnostic"),
            QStringLiteral("helper"),
            QStringLiteral("daemon")
        };

        for (const QString &term :
             terms) {
            if (text.contains(term))
                return true;
        }

        return false;
    }


    static void collapseManualOptApplications(
        QList<ApplicationInfo> &applications)
    {
        QMap<QString, QList<ApplicationInfo>> groups;
        QList<ApplicationInfo> unchanged;

        for (const ApplicationInfo &app :
             applications) {
            if (app.type ==
                    ApplicationType::RPM ||
                app.type ==
                    ApplicationType::Flatpak ||
                app.type ==
                    ApplicationType::AppImage) {
                unchanged.append(app);
                continue;
            }

            const QString root =
                manualOptRootFor(app);

            if (root.isEmpty() ||
                !QFileInfo(root).isDir()) {
                unchanged.append(app);
                continue;
            }

            groups[root].append(app);
        }

        for (auto it =
                 groups.cbegin();
             it != groups.cend();
             ++it) {
            const QString root =
                it.key();

            const QList<ApplicationInfo> members =
                it.value();

            if (members.isEmpty())
                continue;

            int bestIndex = 0;
            int bestScore =
                manualOptApplicationScore(
                    members.first(),
                    root);

            for (int i = 1;
                 i < members.size();
                 ++i) {
                const int score =
                    manualOptApplicationScore(
                        members.at(i),
                        root);

                if (score > bestScore) {
                    bestScore = score;
                    bestIndex = i;
                }
            }

            ApplicationInfo merged =
                members.at(bestIndex);

            QStringList files;
            QStringList locations = {
                root
            };

            for (const ApplicationInfo &member :
                 members) {
                if (merged.description
                        .trimmed()
                        .isEmpty() &&
                    !member.description
                         .trimmed()
                         .isEmpty()) {
                    merged.description =
                        member.description.trimmed();
                }

                if (merged.version
                        .trimmed()
                        .isEmpty() &&
                    !member.version
                         .trimmed()
                         .isEmpty()) {
                    merged.version =
                        member.version.trimmed();
                }

                if (merged.desktopFile
                        .trimmed()
                        .isEmpty() &&
                    !member.desktopFile
                         .trimmed()
                         .isEmpty()) {
                    merged.desktopFile =
                        member.desktopFile;
                }

                for (const QString &file :
                     member.files) {
                    if (!file.trimmed().isEmpty() &&
                        !files.contains(file)) {
                        files.append(file);
                    }
                }

                if (!member.desktopFile
                         .trimmed()
                         .isEmpty() &&
                    !files.contains(
                        member.desktopFile)) {
                    files.append(
                        member.desktopFile);
                }
            }

            if (merged.installedSize
                    .trimmed()
                    .isEmpty()) {
                merged.installedSize =
                    manualSizeText(
                        manualDirectorySize(
                            root));
            }

            if (merged.installDate
                    .trimmed()
                    .isEmpty()) {
                const QFileInfo rootInfo(
                    root);

                QDateTime installTime =
                    rootInfo.birthTime();

                if (!installTime.isValid())
                    installTime =
                        rootInfo.lastModified();

                if (installTime.isValid()) {
                    merged.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    merged.installDateEstimated =
                        true;
                }
            }

            merged.installLocation =
                root;

            merged.installLocations =
                locations;

            merged.files =
                files;

            merged.packageManager =
                QStringLiteral(
                    "Manual / Local");

            merged.source =
                QStringLiteral("Local");

            merged.type =
                ApplicationType::Custom;

            merged.installed = true;
            merged.removable = true;
            merged.userInstalled = true;
            merged.systemComponent = false;
            merged.protectedComponent = false;

            unchanged.append(merged);

            QSet<QString> componentKeys;

            for (int i = 0;
                 i < members.size();
                 ++i) {
                if (i == bestIndex)
                    continue;

                const ApplicationInfo &member =
                    members.at(i);

                if (member.desktopFile
                        .trimmed()
                        .isEmpty() ||
                    manualOptHelperLike(
                        member)) {
                    continue;
                }

                const QString memberName =
                    member.name
                        .trimmed();

                if (memberName.isEmpty() ||
                    memberName.compare(
                        merged.name,
                        Qt::CaseInsensitive) == 0) {
                    continue;
                }

                const QString key =
                    memberName.toLower() +
                    QLatin1Char('|') +
                    member.desktopFile
                        .trimmed()
                        .toLower();

                if (componentKeys.contains(key))
                    continue;

                componentKeys.insert(key);

                ApplicationInfo component =
                    member;

                component.installLocation =
                    root;

                component.installLocations = {
                    root
                };

                component.packageManager =
                    QStringLiteral(
                        "Manual / Local (Bundled)");

                component.source =
                    QStringLiteral(
                        "Bundled component");

                component.installedSize.clear();

                component.installDate =
                    merged.installDate;

                component.installDateEstimated =
                    merged.installDateEstimated;

                if (component.description
                        .trimmed()
                        .isEmpty()) {
                    component.description =
                        QStringLiteral(
                            "Bundled component of %1")
                            .arg(
                                merged.name.isEmpty()
                                    ? QFileInfo(root)
                                          .fileName()
                                    : merged.name);
                }

                component.type =
                    ApplicationType::Custom;

                component.installed = true;
                component.removable = false;
                component.userInstalled = true;
                component.systemComponent = false;
                component.protectedComponent = false;

                unchanged.append(component);
            }
        }

        applications =
            std::move(unchanged);
    }


    static QString cleanMetadataText(
        QString value)
    {
        value.remove(
            QRegularExpression(
                QStringLiteral(
                    R"(<[^>]+>)")));

        value.replace(
            QStringLiteral("&quot;"),
            QStringLiteral("\""));

        value.replace(
            QStringLiteral("&apos;"),
            QStringLiteral("'"));

        value.replace(
            QStringLiteral("&lt;"),
            QStringLiteral("<"));

        value.replace(
            QStringLiteral("&gt;"),
            QStringLiteral(">"));

        value.replace(
            QStringLiteral("&amp;"),
            QStringLiteral("&"));

        return value.simplified();
    }


    static QStringList localMetadataDirectories(
        const ApplicationInfo &app)
    {
        QStringList directories;

        auto addCandidate =
            [&directories](QString candidate) {
                candidate =
                    candidate.trimmed();

                if (candidate.startsWith(
                        QStringLiteral(
                            "file://"))) {
                    candidate =
                        candidate.mid(7);
                }

                if (candidate.isEmpty())
                    return;

                QFileInfo info(candidate);

                if (!info.exists())
                    return;

                QString current;

                if (info.isDir()) {
                    current =
                        info.canonicalFilePath();

                    if (current.isEmpty())
                        current =
                            info.absoluteFilePath();
                }
                else {
                    QString canonical =
                        info.canonicalFilePath();

                    if (canonical.isEmpty())
                        canonical =
                            info.absoluteFilePath();

                    current =
                        QFileInfo(canonical)
                            .absolutePath();
                }

                for (int depth = 0;
                     depth < 4 &&
                     !current.isEmpty() &&
                     current !=
                         QStringLiteral("/");
                     ++depth) {
                    current =
                        QDir::cleanPath(
                            current);

                    if (!directories.contains(
                            current)) {
                        directories.append(
                            current);
                    }

                    const QString parent =
                        QFileInfo(current)
                            .absolutePath();

                    if (parent == current)
                        break;

                    current = parent;
                }
            };

        addCandidate(
            app.installLocation);

        for (const QString &location :
             app.installLocations) {
            addCandidate(location);
        }

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        for (QString part :
             execParts) {
            part = part.trimmed();

            if (part.isEmpty() ||
                part.startsWith(
                    QLatin1Char('%'))) {
                continue;
            }

            addCandidate(part);
        }

        if (!app.desktopFile
                 .trimmed()
                 .isEmpty() &&
            QFileInfo::exists(
                app.desktopFile)) {
            QSettings desktop(
                app.desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            addCandidate(
                desktop.value(
                    QStringLiteral("TryExec"))
                    .toString());

            const QString exec =
                desktop.value(
                    QStringLiteral("Exec"))
                    .toString();

            desktop.endGroup();

            const QStringList parts =
                QProcess::splitCommand(exec);

            for (QString part :
                 parts) {
                part = part.trimmed();

                if (part.isEmpty() ||
                    part.startsWith(
                        QLatin1Char('%'))) {
                    continue;
                }

                addCandidate(part);
            }
        }

        return directories;
    }


    static QStringList resolvedLocalLauncherTargets(
        const ApplicationInfo &app)
    {
        QStringList targets;

        auto addTarget =
            [&targets](QString candidate) {
                candidate =
                    candidate.trimmed();

                if (candidate.startsWith(
                        QStringLiteral(
                            "file://"))) {
                    candidate =
                        candidate.mid(7);
                }

                if (!QDir::isAbsolutePath(
                        candidate)) {
                    return;
                }

                const QFileInfo info(candidate);

                if (!info.isFile())
                    return;

                QString canonical =
                    info.canonicalFilePath();

                if (canonical.isEmpty())
                    canonical =
                        info.absoluteFilePath();

                if (!targets.contains(
                        canonical)) {
                    targets.append(
                        canonical);
                }
            };

        auto addCommand =
            [&addTarget](
                const QString &command) {
                const QStringList parts =
                    QProcess::splitCommand(
                        command.trimmed());

                const QRegularExpression assignment(
                    QStringLiteral(
                        R"(^[A-Za-z_][A-Za-z0-9_]*=.*$)"));

                for (QString part : parts) {
                    part =
                        part.trimmed();

                    if (part.isEmpty() ||
                        part ==
                            QStringLiteral("env") ||
                        part.startsWith(
                            QLatin1Char('%')) ||
                        assignment.match(part)
                            .hasMatch()) {
                        continue;
                    }

                    addTarget(part);
                }
            };

        addCommand(
            app.executable);

        if (!app.desktopFile
                 .trimmed()
                 .isEmpty() &&
            QFileInfo::exists(
                app.desktopFile)) {
            QSettings desktop(
                app.desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral(
                    "Desktop Entry"));

            addTarget(
                desktop.value(
                    QStringLiteral("TryExec"))
                    .toString());

            addCommand(
                desktop.value(
                    QStringLiteral("Exec"))
                    .toString());

            desktop.endGroup();
        }

        for (int index = 0;
             index < targets.size();
             ++index) {
            const QString candidate =
                targets.at(index);

            const QFileInfo info(
                candidate);

            if (!info.isFile() ||
                info.size() <= 0 ||
                info.size() > 131072) {
                continue;
            }

            QFile file(candidate);

            if (!file.open(
                    QIODevice::ReadOnly |
                    QIODevice::Text)) {
                continue;
            }

            const QString contents =
                QString::fromUtf8(
                    file.read(131072));

            file.close();

            if (!contents.startsWith(
                    QStringLiteral("#!"))) {
                continue;
            }

            const QRegularExpression homeTarget(
                QStringLiteral(
                    R"((?:exec\s+)?["']?(?:\$HOME|\$\{HOME\}|~)(/[^"'\s]+))"));

            QRegularExpressionMatchIterator
                homeMatches =
                    homeTarget.globalMatch(
                        contents);

            while (homeMatches.hasNext()) {
                const QString relative =
                    homeMatches.next()
                        .captured(1);

                if (!relative.isEmpty()) {
                    addTarget(
                        QDir::homePath() +
                        relative);
                }
            }

            const QRegularExpression absoluteTarget(
                QStringLiteral(
                    R"(exec\s+["']?(/[^"'\s]+))"));

            QRegularExpressionMatchIterator
                absoluteMatches =
                    absoluteTarget.globalMatch(
                        contents);

            while (absoluteMatches.hasNext()) {
                const QString absolute =
                    absoluteMatches.next()
                        .captured(1);

                if (!absolute.isEmpty())
                    addTarget(absolute);
            }
        }

        return targets;
    }


    static QString structuredApplicationIniVersion(
        const ApplicationInfo &app)
    {
        const QStringList targets =
            resolvedLocalLauncherTargets(
                app);

        for (const QString &target :
             targets) {
            QFileInfo info(target);

            QString directory =
                info.isDir()
                    ? info.absoluteFilePath()
                    : info.absolutePath();

            for (int depth = 0;
                 depth < 4 &&
                 !directory.isEmpty() &&
                 directory !=
                     QStringLiteral("/");
                 ++depth) {
                const QStringList candidates = {
                    QDir(directory)
                        .filePath(
                            QStringLiteral(
                                "application.ini")),
                    QDir(directory)
                        .filePath(
                            QStringLiteral(
                                "browser/application.ini"))
                };

                for (const QString &iniPath :
                     candidates) {
                    if (!QFileInfo::exists(
                            iniPath)) {
                        continue;
                    }

                    QSettings ini(
                        iniPath,
                        QSettings::IniFormat);

                    ini.beginGroup(
                        QStringLiteral("App"));

                    const QString declaredName =
                        ini.value(
                            QStringLiteral("Name"))
                            .toString()
                            .trimmed();

                    const QString version =
                        ini.value(
                            QStringLiteral("Version"))
                            .toString()
                            .trimmed();

                    ini.endGroup();

                    if (version.isEmpty())
                        continue;

                    if (!declaredName.isEmpty()) {
                        const bool nameMatches =
                            (!app.name
                                  .trimmed()
                                  .isEmpty() &&
                             declaredName.compare(
                                 app.name.trimmed(),
                                 Qt::CaseInsensitive) == 0);

                        const bool idMatches =
                            (!app.id
                                  .trimmed()
                                  .isEmpty() &&
                             declaredName.compare(
                                 app.id.trimmed(),
                                 Qt::CaseInsensitive) == 0);

                        if (!nameMatches &&
                            !idMatches) {
                            continue;
                        }
                    }

                    return version;
                }

                const QString parent =
                    QFileInfo(directory)
                        .absolutePath();

                if (parent == directory)
                    break;

                directory = parent;
            }
        }

        return {};
    }


    static QString desktopEntryValueFromText(
        const QString &contents,
        const QString &key)
    {
        bool inDesktopEntry = false;

        const QStringList lines =
            contents.split(
                QLatin1Char('\n'));

        for (QString line : lines) {
            line =
                line.trimmed();

            if (line.startsWith(
                    QLatin1Char('[')) &&
                line.endsWith(
                    QLatin1Char(']'))) {
                inDesktopEntry =
                    line.compare(
                        QStringLiteral(
                            "[Desktop Entry]"),
                        Qt::CaseInsensitive) == 0;

                continue;
            }

            if (!inDesktopEntry)
                continue;

            const QString prefix =
                key +
                QLatin1Char('=');

            if (line.startsWith(
                    prefix,
                    Qt::CaseSensitive)) {
                return line.mid(
                    prefix.size())
                    .trimmed();
            }
        }

        return {};
    }


    static QStringList appImageMetadataPaths(
        const QString &imagePath)
    {
        QStringList paths;

        QProcess process;

        process.start(
            QStringLiteral("7z"),
            {
                QStringLiteral("l"),
                QStringLiteral("-slt"),
                imagePath
            });

        if (!process.waitForStarted(
                5000)) {
            return {};
        }

        if (!process.waitForFinished(
                30000)) {
            process.kill();
            process.waitForFinished();
            return {};
        }

        if (process.exitStatus() !=
                QProcess::NormalExit ||
            process.exitCode() != 0) {
            return {};
        }

        const QString output =
            QString::fromLocal8Bit(
                process.readAllStandardOutput());

        const QStringList lines =
            output.split(
                QLatin1Char('\n'));

        for (QString line : lines) {
            line =
                line.trimmed();

            if (!line.startsWith(
                    QStringLiteral(
                        "Path = "))) {
                continue;
            }

            const QString candidate =
                line.mid(7).trimmed();

            if (candidate.endsWith(
                    QStringLiteral(
                        ".desktop"),
                    Qt::CaseInsensitive) ||
                candidate.endsWith(
                    QStringLiteral(
                        ".appdata.xml"),
                    Qt::CaseInsensitive) ||
                candidate.endsWith(
                    QStringLiteral(
                        ".metainfo.xml"),
                    Qt::CaseInsensitive)) {
                if (!paths.contains(
                        candidate)) {
                    paths.append(
                        candidate);
                }
            }
        }

        return paths;
    }


    static QByteArray readAppImageMetadataPath(
        const QString &imagePath,
        const QString &archivePath)
    {
        QProcess process;

        process.start(
            QStringLiteral("7z"),
            {
                QStringLiteral("e"),
                QStringLiteral("-so"),
                QStringLiteral("-bd"),
                QStringLiteral("-y"),
                imagePath,
                archivePath
            });

        if (!process.waitForStarted(
                5000)) {
            return {};
        }

        if (!process.waitForFinished(
                30000)) {
            process.kill();
            process.waitForFinished();
            return {};
        }

        if (process.exitStatus() !=
                QProcess::NormalExit ||
            process.exitCode() != 0) {
            return {};
        }

        const QByteArray contents =
            process.readAllStandardOutput();

        if (contents.size() >
                2 * 1024 * 1024) {
            return {};
        }

        return contents;
    }


    static bool embeddedAppImageMetadata(
        const QString &imagePath,
        QString &name,
        QString &version,
        QString &description)
    {
        if (!isAppImageFile(
                imagePath)) {
            return false;
        }

        const QStringList paths =
            appImageMetadataPaths(
                imagePath);

        if (paths.isEmpty())
            return false;

        int bestScore =
            std::numeric_limits<int>::min();

        QString bestName;
        QString bestVersion;
        QString bestDescription;

        QSet<QString> summaries;

        for (const QString &archivePath :
             paths) {
            const QByteArray bytes =
                readAppImageMetadataPath(
                    imagePath,
                    archivePath);

            if (bytes.isEmpty())
                continue;

            const QString contents =
                QString::fromUtf8(
                    bytes);

            if (archivePath.endsWith(
                    QStringLiteral(
                        ".desktop"),
                    Qt::CaseInsensitive)) {
                const QString type =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral("Type"));

                const QString hidden =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral("Hidden"));

                const QString noDisplay =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral("NoDisplay"));

                const QString candidateName =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral("Name"));

                const QString genericName =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral(
                            "GenericName"));

                const QString comment =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral("Comment"));

                const QString candidateVersion =
                    desktopEntryValueFromText(
                        contents,
                        QStringLiteral(
                            "X-AppImage-Version"));

                if ((!type.isEmpty() &&
                     type.compare(
                         QStringLiteral(
                             "Application"),
                         Qt::CaseInsensitive) != 0) ||
                    hidden.compare(
                        QStringLiteral("true"),
                        Qt::CaseInsensitive) == 0) {
                    continue;
                }

                int score = 0;

                if (!candidateVersion.isEmpty())
                    score += 150;

                if (!comment.isEmpty())
                    score += 120;

                if (!candidateName.isEmpty())
                    score += 50;

                if (!genericName.isEmpty())
                    score += 20;

                if (noDisplay.compare(
                        QStringLiteral("true"),
                        Qt::CaseInsensitive) == 0) {
                    score -= 80;
                }

                const QString helperText =
                    (candidateName +
                     QLatin1Char(' ') +
                     archivePath)
                        .toLower();

                const QStringList helperTerms = {
                    QStringLiteral("uninstall"),
                    QStringLiteral("installer"),
                    QStringLiteral("setup"),
                    QStringLiteral("updater"),
                    QStringLiteral("helper")
                };

                for (const QString &term :
                     helperTerms) {
                    if (helperText.contains(
                            term)) {
                        score -= 250;
                    }
                }

                if (score > bestScore) {
                    bestScore =
                        score;

                    bestName =
                        candidateName;

                    bestVersion =
                        candidateVersion;

                    if (!comment.isEmpty()) {
                        bestDescription =
                            comment;
                    }
                    else if (!genericName.isEmpty() &&
                             genericName.compare(
                                 candidateName,
                                 Qt::CaseInsensitive) != 0) {
                        bestDescription =
                            genericName;
                    }
                    else {
                        bestDescription.clear();
                    }
                }

                continue;
            }

            const QRegularExpression summaryExpression(
                QStringLiteral(
                    R"(<summary(?:\s[^>]*)?>(.*?)</summary>)"),
                QRegularExpression::
                    CaseInsensitiveOption |
                QRegularExpression::
                    DotMatchesEverythingOption);

            const QRegularExpressionMatch
                summaryMatch =
                    summaryExpression.match(
                        contents);

            if (summaryMatch.hasMatch()) {
                const QString summary =
                    cleanMetadataText(
                        summaryMatch
                            .captured(1));

                if (!summary.isEmpty())
                    summaries.insert(
                        summary);
            }
        }

        if (bestDescription.isEmpty() &&
            summaries.size() == 1) {
            bestDescription =
                *summaries.cbegin();
        }

        bool changed = false;

        if (name.trimmed().isEmpty() &&
            !bestName.isEmpty()) {
            name =
                bestName;

            changed = true;
        }

        if (version.trimmed().isEmpty() &&
            !bestVersion.isEmpty()) {
            version =
                bestVersion;

            changed = true;
        }

        if (description
                .trimmed()
                .isEmpty() &&
            !bestDescription.isEmpty()) {
            description =
                cleanMetadataText(
                    bestDescription);

            changed = true;
        }

        return changed;
    }


    static void enrichManualOptDesktopMetadata(
        ApplicationInfo &app)
    {
        const QString root =
            manualOptRootFor(app);

        if (root.isEmpty() ||
            !QFileInfo(root).isDir()) {
            return;
        }

        int bestScore =
            std::numeric_limits<int>::min();

        QString bestName;
        QString bestDescription;
        QString bestDesktop;
        QString bestExecutable;

        const QStringList directories = {
            QDir::homePath() +
                QStringLiteral(
                    "/.local/share/applications"),
            QStringLiteral(
                "/usr/local/share/applications"),
            QStringLiteral(
                "/usr/share/applications")
        };

        for (const QString &directoryPath :
             directories) {
            QDir directory(
                directoryPath);

            if (!directory.exists())
                continue;

            const QFileInfoList entries =
                directory.entryInfoList(
                    {
                        QStringLiteral(
                            "*.desktop")
                    },
                    QDir::Files |
                        QDir::Readable |
                        QDir::NoDotAndDotDot,
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
                        QStringLiteral(
                            "NoDisplay"),
                        false)
                        .toBool();

                const QString candidateName =
                    desktop.value(
                        QStringLiteral("Name"))
                        .toString()
                        .trimmed();

                const QString genericName =
                    desktop.value(
                        QStringLiteral(
                            "GenericName"))
                        .toString()
                        .trimmed();

                const QString comment =
                    desktop.value(
                        QStringLiteral("Comment"))
                        .toString()
                        .trimmed();

                const QString exec =
                    desktop.value(
                        QStringLiteral("Exec"))
                        .toString()
                        .trimmed();

                const QString tryExec =
                    desktop.value(
                        QStringLiteral("TryExec"))
                        .toString()
                        .trimmed();

                desktop.endGroup();

                if (hidden ||
                    (!type.isEmpty() &&
                     type !=
                        QStringLiteral(
                            "Application"))) {
                    continue;
                }

                const QString executable =
                    desktopExecutablePath(
                        exec,
                        tryExec);

                if (executable.isEmpty() ||
                    optApplicationRoot(
                        executable) != root) {
                    continue;
                }

                int score = 0;

                if (!comment.isEmpty())
                    score += 120;

                if (!candidateName.isEmpty())
                    score += 40;

                if (!genericName.isEmpty())
                    score += 20;

                if (executable.contains(
                        QStringLiteral(
                            "/bin/"))) {
                    score += 40;
                }

                if (noDisplay)
                    score -= 100;

                const QString helperText =
                    (candidateName +
                     QLatin1Char(' ') +
                     entry.completeBaseName())
                        .toLower();

                const QStringList helperTerms = {
                    QStringLiteral("uninstall"),
                    QStringLiteral("installer"),
                    QStringLiteral("setup"),
                    QStringLiteral("updater"),
                    QStringLiteral("update"),
                    QStringLiteral("capture log"),
                    QStringLiteral("diagnostic"),
                    QStringLiteral("helper"),
                    QStringLiteral("daemon")
                };

                for (const QString &term :
                     helperTerms) {
                    if (helperText.contains(
                            term)) {
                        score -= 250;
                    }
                }

                if (score <= bestScore)
                    continue;

                bestScore = score;
                bestName =
                    candidateName;

                bestDesktop =
                    entry.absoluteFilePath();

                bestExecutable =
                    executable;

                if (!comment.isEmpty()) {
                    bestDescription =
                        comment;
                }
                else if (!genericName.isEmpty() &&
                         genericName.compare(
                             candidateName,
                             Qt::CaseInsensitive) != 0) {
                    bestDescription =
                        genericName;
                }
                else {
                    bestDescription.clear();
                }
            }
        }

        if (app.description
                .trimmed()
                .isEmpty() &&
            !bestDescription.isEmpty()) {
            app.description =
                bestDescription;
        }

        if (app.name
                .trimmed()
                .isEmpty() &&
            !bestName.isEmpty()) {
            app.name =
                bestName;
        }

        if (app.desktopFile
                .trimmed()
                .isEmpty() &&
            !bestDesktop.isEmpty()) {
            app.desktopFile =
                bestDesktop;
        }

        if (app.executable
                .trimmed()
                .isEmpty() &&
            !bestExecutable.isEmpty()) {
            app.executable =
                bestExecutable;
        }
    }


    static QString desktopEntryValueFromFile(
        const QString &desktopFile,
        const QString &key)
    {
        if (desktopFile.trimmed().isEmpty())
            return {};

        QFile file(desktopFile);

        if (!file.open(
                QIODevice::ReadOnly |
                QIODevice::Text)) {
            return {};
        }

        const QByteArray bytes =
            file.read(1024 * 1024);

        file.close();

        if (bytes.isEmpty())
            return {};

        return desktopEntryValueFromText(
            QString::fromUtf8(bytes),
            key);
    }


    static void enrichVerifiedLocalMetadata(
        QList<ApplicationInfo> &applications)
    {
        for (ApplicationInfo &app :
             applications) {
            if (app.description
                    .trimmed()
                    .isEmpty() &&
                !app.desktopFile
                     .trimmed()
                     .isEmpty() &&
                QFileInfo::exists(
                    app.desktopFile)) {
                const QString displayName =
                    desktopEntryValueFromFile(
                        app.desktopFile,
                        QStringLiteral("Name"));

                const QString genericName =
                    desktopEntryValueFromFile(
                        app.desktopFile,
                        QStringLiteral(
                            "GenericName"));

                const QString comment =
                    desktopEntryValueFromFile(
                        app.desktopFile,
                        QStringLiteral("Comment"));

                if (!comment.isEmpty()) {
                    app.description =
                        comment;
                }
                else if (!genericName.isEmpty() &&
                         genericName.compare(
                             displayName,
                             Qt::CaseInsensitive) != 0) {
                    app.description =
                        genericName;
                }
            }

            if (app.type ==
                    ApplicationType::AppImage) {
                const QString imagePath =
                    appImagePathFor(
                        app);

                if (!imagePath.isEmpty() &&
                    (app.version
                         .trimmed()
                         .isEmpty() ||
                     app.description
                         .trimmed()
                         .isEmpty() ||
                     app.name
                         .trimmed()
                         .isEmpty())) {
                    embeddedAppImageMetadata(
                        imagePath,
                        app.name,
                        app.version,
                        app.description);
                }
            }

            if (app.type !=
                    ApplicationType::RPM &&
                app.type !=
                    ApplicationType::Flatpak &&
                app.description
                    .trimmed()
                    .isEmpty()) {
                enrichManualOptDesktopMetadata(
                    app);
            }

            if (app.version
                    .trimmed()
                    .isEmpty() &&
                app.type !=
                    ApplicationType::RPM &&
                app.type !=
                    ApplicationType::Flatpak) {
                app.version =
                    structuredApplicationIniVersion(
                        app);
            }
        }
    }


    static QList<ApplicationInfo> detectLinkedOptApplications(
        const QList<ApplicationInfo> &existing)
    {
        QList<ApplicationInfo> result;
        QSet<QString> knownIds;
        QSet<QString> knownRoots;

        for (const ApplicationInfo &app : existing) {
            const QString id = app.id.trimmed().toLower();
            const QString location =
                QDir::cleanPath(app.installLocation.trimmed());

            if (!id.isEmpty())
                knownIds.insert(id);

            if (!location.isEmpty())
                knownRoots.insert(location);
        }

        auto rpmOwnsPath = [](const QString &path) {
            QProcess process;
            process.start(
                QStringLiteral("rpm"),
                {
                    QStringLiteral("-qf"),
                    path
                });

            if (!process.waitForFinished(5000)) {
                process.kill();
                process.waitForFinished();
                return false;
            }

            return process.exitStatus() ==
                       QProcess::NormalExit &&
                   process.exitCode() == 0;
        };

        const QStringList directories = {
            QStringLiteral("/usr/local/bin"),
            QStringLiteral("/usr/local/sbin")
        };

        for (const QString &directoryPath : directories) {
            QDir directory(directoryPath);

            if (!directory.exists())
                continue;

            const QFileInfoList entries =
                directory.entryInfoList(
                    QDir::Files |
                        QDir::System |
                        QDir::NoDotAndDotDot,
                    QDir::Name);

            for (const QFileInfo &entry : entries) {
                if (!entry.isSymLink())
                    continue;

                const QString linkPath =
                    QDir::cleanPath(
                        entry.absoluteFilePath());

                QString targetPath =
                    entry.symLinkTarget();

                if (targetPath.isEmpty())
                    continue;

                if (!QDir::isAbsolutePath(targetPath)) {
                    targetPath =
                        QDir(entry.absolutePath())
                            .absoluteFilePath(targetPath);
                }

                const QFileInfo targetInfo(targetPath);
                const QString canonicalTarget =
                    targetInfo.canonicalFilePath();

                if (!canonicalTarget.isEmpty())
                    targetPath = canonicalTarget;
                else
                    targetPath = QDir::cleanPath(targetPath);

                const QFileInfo resolved(targetPath);

                if (!resolved.isFile() ||
                    !resolved.isExecutable()) {
                    continue;
                }

                if (!targetPath.startsWith(
                        QStringLiteral("/opt/"))) {
                    continue;
                }

                const QStringList parts =
                    targetPath.split(
                        QLatin1Char('/'),
                        Qt::SkipEmptyParts);

                if (parts.size() < 2 ||
                    parts.at(0) !=
                        QStringLiteral("opt")) {
                    continue;
                }

                const QString installRoot =
                    QStringLiteral("/opt/") +
                    parts.at(1);

                if (!QFileInfo(installRoot).isDir() ||
                    knownRoots.contains(installRoot)) {
                    continue;
                }

                const QString id =
                    entry.fileName().trimmed();

                if (id.isEmpty() ||
                    knownIds.contains(id.toLower())) {
                    continue;
                }

                if (rpmOwnsPath(linkPath) ||
                    rpmOwnsPath(targetPath)) {
                    continue;
                }

                ApplicationInfo app;
                app.name = id;
                app.id = id;
                app.description =
                    QStringLiteral(
                        "Locally installed application");
                app.executable = linkPath;
                app.installLocation = installRoot;
                app.packageManager =
                    QStringLiteral("Manual / Local");
                app.source =
                    QStringLiteral("Local");

                app.version =
                    manualPythonPackageVersion(
                        installRoot,
                        id);

                app.installedSize =
                    manualSizeText(
                        manualDirectorySize(
                            installRoot));

                const QFileInfo installInfo(
                    installRoot);

                QDateTime installTime =
                    installInfo.birthTime();

                if (!installTime.isValid())
                    installTime =
                        installInfo.lastModified();

                if (installTime.isValid()) {
                    app.installDate =
                        installTime.date()
                            .toString(
                                Qt::ISODate);

                    app.installDateEstimated =
                        true;
                }

                app.files = {
                    linkPath,
                    targetPath
                };
                app.installLocations = {
                    installRoot
                };
                app.type =
                    ApplicationType::Custom;
                app.risk =
                    RiskLevel::Unknown;
                app.installed = true;
                app.removable = true;
                app.userInstalled = true;
                app.systemComponent = false;
                app.protectedComponent = false;

                result.append(app);
                knownIds.insert(id.toLower());
                knownRoots.insert(installRoot);
            }
        }

        return result;
    }


    void refreshApplications()
    {
        if (applicationRefreshRunning)
            return;

        applicationRefreshRunning = true;
        applicationDataFresh = false;

        updatePageToolbar();

        if (applicationInventoryLoaded) {
            search->setEnabled(true);
            search->setPlaceholderText(
                "Search cached applications while TotalSweep refreshes…");
        }
        else {
            applicationStatus->setText(
                "Loading installed applications...");

            search->setEnabled(false);
            search->setPlaceholderText(
                "Search will be available after the initial inventory loads…");
        }

        updateApplicationSelection();
        updateApplicationStatus();

        auto freshApplications =
            std::make_shared<QList<ApplicationInfo>>();

        auto refreshSucceeded =
            std::make_shared<bool>(false);

        QThread *thread =
            QThread::create(
                [freshApplications,
                 refreshSucceeded]() {

                    ApplicationBackendManager workerManager;

                    workerManager.registerBackend(
                        new RpmBackend);

                    workerManager.registerBackend(
                        new FlatpakBackend);

                    ApplicationLibrary workerLibrary(
                        &workerManager);

                    workerLibrary.refresh();

                    QList<ApplicationInfo> applications =
                        workerLibrary.applications();

                    const QList<ApplicationInfo> localApplications =
                        Window::detectLinkedOptApplications(
                            applications);

                    for (const ApplicationInfo &app :
                         localApplications) {
                        applications.append(app);
                    }

                    const QList<ApplicationInfo> desktopOptApplications =
                        Window::detectDesktopOptApplications(
                            applications);

                    for (const ApplicationInfo &app :
                         desktopOptApplications) {
                        applications.append(app);
                    }

                    const QList<ApplicationInfo> desktopAppImages =
                        Window::detectDesktopAppImages(
                            applications);

                    for (const ApplicationInfo &app :
                         desktopAppImages) {
                        applications.append(app);
                    }

                    const QList<ApplicationInfo> standaloneAppImages =
                        Window::detectStandaloneAppImages(
                            applications);

                    for (const ApplicationInfo &app :
                         standaloneAppImages) {
                        applications.append(app);
                    }

                    Window::enrichApplicationMetadata(
                        applications);

                    Window::collapseAppImageApplications(
                        applications);

                    Window::collapseManualOptApplications(
                        applications);

                    Window::enrichVerifiedLocalMetadata(
                        applications);

                    if (applications.isEmpty())
                        return;

                    *freshApplications =
                        std::move(applications);

                    *refreshSucceeded = true;

                    saveApplicationCacheFile(
                        *freshApplications);
                });

        connect(
            thread,
            &QThread::finished,
            this,
            [this,
             freshApplications,
             refreshSucceeded]() {

                applicationRefreshRunning = false;

                updatePageToolbar();

                if (*refreshSucceeded &&
                    !freshApplications->isEmpty()) {

                    allApplications =
                        std::move(
                            *freshApplications);

                    currentApplications =
                        allApplications;

                    applicationInventoryLoaded = true;
                    applicationDataFresh = true;

                    if (search)
                        search->setEnabled(true);

                    if (applicationModel) {
                        applicationModel->setApplications(
                            &allApplications);

                        applicationModel->setShowSystemItems(
                            true);

                        if (applicationFilterGroup) {
                            const int mode =
                                applicationFilterGroup
                                    ->checkedId();

                            applicationModel->setFilterMode(
                                mode >= 0
                                    ? mode
                                    : FilterRemovableApplications);
                        }
                    }

                    if (committedApplicationSearch.isEmpty()) {
                        showFullApplicationList(false);
                    }
                    else if (applicationModel) {
                        applicationModel->setQuery(
                            committedApplicationSearch);
                        updateApplicationStatus();
                    }

                    updateApplicationSelection();
                    updateApplicationStatus();
                }
                else {
                    applicationDataFresh = false;

                    if (applicationInventoryLoaded) {
                        if (search)
                            search->setEnabled(true);

                        installInfo->setText(
                            "The current application refresh failed. "
                            "The last known inventory is still shown, "
                            "but removal is disabled for safety.");
                    }
                    else {
                        if (search)
                            search->setEnabled(false);

                        applicationStatus->setText(
                            "TotalSweep could not build the installed-"
                            "application inventory.");

                        installInfo->setText(
                            "No cached inventory was available. "
                            "Restart TotalSweep to try the scan again.");
                    }

                    updateApplicationSelection();
                    updateApplicationStatus();
                }
            });

        connect(
            thread,
            &QThread::finished,
            thread,
            &QObject::deleteLater);

        thread->start();
    }

    void searchApplication()
    {
        if (pages &&
            pages->currentIndex() != 0) {

            return;
        }

        if (!applicationInventoryLoaded) {
            applicationStatus->setText(
                "Installed applications are still loading...");

            if (applicationView)
                applicationView->setEmptyMessage(
                    QStringLiteral(
                        "Loading installed applications…"));

            return;
        }

        committedApplicationSearch =
            search
                ? search->text().trimmed()
                : QString();

        if (applicationModel)
            applicationModel->setQuery(
                committedApplicationSearch);

        if (committedApplicationSearch.isEmpty()) {
            showFullApplicationList(false);
            return;
        }

        installInfo->setText(
            QString(
                "Results for \"%1\".")
                .arg(committedApplicationSearch));

        updateApplicationStatus();
    }


    void populateApplicationTree()
    {
        if (!applicationModel)
            return;

        applicationModel->setApplications(
            &allApplications);

        applicationModel->setShowSystemItems(true);

        if (applicationFilterGroup) {
            const int mode =
                applicationFilterGroup
                    ->checkedId();

            applicationModel->setFilterMode(
                mode >= 0
                    ? mode
                    : FilterRemovableApplications);
        }

        applicationModel->setQuery(
            committedApplicationSearch);

        updateSystemItemsButton();
        updateApplicationStatus();
        updateApplicationSelection();
    }

    void updateApplicationSelection()
    {
        const int selected =
            applicationModel
                ? applicationModel
                    ->checkedCount()
                : 0;

        const bool removalReady =
            applicationDataFresh &&
            !applicationRefreshRunning;

        if (clearApplicationsBtn)
            clearApplicationsBtn->setEnabled(
                selected > 0);

        if (uninstallSelectedBtn) {
            uninstallSelectedBtn->setEnabled(
                removalReady &&
                selected > 0);

            uninstallSelectedBtn->setText(
                selected > 0
                    ? QString(
                        "Uninstall Selected (%1)")
                        .arg(selected)
                    : QStringLiteral(
                        "Uninstall Selected"));
        }

        updateApplicationStatus();
    }

    static QString appImagePathFromText(
        const QString &text)
    {
        const QString value =
            text.trimmed();

        if (value.isEmpty())
            return {};

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

            const QStringList prefixes = {
                QStringLiteral("${HOME}/"),
                QStringLiteral("$HOME/"),
                QStringLiteral("~/")
            };

            for (const QString &prefix : prefixes) {
                const int pos =
                    value.lastIndexOf(
                        prefix,
                        suffixEnd - 1,
                        Qt::CaseInsensitive);

                if (pos > start)
                    start = pos;
            }

            for (int pos = value.lastIndexOf('/', suffixEnd - 1);
                 pos >= 0;
                 pos = value.lastIndexOf('/', pos - 1)) {

                if (pos == 0) {
                    if (start < 0)
                        start = 0;
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
                value.mid(start, suffixEnd - start)
                    .trimmed();

            candidate.replace(
                QStringLiteral("\\ "),
                QStringLiteral(" "));

            if (candidate.startsWith(
                    QStringLiteral("file://"),
                    Qt::CaseInsensitive)) {
                candidate = candidate.mid(7);
            }

            candidate.replace(
                QStringLiteral("${HOME}"),
                QDir::homePath());
            candidate.replace(
                QStringLiteral("$HOME"),
                QDir::homePath());

            if (candidate.startsWith(QStringLiteral("~/"))) {
                candidate =
                    QDir::homePath() + candidate.mid(1);
            }

            candidate =
                QDir::cleanPath(candidate);

            if (QFileInfo(candidate).isAbsolute())
                candidates.append(candidate);
        }

        for (auto candidate = candidates.crbegin();
             candidate != candidates.crend();
             ++candidate) {

            QFileInfo info(*candidate);
            if (info.exists() || info.isSymLink())
                return *candidate;
        }

        return candidates.isEmpty()
            ? QString()
            : candidates.last();
    }


    static QString normalizeApplicationName(
        QString value)
    {
        value = value.toLower();

        QString result;
        for (const QChar c : value) {
            if (c.isLetterOrNumber())
                result.append(c);
        }

        return result;
    }


    static QString expandedManualPathToken(
        QString token)
    {
        token = token.trimmed();
        if (token.isEmpty())
            return {};

        if ((token.startsWith(QLatin1Char('"')) &&
             token.endsWith(QLatin1Char('"'))) ||
            (token.startsWith(QLatin1Char('\'')) &&
             token.endsWith(QLatin1Char('\'')))) {
            token = token.mid(1, token.size() - 2).trimmed();
        }

        const int equals = token.indexOf(QLatin1Char('='));
        if (equals > 0 &&
            token.left(equals).startsWith(QStringLiteral("--"))) {
            token = token.mid(equals + 1).trimmed();
        }

        if (token.startsWith(
                QStringLiteral("file://"),
                Qt::CaseInsensitive)) {
            token = token.mid(7);
        }

        token.replace(
            QStringLiteral("${HOME}"),
            QDir::homePath());
        token.replace(
            QStringLiteral("$HOME"),
            QDir::homePath());

        if (token.startsWith(QStringLiteral("~/")))
            token = QDir::homePath() + token.mid(1);

        if (token.startsWith(QLatin1Char('%')) ||
            token.startsWith(QLatin1Char('-')) ||
            token.contains(QLatin1Char('\n')) ||
            token.contains(QChar::Null)) {
            return {};
        }

        if (QDir::isAbsolutePath(token)) {
            QString cleaned =
                QDir::cleanPath(token);

            const QList<QPair<QString, QString>> aliases = {
                {QStringLiteral("/bin/"), QStringLiteral("/usr/bin/")},
                {QStringLiteral("/sbin/"), QStringLiteral("/usr/sbin/")},
                {QStringLiteral("/lib/"), QStringLiteral("/usr/lib/")},
                {QStringLiteral("/lib64/"), QStringLiteral("/usr/lib64/")}
            };

            for (const auto &alias : aliases) {
                if (cleaned.startsWith(alias.first)) {
                    cleaned = alias.second +
                        cleaned.mid(alias.first.size());
                    break;
                }
            }

            return cleaned;
        }

        if (!token.contains(QLatin1Char('/')) &&
            !token.contains(QLatin1Char(' ')) &&
            !token.contains(QLatin1Char('='))) {

            const QString executable =
                QStandardPaths::findExecutable(token);

            if (!executable.isEmpty())
                return QDir::cleanPath(executable);
        }

        return {};
    }


    static QStringList launchPathCandidates(
        const QString &text)
    {
        QStringList result;

        const QString trimmed = text.trimmed();
        if (trimmed.isEmpty())
            return result;

        const QString appImage =
            appImagePathFromText(trimmed);
        if (!appImage.isEmpty())
            result.append(appImage);

        const QStringList parts =
            QProcess::splitCommand(trimmed);

        const QSet<QString> wrappers = {
            QStringLiteral("env"),
            QStringLiteral("sh"),
            QStringLiteral("bash"),
            QStringLiteral("dash"),
            QStringLiteral("zsh"),
            QStringLiteral("fish"),
            QStringLiteral("python"),
            QStringLiteral("python3"),
            QStringLiteral("perl"),
            QStringLiteral("ruby"),
            QStringLiteral("java"),
            QStringLiteral("wine"),
            QStringLiteral("wine64"),
            QStringLiteral("mono"),
            QStringLiteral("node"),
            QStringLiteral("nodejs"),
            QStringLiteral("electron"),
            QStringLiteral("steam"),
            QStringLiteral("lutris"),
            QStringLiteral("gamemoderun"),
            QStringLiteral("mangohud"),
            QStringLiteral("prime-run"),
            QStringLiteral("systemd-run"),
            QStringLiteral("pkexec"),
            QStringLiteral("sudo"),
            QStringLiteral("nohup"),
            QStringLiteral("snap"),
            QStringLiteral("bwrap"),
            QStringLiteral("firejail"),
            QStringLiteral("nice"),
            QStringLiteral("ionice"),
            QStringLiteral("taskset"),
            QStringLiteral("flatpak-spawn"),
            QStringLiteral("flatpak"),
            QStringLiteral("gtk-launch"),
            QStringLiteral("xdg-open")
        };

        const QSet<QString> delegatingWrappers = {
            QStringLiteral("steam"),
            QStringLiteral("lutris"),
            QStringLiteral("wine"),
            QStringLiteral("wine64"),
            QStringLiteral("snap"),
            QStringLiteral("flatpak"),
            QStringLiteral("flatpak-spawn"),
            QStringLiteral("gtk-launch"),
            QStringLiteral("xdg-open")
        };

        for (const QString &part : parts) {
            const QString token = part.trimmed();
            if (token.isEmpty() || token.contains(QLatin1Char('=')))
                continue;

            QString base =
                QFileInfo(token).fileName().toLower();

            const QString resolved =
                expandedManualPathToken(token);
            if (!resolved.isEmpty())
                base = QFileInfo(resolved).fileName().toLower();

            if (delegatingWrappers.contains(base)) {
                result.removeAll(QString());
                result.removeDuplicates();
                return result;
            }
        }

        for (int i = 0; i < parts.size(); ++i) {
            QString part = parts.at(i).trimmed();
            if (part.isEmpty() ||
                part.startsWith(QLatin1Char('%')))
                continue;

            if (part.contains(QLatin1Char('=')) &&
                !part.startsWith(QLatin1Char('/')) &&
                !part.startsWith(QStringLiteral("~/")) &&
                !part.startsWith(QStringLiteral("$HOME")) &&
                !part.startsWith(QStringLiteral("${HOME}")) &&
                !part.startsWith(QStringLiteral("file://"))) {
                continue;
            }

            QString candidate =
                expandedManualPathToken(part);

            if (part.contains(QLatin1Char(' ')) &&
                (candidate.isEmpty() ||
                 !QFileInfo::exists(candidate))) {

                const QStringList nestedParts =
                    QProcess::splitCommand(part);

                for (const QString &nestedPart : nestedParts) {
                    const QString nestedCandidate =
                        expandedManualPathToken(nestedPart);

                    if (!nestedCandidate.isEmpty() &&
                        QFileInfo::exists(nestedCandidate)) {
                        result.append(nestedCandidate);
                    }
                }

                candidate.clear();
            }

            if (candidate.isEmpty())
                continue;

            const QString base =
                QFileInfo(candidate).fileName().toLower();

            if (wrappers.contains(base))
                continue;

            result.append(candidate);
        }

        result.removeAll(QString());
        result.removeDuplicates();
        return result;
    }


    static QString rpmOwnerForPath(
        const QString &path)
    {
        const QString cleaned =
            QDir::cleanPath(path.trimmed());

        const bool packageRoot =
            cleaned.startsWith(QStringLiteral("/usr/")) ||
            cleaned.startsWith(QStringLiteral("/opt/")) ||
            cleaned.startsWith(QStringLiteral("/etc/")) ||
            cleaned.startsWith(QStringLiteral("/var/")) ||
            cleaned.startsWith(QStringLiteral("/bin/")) ||
            cleaned.startsWith(QStringLiteral("/sbin/")) ||
            cleaned.startsWith(QStringLiteral("/lib/")) ||
            cleaned.startsWith(QStringLiteral("/lib64/"));

        if (!packageRoot)
            return {};

        QFileInfo info(cleaned);
        if (!info.exists() && !info.isSymLink())
            return {};

        QProcess process;
        process.start(
            QStringLiteral("rpm"),
            {
                QStringLiteral("-qf"),
                QStringLiteral("--qf"),
                QStringLiteral("%{NAME}"),
                cleaned
            });

        if (!process.waitForStarted(3000))
            return {};

        if (!process.waitForFinished(5000)) {
            process.kill();
            process.waitForFinished(500);
            return {};
        }

        if (process.exitStatus() != QProcess::NormalExit ||
            process.exitCode() != 0) {
            return {};
        }

        return QString::fromLocal8Bit(
            process.readAllStandardOutput())
            .trimmed();
    }


    static QString flatpakIdFromDesktopFile(
        const QString &desktopFile)
    {
        if (desktopFile.trimmed().isEmpty() ||
            !QFileInfo::exists(desktopFile)) {
            return {};
        }

        QSettings desktop(
            desktopFile,
            QSettings::IniFormat);

        desktop.beginGroup(
            QStringLiteral("Desktop Entry"));

        const QString flatpakId =
            desktop.value(
                QStringLiteral("X-Flatpak"))
                .toString()
                .trimmed();

        desktop.endGroup();
        return flatpakId;
    }


    static bool pathLooksRelatedToApplication(
        const ApplicationInfo &app,
        const QString &path)
    {
        const QString base =
            normalizeApplicationName(
                QFileInfo(path).completeBaseName());

        if (base.size() < 3)
            return false;

        const QSet<QString> genericNames = {
            QStringLiteral("app"),
            QStringLiteral("bin"),
            QStringLiteral("run"),
            QStringLiteral("main"),
            QStringLiteral("launcher"),
            QStringLiteral("start"),
            QStringLiteral("client")
        };

        if (genericNames.contains(base))
            return false;

        QStringList identities = {
            normalizeApplicationName(app.id),
            normalizeApplicationName(app.name)
        };

        const QStringList launchParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        if (!launchParts.isEmpty()) {
            identities.append(
                normalizeApplicationName(
                    QFileInfo(
                        launchParts.first())
                        .completeBaseName()));
        }

        identities.removeAll(QString());
        identities.removeDuplicates();

        for (const QString &identity : identities) {
            if (identity.size() < 3 ||
                genericNames.contains(identity))
                continue;

            if (base == identity ||
                base.contains(identity) ||
                identity.contains(base)) {
                return true;
            }
        }

        return false;
    }


    static bool isBroadUserDirectory(
        const QString &path)
    {
        const QString home =
            QDir::cleanPath(QDir::homePath());
        const QString cleaned =
            QDir::cleanPath(path);

        const QSet<QString> broad = {
            home,
            home + QStringLiteral("/Desktop"),
            home + QStringLiteral("/Documents"),
            home + QStringLiteral("/Downloads"),
            home + QStringLiteral("/Music"),
            home + QStringLiteral("/Pictures"),
            home + QStringLiteral("/Public"),
            home + QStringLiteral("/Templates"),
            home + QStringLiteral("/Videos")
        };

        return broad.contains(cleaned);
    }


    static bool homeManualTargetNeedsRelationship(
        const QString &path)
    {
        const QString home =
            QDir::cleanPath(QDir::homePath());
        const QString cleaned =
            QDir::cleanPath(path);

        if (!cleaned.startsWith(home + QLatin1Char('/')))
            return false;

        const QStringList conventionalRoots = {
            home + QStringLiteral("/.local/bin/"),
            home + QStringLiteral("/.local/libexec/"),
            home + QStringLiteral("/.local/opt/"),
            home + QStringLiteral("/Applications/"),
            home + QStringLiteral("/bin/"),
            home + QStringLiteral("/opt/")
        };

        for (const QString &root : conventionalRoots) {
            if (cleaned.startsWith(root))
                return false;
        }

        return true;
    }


    static bool safeManualRemovalTargetStatic(
        const QString &target)
    {
        const QString raw = target.trimmed();
        if (raw.isEmpty())
            return false;

        const QString cleaned =
            QDir::cleanPath(raw);

        if (!QDir::isAbsolutePath(cleaned) ||
            isTotalSweepManagedPath(cleaned)) {
            return false;
        }

        const QString home =
            QDir::cleanPath(QDir::homePath());

        const QSet<QString> protectedRoots = {
            QStringLiteral("/"),
            home,
            QStringLiteral("/opt"),
            QStringLiteral("/usr"),
            QStringLiteral("/usr/local"),
            QStringLiteral("/usr/bin"),
            QStringLiteral("/usr/sbin"),
            QStringLiteral("/usr/lib"),
            QStringLiteral("/usr/lib64"),
            QStringLiteral("/usr/libexec"),
            QStringLiteral("/usr/share"),
            QStringLiteral("/etc"),
            QStringLiteral("/var"),
            QStringLiteral("/bin"),
            QStringLiteral("/sbin"),
            QStringLiteral("/lib"),
            QStringLiteral("/lib64")
        };

        if (protectedRoots.contains(cleaned) ||
            isBroadUserDirectory(cleaned)) {
            return false;
        }

        const QString trustedRoot =
            trustedDestructiveRootForPath(cleaned);

        if (trustedRoot.isEmpty() ||
            hasSymlinkedParentBelowRoot(
                cleaned,
                trustedRoot)) {
            return false;
        }

        QFileInfo info(cleaned);

        if (cleaned.startsWith(home + QLatin1Char('/')))
            return true;

        if (cleaned.startsWith(QStringLiteral("/opt/")))
            return cleaned.count(QLatin1Char('/')) >= 2;

        if (cleaned.startsWith(QStringLiteral("/usr/local/")))
            return cleaned.count(QLatin1Char('/')) >= 3;

        if ((cleaned.startsWith(QStringLiteral("/usr/bin/")) ||
             cleaned.startsWith(QStringLiteral("/usr/sbin/")) ||
             cleaned.startsWith(QStringLiteral("/usr/libexec/"))) &&
            (info.isFile() || info.isSymLink())) {

            return rpmOwnerForPath(cleaned).isEmpty();
        }

        if (cleaned.startsWith(QStringLiteral("/usr/share/")) &&
            (info.isFile() || info.isSymLink())) {

            return rpmOwnerForPath(cleaned).isEmpty();
        }

        return false;
    }


    static QString collapseManualInstallRoot(
        const ApplicationInfo &app,
        const QString &path)
    {
        const QString cleaned =
            QDir::cleanPath(path);
        QFileInfo info(cleaned);

        if (cleaned.endsWith(
                QStringLiteral(".AppImage"),
                Qt::CaseInsensitive)) {
            return cleaned;
        }

        const QString home =
            QDir::cleanPath(QDir::homePath());

        const QStringList roots = {
            QStringLiteral("/opt"),
            home + QStringLiteral("/.local/opt"),
            home + QStringLiteral("/Applications"),
            home + QStringLiteral("/opt"),
            QStringLiteral("/usr/local/lib"),
            QStringLiteral("/usr/local/lib64"),
            QStringLiteral("/usr/local/share")
        };

        for (const QString &root : roots) {
            const QString prefix =
                QDir::cleanPath(root) + QLatin1Char('/');

            if (!cleaned.startsWith(prefix))
                continue;

            const QString relative =
                cleaned.mid(prefix.size());
            const QString first =
                relative.section(QLatin1Char('/'), 0, 0);

            if (first.isEmpty())
                return cleaned;

            const QSet<QString> generic = {
                QStringLiteral("applications"),
                QStringLiteral("icons"),
                QStringLiteral("metainfo"),
                QStringLiteral("mime")
            };

            if (generic.contains(first.toLower()))
                return cleaned;

            const QString candidate =
                QDir(root).filePath(first);

            if (QFileInfo(candidate).isDir() &&
                pathLooksRelatedToApplication(
                    app,
                    candidate)) {
                return candidate;
            }

            return cleaned;
        }

        return cleaned;
    }


    static void appendManualRemovalCandidate(
        ManualRemovalPlan &plan,
        const ApplicationInfo &app,
        const QString &rawPath,
        bool strongEvidence,
        bool primaryEligible)
    {
        QString path =
            expandedManualPathToken(rawPath);

        if (path.isEmpty())
            path = QDir::cleanPath(rawPath.trimmed());

        QFileInfo originalInfo(path);
        if (path.isEmpty() ||
            (!originalInfo.exists() &&
             !originalInfo.isSymLink())) {
            return;
        }

        const QString symlinkTarget =
            originalInfo.isSymLink()
                ? QDir::cleanPath(
                    originalInfo.symLinkTarget())
                : QString();

        path = collapseManualInstallRoot(app, path);

        QFileInfo info(path);
        if ((!info.exists() && !info.isSymLink()) ||
            !safeManualRemovalTargetStatic(path)) {
            return;
        }

        if (!rpmOwnerForPath(path).isEmpty())
            return;

        const bool related =
            pathLooksRelatedToApplication(app, path);

        if ((!strongEvidence ||
             homeManualTargetNeedsRelationship(path)) &&
            !related) {
            return;
        }

        for (int i = plan.paths.size() - 1;
             i >= 0;
             --i) {

            const QString existing =
                QDir::cleanPath(plan.paths.at(i));

            if (path.startsWith(existing + QLatin1Char('/')))
                return;

            if (existing.startsWith(path + QLatin1Char('/')))
                plan.paths.removeAt(i);
        }

        const bool added =
            !plan.paths.contains(path);

        if (added)
            plan.paths.append(path);

        if (primaryEligible && plan.primary.isEmpty())
            plan.primary = path;

        if (added &&
            !symlinkTarget.isEmpty() &&
            symlinkTarget != path) {

            appendManualRemovalCandidate(
                plan,
                app,
                symlinkTarget,
                true,
                primaryEligible);
        }
    }


    static QStringList manualSearchRoots()
    {
        const QString home =
            QDir::cleanPath(QDir::homePath());

        QStringList roots = {
            home + QStringLiteral("/Applications"),
            home + QStringLiteral("/.local/bin"),
            home + QStringLiteral("/.local/libexec"),
            home + QStringLiteral("/.local/opt"),
            home + QStringLiteral("/bin"),
            home + QStringLiteral("/opt"),
            QStringLiteral("/opt"),
            QStringLiteral("/usr/local/bin"),
            QStringLiteral("/usr/local/sbin"),
            QStringLiteral("/usr/local/libexec"),
            QStringLiteral("/usr/local/games"),
            QStringLiteral("/usr/local/lib"),
            QStringLiteral("/usr/local/lib64"),
            QStringLiteral("/usr/local/share")
        };

        const QStringList pathDirs =
            qEnvironmentVariable("PATH")
                .split(
                    QLatin1Char(':'),
                    Qt::SkipEmptyParts);

        for (const QString &directory : pathDirs) {
            const QString cleaned =
                QDir::cleanPath(directory);

            if (cleaned.startsWith(home + QLatin1Char('/')) ||
                cleaned.startsWith(QStringLiteral("/usr/local/"))) {
                roots.append(cleaned);
            }
        }

        roots.erase(
            std::remove_if(
                roots.begin(),
                roots.end(),
                [](const QString &root) {
                    return !QFileInfo(root).isDir();
                }),
            roots.end());

        roots.removeDuplicates();
        return roots;
    }


    static int manualSearchCandidateScore(
        const ApplicationInfo &app,
        const QString &path)
    {
        const QFileInfo info(path);
        const QString lowerPath =
            QDir::cleanPath(path).toLower();
        const QString suffix =
            info.suffix().toLower();

        if (lowerPath.contains(QStringLiteral("/applications/")) ||
            lowerPath.contains(QStringLiteral("/icons/")) ||
            lowerPath.contains(QStringLiteral("/metainfo/")) ||
            suffix == QStringLiteral("desktop") ||
            suffix == QStringLiteral("svg") ||
            suffix == QStringLiteral("png") ||
            suffix == QStringLiteral("xpm") ||
            suffix == QStringLiteral("xml")) {
            return 0;
        }

        const QString base =
            normalizeApplicationName(
                info.completeBaseName());

        const QString wantedName =
            normalizeApplicationName(app.name);
        QString wantedId =
            normalizeApplicationName(app.id);

        int score = 0;

        if (!wantedId.isEmpty() && base == wantedId)
            score = qMax(score, 120);
        else if (!wantedId.isEmpty() &&
                 base.contains(wantedId))
            score = qMax(score, 80);

        if (!wantedName.isEmpty() && base == wantedName)
            score = qMax(score, 110);
        else if (!wantedName.isEmpty() &&
                 base.contains(wantedName))
            score = qMax(score, 75);

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        for (const QString &part : execParts) {
            const QString execBase =
                normalizeApplicationName(
                    QFileInfo(part).completeBaseName());

            if (!execBase.isEmpty() &&
                base == execBase) {
                score = qMax(score, 140);
            }
        }

        if (app.type == ApplicationType::AppImage &&
            path.endsWith(
                QStringLiteral(".AppImage"),
                Qt::CaseInsensitive)) {
            score += 20;
        }

        if (info.isDir())
            score += 30;
        else if (info.isExecutable())
            score += 25;

        if (path.startsWith(QStringLiteral("/opt/")))
            score += 10;

        return score;
    }


    static QString bestManualSearchCandidate(
        const ApplicationInfo &app)
    {
        QStringList needles;

        const QString idBase =
            QFileInfo(app.id).completeBaseName().trimmed();
        const QString name =
            app.name.trimmed();

        if (idBase.size() >= 3)
            needles.append(idBase);
        if (name.size() >= 3)
            needles.append(name);

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());

        if (!execParts.isEmpty()) {
            const QString execBase =
                QFileInfo(execParts.first())
                    .fileName()
                    .trimmed();
            if (execBase.size() >= 3)
                needles.append(execBase);
        }

        needles.removeAll(QString());
        needles.removeDuplicates();

        QStringList found;

        for (const QString &root : manualSearchRoots()) {
            const int maxDepth =
                root == QStringLiteral("/opt") ||
                root.startsWith(QStringLiteral("/usr/local/lib")) ||
                root == QStringLiteral("/usr/local/share")
                    ? 4
                    : 2;

            for (const QString &needle : needles) {
                QProcess process;
                process.start(
                    QStringLiteral("find"),
                    {
                        root,
                        QStringLiteral("-xdev"),
                        QStringLiteral("-maxdepth"),
                        QString::number(maxDepth),
                        QStringLiteral("("),
                        QStringLiteral("-type"),
                        QStringLiteral("f"),
                        QStringLiteral("-o"),
                        QStringLiteral("-type"),
                        QStringLiteral("d"),
                        QStringLiteral(")"),
                        QStringLiteral("-iname"),
                        QStringLiteral("*%1*").arg(needle),
                        QStringLiteral("-print")
                    });

                if (!process.waitForStarted(2000))
                    continue;

                if (!process.waitForFinished(5000)) {
                    process.kill();
                    process.waitForFinished(500);
                    continue;
                }

                const QStringList lines =
                    QString::fromLocal8Bit(
                        process.readAllStandardOutput())
                        .split(
                            QLatin1Char('\n'),
                            Qt::SkipEmptyParts);

                for (const QString &line : lines.mid(0, 40)) {
                    const QString candidate =
                        QDir::cleanPath(line.trimmed());

                    if (safeManualRemovalTargetStatic(candidate) &&
                        !isTotalSweepManagedPath(candidate) &&
                        rpmOwnerForPath(candidate).isEmpty() &&
                        pathLooksRelatedToApplication(
                            app,
                            candidate)) {
                        found.append(candidate);
                    }
                }
            }
        }

        if (app.type == ApplicationType::AppImage) {
            QProcess process;
            process.start(
                QStringLiteral("find"),
                {
                    QDir::homePath(),
                    QStringLiteral("-xdev"),
                    QStringLiteral("-maxdepth"),
                    QStringLiteral("4"),
                    QStringLiteral("-type"),
                    QStringLiteral("f"),
                    QStringLiteral("-iname"),
                    QStringLiteral("*.AppImage"),
                    QStringLiteral("-print")
                });

            if (process.waitForStarted(2000) &&
                process.waitForFinished(8000)) {

                const QStringList lines =
                    QString::fromLocal8Bit(
                        process.readAllStandardOutput())
                        .split(
                            QLatin1Char('\n'),
                            Qt::SkipEmptyParts);

                for (const QString &line : lines.mid(0, 80)) {
                    const QString candidate =
                        QDir::cleanPath(line.trimmed());
                    if (safeManualRemovalTargetStatic(candidate) &&
                        pathLooksRelatedToApplication(app, candidate)) {
                        found.append(candidate);
                    }
                }
            }
            else if (process.state() != QProcess::NotRunning) {
                process.kill();
                process.waitForFinished(500);
            }
        }

        found.removeAll(QString());
        found.removeDuplicates();

        int bestScore = 0;
        QString best;
        bool tied = false;

        for (const QString &candidate : found) {
            const int score =
                manualSearchCandidateScore(
                    app,
                    candidate);

            if (score > bestScore) {
                bestScore = score;
                best = candidate;
                tied = false;
            }
            else if (score == bestScore &&
                     score > 0 &&
                     QDir::cleanPath(candidate) !=
                         QDir::cleanPath(best)) {
                tied = true;
            }
        }

        if (bestScore < 70 || tied)
            return {};

        return best;
    }


    static ManualRemovalPlan resolveManualRemovalPlan(
        const ApplicationInfo &app,
        bool deepSearch)
    {
        ManualRemovalPlan plan;

        if (!isManualLocal(app)) {
            plan.resolution =
                QStringLiteral(
                    "not a manual/local application");
            return plan;
        }

        appendManualRemovalCandidate(
            plan,
            app,
            app.installLocation,
            true,
            true);

        for (const QString &location :
             app.installLocations) {
            appendManualRemovalCandidate(
                plan,
                app,
                location,
                true,
                true);
        }

        QStringList launchTexts;
        launchTexts.append(app.executable);
        QString desktopExec;
        QString desktopWorkingDirectory;

        if (!app.desktopFile.trimmed().isEmpty() &&
            QFileInfo::exists(app.desktopFile)) {

            QSettings desktop(
                app.desktopFile,
                QSettings::IniFormat);

            desktop.beginGroup(
                QStringLiteral("Desktop Entry"));

            desktopExec =
                desktop.value(
                    QStringLiteral("Exec"))
                    .toString();
            desktopWorkingDirectory =
                desktop.value(
                    QStringLiteral("Path"))
                    .toString()
                    .trimmed();

            launchTexts.append(desktopExec);
            launchTexts.append(
                desktop.value(
                    QStringLiteral("TryExec"))
                    .toString());
            launchTexts.append(
                desktop.value(
                    QStringLiteral("X-AppImage-Path"))
                    .toString());

            desktop.endGroup();
        }

        for (const QString &launchText : launchTexts) {
            for (const QString &candidate :
                 launchPathCandidates(launchText)) {

                appendManualRemovalCandidate(
                    plan,
                    app,
                    candidate,
                    true,
                    true);
            }
        }

        if (!desktopWorkingDirectory.isEmpty() &&
            QFileInfo(desktopWorkingDirectory).isDir() &&
            !desktopExec.trimmed().isEmpty()) {

            const QStringList parts =
                QProcess::splitCommand(desktopExec.trimmed());

            for (const QString &part : parts) {
                QString token = part.trimmed();
                if (token.isEmpty() ||
                    token.startsWith(QLatin1Char('-')) ||
                    token.startsWith(QLatin1Char('%')) ||
                    token.contains(QLatin1Char('='))) {
                    continue;
                }

                if (QDir::isAbsolutePath(token))
                    continue;

                const QString relativeCandidate =
                    QDir(desktopWorkingDirectory)
                        .filePath(token);

                if (QFileInfo::exists(relativeCandidate)) {
                    appendManualRemovalCandidate(
                        plan,
                        app,
                        relativeCandidate,
                        true,
                        true);
                    break;
                }
            }
        }

        for (const QString &file : app.files) {
            appendManualRemovalCandidate(
                plan,
                app,
                file,
                false,
                plan.primary.isEmpty());
        }

        if (plan.primary.isEmpty() && deepSearch) {
            const QString searched =
                bestManualSearchCandidate(app);

            appendManualRemovalCandidate(
                plan,
                app,
                searched,
                true,
                true);
        }

        appendManualRemovalCandidate(
            plan,
            app,
            app.desktopFile,
            true,
            false);

        if (plan.primary.isEmpty() &&
            !plan.paths.isEmpty()) {

            for (const QString &path : plan.paths) {
                if (!path.endsWith(
                        QStringLiteral(".desktop"),
                        Qt::CaseInsensitive)) {
                    plan.primary = path;
                    break;
                }
            }
        }

        if (plan.resolved()) {
            plan.resolution =
                QStringLiteral(
                    "%1 verified application %2")
                    .arg(plan.paths.size())
                    .arg(wordForCount(
                        plan.paths.size(),
                        QStringLiteral("path"),
                        QStringLiteral("paths")));
        }
        else {
            plan.paths.clear();
            plan.primary.clear();
            plan.resolution =
                QStringLiteral(
                    "no unambiguous unmanaged application target could be verified");
        }

        return plan;
    }


    QString resolveManualRemovalTarget(
        const ApplicationInfo &app) const
    {
        return resolveManualRemovalPlan(
            app,
            true).primary;
    }


    bool safeManualRemovalTarget(
        const QString &target) const
    {
        return safeManualRemovalTargetStatic(target);
    }


    bool commandSucceeds(
        const QString &program,
        const QStringList &arguments,
        int timeout = 10000) const
    {
        QProcess process;

        process.start(
            program,
            arguments);

        if (!process.waitForStarted(5000))
            return false;

        if (!process.waitForFinished(timeout)) {
            process.kill();
            process.waitForFinished(1000);
            return false;
        }

        return process.exitStatus() ==
                QProcess::NormalExit &&
            process.exitCode() == 0;
    }


    QString resolvedFlatpakScope(
        const ApplicationInfo &app) const
    {
        const QString hinted =
            flatpakScopeForApplication(app);

        auto installedInScope =
            [this, &app](const QString &scope) {
                QStringList arguments{
                    QStringLiteral("info"),
                    scope == QStringLiteral("user")
                        ? QStringLiteral("--user")
                        : QStringLiteral("--system"),
                    app.id
                };
                return commandSucceeds(
                    QStringLiteral("flatpak"),
                    arguments,
                    10000);
            };

        if (!hinted.isEmpty() && installedInScope(hinted))
            return hinted;

        const bool userInstalled =
            installedInScope(QStringLiteral("user"));
        const bool systemInstalled =
            installedInScope(QStringLiteral("system"));

        if (userInstalled != systemInstalled) {
            return userInstalled
                ? QStringLiteral("user")
                : QStringLiteral("system");
        }

        return {};
    }


    RpmRemovalPreview previewRpmRemoval(
        const QStringList &packageIds)
    {
        RpmRemovalPreview preview;
        if (packageIds.isEmpty())
            return preview;

        const QString storeDirectory =
            totalSweepData() +
            QStringLiteral("/staging/dnf_preview_") +
            QString::number(
                QDateTime::currentMSecsSinceEpoch());

        QDir(storeDirectory).removeRecursively();

        QProcessEnvironment environment =
            QProcessEnvironment::systemEnvironment();
        environment.insert(QStringLiteral("LC_ALL"), QStringLiteral("C"));
        environment.insert(QStringLiteral("LANG"), QStringLiteral("C"));
        environment.insert(QStringLiteral("NO_COLOR"), QStringLiteral("1"));

        QStringList arguments{
            QStringLiteral("remove"),
            QStringLiteral("--store=%1").arg(storeDirectory),
            QStringLiteral("-y")
        };
        arguments += packageIds;

        const ProcessResult result =
            runProcessResponsive(
                this,
                QStringLiteral("Checking RPM Removal"),
                QStringLiteral("Calculating the DNF removal transaction…"),
                QStringLiteral("dnf"),
                arguments,
                180000,
                environment);

        preview = parseRpmRemovalPreview(
            result.standardOutput +
            QLatin1Char('\n') +
            result.standardError,
            packageIds);

        if (!preview.available) {
            QFile transactionFile(
                QDir(storeDirectory)
                    .filePath(
                        QStringLiteral(
                            "transaction.json")));

            if (transactionFile.open(
                    QIODevice::ReadOnly)) {
                const QJsonObject root =
                    QJsonDocument::fromJson(
                        transactionFile.readAll())
                        .object();

                const QJsonArray rpms =
                    root.value(
                        QStringLiteral("rpms"))
                        .toArray();

                QSet<QString> requested;
                for (const QString &package :
                     packageIds) {
                    requested.insert(
                        package.trimmed()
                            .toCaseFolded());
                }

                QStringList allPackages;
                QStringList unusedPackages;
                QStringList otherAdditional;

                for (const QJsonValue &value :
                     rpms) {
                    const QJsonObject rpm =
                        value.toObject();

                    const QString action =
                        rpm.value(
                            QStringLiteral("action"))
                            .toString();

                    if (action.compare(
                            QStringLiteral("Removed"),
                            Qt::CaseInsensitive) != 0 &&
                        action.compare(
                            QStringLiteral("Remove"),
                            Qt::CaseInsensitive) != 0) {
                        continue;
                    }

                    const QString nevra =
                        rpm.value(
                            QStringLiteral("nevra"))
                            .toString()
                            .trimmed();

                    QString packageName;
                    for (const QString &requestedId :
                         packageIds) {
                        if (nevra.startsWith(
                                requestedId +
                                QLatin1Char('-'))) {
                            packageName =
                                requestedId;
                            break;
                        }
                    }

                    if (packageName.isEmpty()) {
                        const QRegularExpression nameExpression(
                            QStringLiteral(
                                "^(.+)-[0-9]+:[^-]+-.+\\.[^.]+$"));
                        const QRegularExpressionMatch match =
                            nameExpression.match(
                                nevra);
                        if (match.hasMatch())
                            packageName =
                                match.captured(1);
                    }

                    if (packageName.isEmpty())
                        packageName = nevra;

                    if (packageName.isEmpty())
                        continue;

                    allPackages.append(
                        packageName);

                    if (!requested.contains(
                            packageName
                                .toCaseFolded())) {
                        const QString reason =
                            rpm.value(
                                QStringLiteral("reason"))
                                .toString()
                                .toLower();

                        if (reason ==
                            QStringLiteral("clean")) {
                            unusedPackages.append(
                                packageName);
                        }
                        else {
                            otherAdditional.append(
                                packageName);
                        }
                    }
                }

                allPackages.removeDuplicates();
                unusedPackages.removeDuplicates();
                otherAdditional.removeDuplicates();

                if (!allPackages.isEmpty()) {
                    preview.available = true;
                    preview.allPackages =
                        allPackages;
                    preview.unusedDependencies =
                        unusedPackages;
                    preview.additionalPackages =
                        unusedPackages +
                        otherAdditional;
                    preview.additionalPackages
                        .removeDuplicates();
                    preview.error.clear();
                }
            }
        }

        if (!preview.available) {
            if (!result.started) {
                preview.error =
                    QStringLiteral(
                        "DNF could not be started to preview this removal.");
            }
            else if (preview.error.isEmpty()) {
                preview.error =
                    QStringLiteral(
                        "DNF could not provide a non-destructive stored transaction preview. "
                        "The uninstall can still proceed with one authentication request.");
            }
        }

        QDir(storeDirectory)
            .removeRecursively();

        return preview;
    }


    void showRpmRemovalDetails(
        const RpmRemovalPreview &preview,
        const QStringList &requestedPackages)
    {
        QDialog details(this);
        details.setModal(true);
        details.setWindowTitle(QStringLiteral("DNF Package Details"));
        details.setWindowIcon(totalSweepIcon());

        auto *layout = new QVBoxLayout(&details);
        layout->setContentsMargins(18, 16, 18, 16);
        layout->setSpacing(10);

        auto *intro = new QLabel(
            QStringLiteral(
                "<b>DNF plans to remove %1 RPM packages.</b><br>"
                "Packages marked <b>No longer needed</b> were installed with a dependency reason and "
                "DNF says no user-installed/protected package will still need them after this removal. "
                "That does <i>not</i> prove they originally came with the selected application."
            ).arg(preview.allPackages.size()),
            &details);
        intro->setTextFormat(Qt::RichText);
        intro->setWordWrap(true);
        layout->addWidget(intro);

        auto *tree = new QTreeWidget(&details);
        tree->setColumnCount(2);
        tree->setHeaderLabels({
            QStringLiteral("Package"),
            QStringLiteral("Why it is being removed")
        });
        tree->setRootIsDecorated(true);
        tree->setSelectionMode(QAbstractItemView::NoSelection);
        tree->setFocusPolicy(Qt::StrongFocus);
        tree->setUniformRowHeights(true);
        tree->setAlternatingRowColors(false);
        tree->setTextElideMode(Qt::ElideNone);
        tree->header()->setStretchLastSection(false);
        tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
        tree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

        QSet<QString> dependentSet;
        for (const QString &package : preview.dependentPackages)
            dependentSet.insert(package);

        QSet<QString> unusedSet;
        for (const QString &package : preview.unusedDependencies)
            unusedSet.insert(package);

        QSet<QString> requestedSet;
        for (const QString &package : requestedPackages)
            requestedSet.insert(package.trimmed().toCaseFolded());

        auto addGroup =
            [tree](const QString &label,
                   const QString &reason,
                   const QStringList &packages) {
                if (packages.isEmpty())
                    return;

                auto *group = new QTreeWidgetItem(tree);
                group->setText(0, QStringLiteral("%1 (%2)").arg(label).arg(packages.size()));
                group->setText(1, reason);
                QFont groupFont = group->font(0);
                groupFont.setBold(true);
                group->setFont(0, groupFont);
                group->setFirstColumnSpanned(false);

                for (const QString &package : packages) {
                    auto *child = new QTreeWidgetItem(group);
                    child->setText(0, package);
                    child->setText(1, reason);
                    child->setFlags(Qt::ItemIsEnabled);
                }

                group->setExpanded(true);
            };

        QStringList selected;
        QStringList dependent;
        QStringList unused;
        QStringList other;

        for (const QString &package : preview.allPackages) {
            if (requestedSet.contains(package.toCaseFolded())) {
                selected.append(package);
                continue;
            }
            if (dependentSet.contains(package)) {
                dependent.append(package);
                continue;
            }
            if (unusedSet.contains(package)) {
                unused.append(package);
                continue;
            }
            other.append(package);
        }

        addGroup(
            QStringLiteral("Selected"),
            QStringLiteral("You selected this package for removal"),
            selected);
        addGroup(
            QStringLiteral("Dependent removals"),
            QStringLiteral("Depends on a selected package"),
            dependent);
        addGroup(
            QStringLiteral("No longer needed"),
            QStringLiteral("DNF dependency cleanup"),
            unused);
        addGroup(
            QStringLiteral("Other DNF transaction packages"),
            QStringLiteral("Included by DNF's resolved transaction"),
            other);

        layout->addWidget(tree, 1);

        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &details);
        connect(buttons, &QDialogButtonBox::rejected, &details, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, &details, &QDialog::accept);
        layout->addWidget(buttons);

        const QScreen *screen =
            details.screen() ? details.screen() : QApplication::primaryScreen();
        const QRect available = screen
            ? screen->availableGeometry()
            : QRect(0, 0, 1280, 900);
        details.resize(
            qMax(760, qMin(980, available.width() - 120)),
            qMax(520, qMin(720, available.height() - 120)));

        details.exec();
    }


    ProcessResult runPrivilegedPackageRemovalBatch(
        const QStringList &rpmIds,
        const QStringList &systemFlatpakIds,
        bool removeFlatpakData,
        const QList<QStringList> &manualDeleteGroups = {})
    {
        if (rpmIds.isEmpty() &&
            systemFlatpakIds.isEmpty() &&
            manualDeleteGroups.isEmpty()) {
            return {true, true, 0, {}, {}};
        }

        for (const QString &id : rpmIds) {
            if (!isSafeRpmNameToken(id)) {
                return {false, false, -1, {},
                    QStringLiteral("Unsafe RPM package identifier refused.")};
            }
        }
        for (const QString &id : systemFlatpakIds) {
            if (!isSafeFlatpakIdToken(id)) {
                return {false, false, -1, {},
                    QStringLiteral("Unsafe Flatpak application identifier refused.")};
            }
        }
        for (const QStringList &group : manualDeleteGroups) {
            for (const QString &path : group) {
                if (!isSafePrivilegedPathOperationTarget(path)) {
                    return {false, false, -1, {},
                        QStringLiteral(
                            "A manual/local path became unsafe before administrator removal. Nothing was removed by the privileged batch.")};
                }
            }
        }

        const QString script = QStringLiteral(
            "set -u; "
            "rpm_count=\"$1\"; shift; "
            "rpm_args=(); "
            "i=0; while [ \"$i\" -lt \"$rpm_count\" ]; do "
            "rpm_args+=(\"$1\"); shift; i=$((i+1)); done; "
            "flatpak_count=\"$1\"; shift; "
            "flatpak_args=(); "
            "i=0; while [ \"$i\" -lt \"$flatpak_count\" ]; do "
            "flatpak_args+=(\"$1\"); shift; i=$((i+1)); done; "
            "remove_data=\"$1\"; shift; "
            "if [ \"${#rpm_args[@]}\" -gt 0 ]; then "
            "/usr/bin/dnf remove -y \"${rpm_args[@]}\" || exit $?; fi; "
            "if [ \"${#flatpak_args[@]}\" -gt 0 ]; then "
            "if [ \"$remove_data\" = 1 ]; then "
            "/usr/bin/flatpak uninstall --system --delete-data -y \"${flatpak_args[@]}\" || exit $?; "
            "else /usr/bin/flatpak uninstall --system -y \"${flatpak_args[@]}\" || exit $?; fi; fi; "
            "manual_failed=0; "
            "delete_group_count=\"$1\"; shift; "
            "g=0; while [ \"$g\" -lt \"$delete_group_count\" ]; do "
            "path_count=\"$1\"; shift; "
            "i=0; while [ \"$i\" -lt \"$path_count\" ]; do "
            "path=\"$1\"; shift; "
            "/usr/bin/rm -rf -- \"$path\" || manual_failed=1; "
            "i=$((i+1)); done; "
            "g=$((g+1)); done; "
            "exit \"$manual_failed\"");

        QStringList arguments{
            QStringLiteral("/bin/bash"),
            QStringLiteral("-c"),
            script,
            QStringLiteral("totalsweep-unified-remove"),
            QString::number(rpmIds.size())
        };
        arguments += rpmIds;
        arguments.append(QString::number(systemFlatpakIds.size()));
        arguments += systemFlatpakIds;
        arguments.append(
            removeFlatpakData
                ? QStringLiteral("1")
                : QStringLiteral("0"));
        arguments.append(QString::number(manualDeleteGroups.size()));
        for (const QStringList &group : manualDeleteGroups) {
            arguments.append(QString::number(group.size()));
            arguments += group;
        }

        return runProcessResponsive(
            this,
            QStringLiteral("Uninstalling Applications"),
            QStringLiteral(
                "Removing all protected parts of this uninstall with one authentication request…"),
            QStringLiteral("pkexec"),
            arguments,
            900000);
    }


    ProcessResult runUserFlatpakRemovalBatch(
        const QStringList &userFlatpakIds,
        bool removeFlatpakData)
    {
        if (userFlatpakIds.isEmpty())
            return {true, true, 0, {}, {}};

        QStringList arguments{
            QStringLiteral("uninstall"),
            QStringLiteral("--user")
        };
        if (removeFlatpakData)
            arguments.append(QStringLiteral("--delete-data"));
        arguments.append(QStringLiteral("-y"));
        arguments += userFlatpakIds;

        return runProcessResponsive(
            this,
            QStringLiteral("Uninstalling Applications"),
            QStringLiteral("Removing selected user Flatpak applications…"),
            QStringLiteral("flatpak"),
            arguments,
            900000);
    }


    bool verifyApplicationStillInstalled(
        const ApplicationInfo &app,
        QString &reason) const
    {
        if (app.type == ApplicationType::RPM) {
            if (app.id.trimmed().isEmpty() ||
                !commandSucceeds(
                    QStringLiteral("rpm"),
                    {QStringLiteral("-q"), app.id},
                    10000)) {

                reason =
                    QStringLiteral(
                        "the RPM package is no longer installed");

                return false;
            }

            return true;
        }

        if (app.type == ApplicationType::Flatpak) {
            if (app.id.trimmed().isEmpty()) {
                reason = QStringLiteral(
                    "the Flatpak application ID is missing");
                return false;
            }

            const QString scope =
                resolvedFlatpakScope(app);

            if (scope.isEmpty()) {
                reason = QStringLiteral(
                    "the Flatpak installation scope could not be verified unambiguously");
                return false;
            }

            return true;
        }

        if (isManualLocal(app)) {

            const ManualRemovalPlan plan =
                resolveManualRemovalPlan(
                    app,
                    true);

            if (!plan.resolved()) {
                reason = QStringLiteral(
                    "the removal location could not be verified");
                return false;
            }

            for (const QString &path : plan.paths) {
                QFileInfo info(path);
                if ((!info.exists() && !info.isSymLink()) ||
                    !safeManualRemovalTargetStatic(path)) {
                    reason = QStringLiteral(
                        "one or more verified application paths changed or disappeared");
                    return false;
                }
            }

            return true;
        }

        return true;
    }



    static QStringList toQStringList(
        const std::vector<std::string> &values)
    {
        QStringList result;
        for (const std::string &value : values)
            result.append(QString::fromStdString(value));
        return result;
    }


    bool rpmIdentityFor(
        const ApplicationInfo &app,
        totalsweep_restore::RpmIdentity &identity,
        QString &error) const
    {
        const QStringList lines = runCommand(
            QStringLiteral("rpm"),
            {
                QStringLiteral("-q"),
                QStringLiteral("--qf"),
                QStringLiteral("%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n"),
                app.id
            },
            10000);

        if (lines.isEmpty()) {
            error = QStringLiteral("Could not read the installed RPM identity.");
            return false;
        }

        const QStringList fields = lines.first().split('\t');
        if (fields.size() < 5) {
            error = QStringLiteral("The installed RPM identity was incomplete.");
            return false;
        }

        identity.name = fields.at(0).trimmed().toStdString();
        identity.epoch = fields.at(1).trimmed().toStdString();
        identity.version = fields.at(2).trimmed().toStdString();
        identity.release = fields.at(3).trimmed().toStdString();
        identity.arch = fields.at(4).trimmed().toStdString();
        return !identity.name.empty() && !identity.version.empty();
    }


    QString flatpakRemoteUrl(
        const QString &scope,
        const QString &origin) const
    {
        if (origin.isEmpty())
            return {};

        const QStringList lines = runCommand(
            QStringLiteral("flatpak"),
            {
                QStringLiteral("remotes"),
                scope == QStringLiteral("user")
                    ? QStringLiteral("--user")
                    : QStringLiteral("--system"),
                QStringLiteral("--columns=name,url")
            },
            10000);

        for (const QString &line : lines) {
            const QStringList fields = line.split('\t');
            if (fields.size() >= 2 && fields.at(0).trimmed() == origin)
                return fields.at(1).trimmed();
        }
        return {};
    }


    bool flatpakIdentityFor(
        const ApplicationInfo &app,
        totalsweep_restore::FlatpakIdentity &identity,
        QString &error) const
    {
        const QString scope =
            resolvedFlatpakScope(app);

        if (scope.isEmpty()) {
            error = QStringLiteral(
                "Could not determine the selected Flatpak installation scope unambiguously.");
            return false;
        }

        const QString scopeArg = scope == QStringLiteral("user")
            ? QStringLiteral("--user")
            : QStringLiteral("--system");

        auto oneLine = [&](const QString &option) -> QString {
            const QStringList lines = runCommand(
                QStringLiteral("flatpak"),
                {QStringLiteral("info"), scopeArg, option, app.id},
                10000);
            return lines.isEmpty() ? QString() : lines.first().trimmed();
        };

        const QString ref = oneLine(QStringLiteral("--show-ref"));
        const QString commit = oneLine(QStringLiteral("--show-commit"));
        const QString origin = oneLine(QStringLiteral("--show-origin"));

        if (ref.isEmpty() || commit.isEmpty()) {
            error = QStringLiteral("Could not read the exact Flatpak ref/commit.");
            return false;
        }

        identity.appId = app.id.toStdString();
        identity.ref = ref.toStdString();
        identity.commit = commit.toStdString();
        identity.origin = origin.toStdString();
        identity.scope = scope.toStdString();
        identity.runtimeRepoUrl = flatpakRemoteUrl(scope, origin).toStdString();
        return true;
    }



    QString findSystemCachedRpm(
        const totalsweep_restore::RpmIdentity &identity) const
    {
        const QString expectedFile = QStringLiteral("%1-%2-%3.%4.rpm")
            .arg(
                QString::fromStdString(identity.name),
                QString::fromStdString(identity.version),
                QString::fromStdString(identity.release),
                QString::fromStdString(identity.arch));
        const QString expectedNevra = QString::fromStdString(identity.fullNevra());

        const QStringList roots = {
            QStringLiteral("/var/cache/libdnf5"),
            QStringLiteral("/var/cache/dnf")
        };

        for (const QString &root : roots) {
            if (!QFileInfo(root).isDir())
                continue;

            QDirIterator iterator(
                root,
                {expectedFile},
                QDir::Files,
                QDirIterator::Subdirectories);

            while (iterator.hasNext()) {
                const QString path = iterator.next();
                const QStringList lines = runCommand(
                    QStringLiteral("rpm"),
                    {
                        QStringLiteral("-qp"),
                        QStringLiteral("--qf"),
                        QStringLiteral("%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"),
                        path
                    },
                    10000);
                if (!lines.isEmpty() && lines.first().trimmed() == expectedNevra)
                    return path;
            }
        }
        return {};
    }


    PreparedRestore prepareRpmRestore(
        const ApplicationInfo &app)
    {
        PreparedRestore prepared;
        prepared.metadata[QStringLiteral("kind")] = QStringLiteral("application");
        prepared.metadata[QStringLiteral("appType")] = QStringLiteral("RPM");
        prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("rpm-metadata");

        totalsweep_restore::RpmIdentity identity;
        QString error;
        if (!rpmIdentityFor(app, identity, error)) {
            prepared.warning = error;
            return prepared;
        }

        const QString nevra = QString::fromStdString(identity.fullNevra());
        prepared.metadata[QStringLiteral("exactIdentity")] = nevra;
        prepared.metadata[QStringLiteral("rpmName")] = QString::fromStdString(identity.name);
        prepared.metadata[QStringLiteral("rpmEpoch")] = QString::fromStdString(identity.epoch);
        prepared.metadata[QStringLiteral("rpmVersion")] = QString::fromStdString(identity.version);
        prepared.metadata[QStringLiteral("rpmRelease")] = QString::fromStdString(identity.release);
        prepared.metadata[QStringLiteral("rpmArch")] = QString::fromStdString(identity.arch);

        if (!exactPackageSnapshotsEnabled()) {
            prepared.snapshotDisabled = true;
            prepared.metadata[QStringLiteral("snapshotPolicy")] = QStringLiteral("disabled");
            prepared.warning = QStringLiteral(
                "Exact package payload preservation is disabled in Settings.");
            return prepared;
        }

        prepared.snapshotAttempted = true;
        prepared.metadata[QStringLiteral("snapshotPolicy")] = QStringLiteral("enabled");

        const QString alreadyCached = cachedPayloadForIdentity(
            QStringLiteral("rpm"), nevra);
        if (!alreadyCached.isEmpty()) {
            prepared.exactAvailable = true;
            prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("rpm-local");
            prepared.metadata[QStringLiteral("snapshotPath")] = alreadyCached;
            prepared.metadata[QStringLiteral("snapshotSha256")] = sha256File(alreadyCached);
            return prepared;
        }

        const QString systemCached = findSystemCachedRpm(identity);
        if (!systemCached.isEmpty()) {
            QString cachedPath;
            QString hash;
            if (copyIntoContentCache(
                    systemCached,
                    QStringLiteral("rpm"),
                    QStringLiteral(".rpm"),
                    cachedPath,
                    hash,
                    error)) {
                rememberCachedPayload(QStringLiteral("rpm"), nevra, cachedPath, hash);
                prepared.exactAvailable = true;
                prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("rpm-local");
                prepared.metadata[QStringLiteral("snapshotPath")] = cachedPath;
                prepared.metadata[QStringLiteral("snapshotSha256")] = hash;
                prepared.metadata[QStringLiteral("snapshotSource")] = QStringLiteral("dnf-cache");
                return prepared;
            }
        }

        const QString staging = totalSweepData() + QStringLiteral("/staging/rpm_") +
            sanitize(app.id) + QLatin1Char('_') +
            QString::number(QDateTime::currentMSecsSinceEpoch());
        QDir().mkpath(staging);

        const ProcessResult result = runProcessResponsive(
            this,
            QStringLiteral("Creating Exact Restore Snapshot"),
            QStringLiteral("Preserving the exact RPM for %1…")
                .arg(app.name.isEmpty() ? app.id : app.name),
            QStringLiteral("dnf"),
            toQStringList(totalsweep_restore::rpmDownloadArgs(
                identity, staging.toStdString())),
            300000);

        if (!result.success) {
            QDir(staging).removeRecursively();
            prepared.warning = result.standardError.isEmpty()
                ? QStringLiteral("The exact installed RPM is no longer downloadable from the enabled repositories.")
                : result.standardError;
            return prepared;
        }

        const QStringList rpms = QDir(staging).entryList(
            {QStringLiteral("*.rpm")}, QDir::Files, QDir::Name);
        if (rpms.isEmpty()) {
            QDir(staging).removeRecursively();
            prepared.warning = QStringLiteral("DNF completed, but no exact RPM payload was produced.");
            return prepared;
        }

        const QString downloaded = QDir(staging).filePath(rpms.first());
        QString cachedPath;
        QString hash;
        if (!moveIntoContentCache(
                downloaded,
                QStringLiteral("rpm"),
                QStringLiteral(".rpm"),
                cachedPath,
                hash,
                error)) {
            QDir(staging).removeRecursively();
            prepared.warning = error;
            return prepared;
        }
        QDir(staging).removeRecursively();

        rememberCachedPayload(QStringLiteral("rpm"), nevra, cachedPath, hash);
        prepared.exactAvailable = true;
        prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("rpm-local");
        prepared.metadata[QStringLiteral("snapshotPath")] = cachedPath;
        prepared.metadata[QStringLiteral("snapshotSha256")] = hash;
        return prepared;
    }


    PreparedRestore prepareFlatpakRestore(
        const ApplicationInfo &app)
    {
        PreparedRestore prepared;
        prepared.metadata[QStringLiteral("kind")] = QStringLiteral("application");
        prepared.metadata[QStringLiteral("appType")] = QStringLiteral("Flatpak");
        prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("flatpak-metadata");

        totalsweep_restore::FlatpakIdentity identity;
        QString error;
        if (!flatpakIdentityFor(app, identity, error)) {
            prepared.warning = error;
            return prepared;
        }

        const QString commit = QString::fromStdString(identity.commit);
        prepared.metadata[QStringLiteral("exactIdentity")] = commit;
        prepared.metadata[QStringLiteral("flatpakRef")] = QString::fromStdString(identity.ref);
        prepared.metadata[QStringLiteral("flatpakCommit")] = commit;
        prepared.metadata[QStringLiteral("flatpakOrigin")] = QString::fromStdString(identity.origin);
        prepared.metadata[QStringLiteral("flatpakScope")] = QString::fromStdString(identity.scope);
        prepared.metadata[QStringLiteral("runtimeRepoUrl")] = QString::fromStdString(identity.runtimeRepoUrl);

        if (!exactPackageSnapshotsEnabled()) {
            prepared.snapshotDisabled = true;
            prepared.metadata[QStringLiteral("snapshotPolicy")] = QStringLiteral("disabled");
            prepared.warning = QStringLiteral(
                "Exact package payload preservation is disabled in Settings.");
            return prepared;
        }

        prepared.snapshotAttempted = true;
        prepared.metadata[QStringLiteral("snapshotPolicy")] = QStringLiteral("enabled");

        const QString alreadyCached = cachedPayloadForIdentity(
            QStringLiteral("flatpak"), commit);
        if (!alreadyCached.isEmpty()) {
            prepared.exactAvailable = true;
            prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("flatpak-bundle");
            prepared.metadata[QStringLiteral("snapshotPath")] = alreadyCached;
            prepared.metadata[QStringLiteral("snapshotSha256")] = sha256File(alreadyCached);
            return prepared;
        }

        const QString stagingDir = totalSweepData() + QStringLiteral("/staging/flatpak_") +
            sanitize(app.id) + QLatin1Char('_') +
            QString::number(QDateTime::currentMSecsSinceEpoch());
        QDir().mkpath(stagingDir);
        const QString bundle = QDir(stagingDir).filePath(QStringLiteral("snapshot.flatpak"));
        const QString repo = identity.scope == "user"
            ? QDir::homePath() + QStringLiteral("/.local/share/flatpak/repo")
            : QStringLiteral("/var/lib/flatpak/repo");

        const ProcessResult result = runProcessResponsive(
            this,
            QStringLiteral("Creating Exact Restore Snapshot"),
            QStringLiteral("Bundling the exact Flatpak commit for %1…")
                .arg(app.name.isEmpty() ? app.id : app.name),
            QStringLiteral("flatpak"),
            toQStringList(totalsweep_restore::flatpakBundleArgs(
                identity, repo.toStdString(), bundle.toStdString())),
            300000);

        if (!result.success || !QFileInfo::exists(bundle)) {
            QDir(stagingDir).removeRecursively();
            prepared.warning = result.standardError.isEmpty()
                ? QStringLiteral("The exact Flatpak bundle could not be created from the local OSTree repository.")
                : result.standardError;
            return prepared;
        }

        QString cachedPath;
        QString hash;
        if (!moveIntoContentCache(
                bundle,
                QStringLiteral("flatpak"),
                QStringLiteral(".flatpak"),
                cachedPath,
                hash,
                error)) {
            QDir(stagingDir).removeRecursively();
            prepared.warning = error;
            return prepared;
        }
        QDir(stagingDir).removeRecursively();

        rememberCachedPayload(QStringLiteral("flatpak"), commit, cachedPath, hash);
        prepared.exactAvailable = true;
        prepared.metadata[QStringLiteral("restoreMode")] = QStringLiteral("flatpak-bundle");
        prepared.metadata[QStringLiteral("snapshotPath")] = cachedPath;
        prepared.metadata[QStringLiteral("snapshotSha256")] = hash;
        return prepared;
    }


    PreparedRestore preparePackageRestore(
        const ApplicationInfo &app)
    {
        if (app.type == ApplicationType::RPM)
            return prepareRpmRestore(app);
        if (app.type == ApplicationType::Flatpak)
            return prepareFlatpakRestore(app);
        return {};
    }


    QString createQuarantineSessionPath(
        const QString &application)
    {
        const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss_zzz"));
        const QString session = totalSweepData() + QStringLiteral("/quarantine/") +
            stamp + QLatin1Char('_') + sanitize(application);
        QDir().mkpath(session);
        return session;
    }


    void appendHistoryObject(const QJsonObject &entry)
    {
        const QString path = totalSweepData() + QStringLiteral("/history.json");
        QJsonArray history = readJsonArray(path);
        history.append(entry);
        writeJsonArrayAtomic(path, history);
    }


    bool commitPackageRestoreRecord(
        const ApplicationInfo &app,
        PreparedRestore prepared)
    {
        const QString displayName = app.name.isEmpty() ? app.id : app.name;
        const QString session = createQuarantineSessionPath(displayName);
        const QString created = QDateTime::currentDateTime().toString(Qt::ISODate);

        prepared.metadata[QStringLiteral("schema")] = 2;
        prepared.metadata[QStringLiteral("kind")] = QStringLiteral("application");
        prepared.metadata[QStringLiteral("application")] = displayName;
        prepared.metadata[QStringLiteral("appId")] = app.id;
        prepared.metadata[QStringLiteral("version")] = app.version;
        prepared.metadata[QStringLiteral("packageManager")] = app.packageManager;
        prepared.metadata[QStringLiteral("created")] = created;
        prepared.metadata[QStringLiteral("snapshotStatus")] = prepared.exactAvailable
            ? QStringLiteral("available")
            : (prepared.snapshotDisabled
                ? QStringLiteral("disabled")
                : QStringLiteral("metadata-only"));
        prepared.metadata[QStringLiteral("snapshotWarning")] = prepared.warning;
        prepared.metadata[QStringLiteral("restored")] = false;
        prepared.metadata[QStringLiteral("items")] = QJsonArray();
        if (!writeJsonObjectAtomic(
                session + QStringLiteral("/metadata.json"),
                prepared.metadata)) {
            QDir(session).removeRecursively();
            return false;
        }

        QJsonObject history;
        history[QStringLiteral("id")] = QFileInfo(session).fileName().section('_', 0, 2);
        history[QStringLiteral("kind")] = QStringLiteral("application");
        history[QStringLiteral("application")] = displayName;
        history[QStringLiteral("session")] = session;
        history[QStringLiteral("items")] = 1;
        history[QStringLiteral("created")] = created;
        history[QStringLiteral("appType")] = prepared.metadata[QStringLiteral("appType")].toString();
        history[QStringLiteral("version")] = app.version;
        history[QStringLiteral("restoreMode")] = prepared.metadata[QStringLiteral("restoreMode")].toString();
        appendHistoryObject(history);
        return true;
    }


    QString futureRemovalPolicySummary() const
    {
        if (!restorePreferences.restoreProtection) {
            return QStringLiteral(
                "Restore protection is off — this removal may be permanent.");
        }

        return QStringLiteral(
            "Application restore: %1  •  Exact package snapshot: %2  •  Leftovers: %3")
            .arg(
                applicationRestoreTrackingEnabled()
                    ? QStringLiteral("On")
                    : QStringLiteral("Off"),
                exactPackageSnapshotsEnabled()
                    ? QStringLiteral("On")
                    : QStringLiteral("Off"),
                leftoverQuarantineEnabled()
                    ? QStringLiteral("Quarantine")
                    : QStringLiteral("Permanent delete"));
    }


    bool commitNonRestorableApplicationRecord(
        const ApplicationInfo &app,
        const QString &reason)
    {
        if (!applicationRestoreTrackingEnabled() ||
            !restorePreferences.keepMetadataOnlyRecords) {
            return true;
        }

        const QString displayName = app.name.isEmpty() ? app.id : app.name;
        const QString session = createQuarantineSessionPath(displayName);
        const QString created = QDateTime::currentDateTime().toString(Qt::ISODate);

        QJsonObject metadata;
        metadata[QStringLiteral("schema")] = 2;
        metadata[QStringLiteral("kind")] = QStringLiteral("application");
        metadata[QStringLiteral("application")] = displayName;
        metadata[QStringLiteral("appId")] = app.id;
        metadata[QStringLiteral("appType")] = restoreTypeLabel(app);
        metadata[QStringLiteral("version")] = app.version;
        metadata[QStringLiteral("packageManager")] = app.packageManager;
        metadata[QStringLiteral("restoreMode")] = QStringLiteral("none");
        metadata[QStringLiteral("snapshotStatus")] = QStringLiteral("disabled");
        metadata[QStringLiteral("snapshotWarning")] = reason;
        metadata[QStringLiteral("created")] = created;
        metadata[QStringLiteral("restored")] = false;
        metadata[QStringLiteral("items")] = QJsonArray();

        if (!writeJsonObjectAtomic(
                session + QStringLiteral("/metadata.json"),
                metadata)) {
            QDir(session).removeRecursively();
            return false;
        }

        QJsonObject history;
        history[QStringLiteral("id")] = QFileInfo(session).fileName().section('_', 0, 2);
        history[QStringLiteral("kind")] = QStringLiteral("application");
        history[QStringLiteral("application")] = displayName;
        history[QStringLiteral("session")] = session;
        history[QStringLiteral("items")] = 0;
        history[QStringLiteral("created")] = created;
        history[QStringLiteral("appType")] = restoreTypeLabel(app);
        history[QStringLiteral("version")] = app.version;
        history[QStringLiteral("restoreMode")] = QStringLiteral("none");
        appendHistoryObject(history);
        return true;
    }


    bool isProtectedPermanentDeleteTarget(
        const QString &path) const
    {
        const QString raw = path.trimmed();
        if (raw.isEmpty())
            return true;

        QString cleaned = QDir::cleanPath(raw);
        if (!QDir::isAbsolutePath(cleaned))
            return true;

        if (cleaned.size() > 1 && cleaned.endsWith(QLatin1Char('/')))
            cleaned.chop(1);

        if (cleaned.isEmpty() ||
            isTotalSweepManagedPath(cleaned)) {
            return true;
        }

        const QString trustedRoot =
            trustedDestructiveRootForPath(cleaned);

        if (trustedRoot.isEmpty())
            return true;

        return hasSymlinkedParentBelowRoot(
            cleaned,
            trustedRoot);
    }


    bool removeManualApplicationPermanently(
        const ApplicationInfo &app,
        QString &error)
    {
        if (!app.removable) {
            error = QStringLiteral(
                "This manual/local application is not marked as removable.");
            return false;
        }

        const ManualRemovalPlan plan =
            resolveManualRemovalPlan(
                app,
                true);

        if (!plan.resolved()) {
            error = QStringLiteral(
                "TotalSweep could not verify an unambiguous unmanaged removal location for this application.");
            return false;
        }

        const QStringList paths =
            plan.paths;

        int removedCount = 0;
        const QStringList failures =
            removePathsPermanentlyBatch(paths, removedCount);
        Q_UNUSED(removedCount);

        if (!failures.isEmpty()) {
            error = QStringLiteral(
                "Permanent removal was incomplete:\n%1")
                .arg(failures.join(QLatin1Char('\n')));
            return false;
        }

        return true;
    }


    QStringList removePathsPermanentlyBatch(
        const QStringList &inputPaths,
        int &successful)
    {
        successful = 0;
        QStringList failures;
        QStringList unprivileged;
        QStringList privileged;
        QSet<QString> seen;

        for (const QString &path : inputPaths) {
            const QString raw = path.trimmed();
            const QString cleaned = QDir::cleanPath(raw);
            if (raw.isEmpty() || seen.contains(cleaned))
                continue;
            seen.insert(cleaned);

            if (isProtectedPermanentDeleteTarget(cleaned) ||
                isTotalSweepManagedPath(cleaned)) {
                failures.append(QStringLiteral("%1 — protected TotalSweep/system path refused").arg(cleaned));
                continue;
            }

            QFileInfo info(cleaned);
            if (!info.exists() && !info.isSymLink()) {
                ++successful;
                continue;
            }

            if (QFileInfo(info.absolutePath()).isWritable()) {
                unprivileged.append(cleaned);
            }
            else if (isSafePrivilegedPathOperationTarget(cleaned)) {
                privileged.append(cleaned);
            }
            else {
                failures.append(
                    QStringLiteral(
                        "%1 — privileged removal refused because a parent path is user-writable or otherwise unsafe")
                        .arg(cleaned));
            }
        }

        bool cancelled = false;
        if (!unprivileged.isEmpty()) {
            QStringList args{QStringLiteral("-rf"), QStringLiteral("--")};
            args += unprivileged;
            const ProcessResult result = runProcessResponsive(
                this,
                QStringLiteral("Deleting Selected Leftovers"),
                QStringLiteral("Permanently deleting %1 selected %2…")
                    .arg(unprivileged.size())
                    .arg(wordForCount(
                        unprivileged.size(),
                        QStringLiteral("item"),
                        QStringLiteral("items"))),
                QStringLiteral("rm"),
                args,
                300000);
            cancelled = result.standardError == QStringLiteral("Operation cancelled.");

            for (const QString &path : unprivileged) {
                QFileInfo info(path);
                if (!info.exists() && !info.isSymLink()) {
                    ++successful;
                }
                else {
                    failures.append(
                        QStringLiteral(
                            "%1 — unprivileged deletion failed; TotalSweep will not promote a user-owned path to administrator deletion")
                            .arg(path));
                }
            }
        }

        if (!cancelled && !privileged.isEmpty()) {
            privileged.removeDuplicates();
            QStringList args{QStringLiteral("/usr/bin/rm"), QStringLiteral("-rf"), QStringLiteral("--")};
            args += privileged;
            const ProcessResult result = runProcessResponsive(
                this,
                QStringLiteral("Deleting Selected Leftovers"),
                QStringLiteral("Removing %1 protected/permission-restricted selected %2 with one authentication request…")
                    .arg(privileged.size())
                    .arg(wordForCount(
                        privileged.size(),
                        QStringLiteral("item"),
                        QStringLiteral("items"))),
                QStringLiteral("pkexec"),
                args,
                300000);
            cancelled = result.standardError == QStringLiteral("Operation cancelled.");

            for (const QString &path : privileged) {
                QFileInfo info(path);
                if (!info.exists() && !info.isSymLink())
                    ++successful;
                else
                    failures.append(QStringLiteral("%1 — %2")
                        .arg(path,
                            result.standardError.trimmed().isEmpty()
                                ? QStringLiteral("could not be deleted")
                                : result.standardError.trimmed()));
            }
        }
        else if (cancelled) {
            for (const QString &path : privileged)
                failures.append(QStringLiteral("%1 — operation cancelled").arg(path));
        }

        return failures;
    }


    static bool leftoverTreeLeafHasPath(
        const QTreeWidgetItem *item)
    {
        return item &&
            item->childCount() == 0 &&
            item->data(0, Qt::UserRole + 1).isValid() &&
            !item->data(0, Qt::UserRole).toString().trimmed().isEmpty();
    }


    static bool pathIsSameOrChildOf(
        const QString &path,
        const QString &root)
    {
        const QString cleanedPath = QDir::cleanPath(path);
        const QString cleanedRoot = QDir::cleanPath(root);

        if (cleanedPath == cleanedRoot)
            return true;

        const QString prefix = cleanedRoot.endsWith(QLatin1Char('/'))
            ? cleanedRoot
            : cleanedRoot + QLatin1Char('/');

        return cleanedPath.startsWith(prefix);
    }


    int leftoverLeafCount(
        QTreeWidgetItem *root) const
    {
        if (!root)
            return 0;

        if (leftoverTreeLeafHasPath(root))
            return 1;

        int count = 0;
        for (int i = 0; i < root->childCount(); ++i)
            count += leftoverLeafCount(root->child(i));

        return count;
    }


    void refreshLeftoverResultsAfterRemoval(
        const QStringList &requestedPaths)
    {
        if (!results || requestedPaths.isEmpty())
            return;

        QStringList removedRoots;
        for (const QString &path : requestedPaths) {
            const QString cleaned = QDir::cleanPath(path.trimmed());
            if (cleaned.isEmpty())
                continue;

            const QFileInfo info(cleaned);
            if (!info.exists() && !info.isSymLink())
                removedRoots.append(cleaned);
        }
        removedRoots.removeDuplicates();

        if (removedRoots.isEmpty())
            return;

        bool groupedPostUninstallResults = false;
        int skippedPostUninstallGroups = 0;

        for (int i = 0; i < results->topLevelItemCount(); ++i) {
            QTreeWidgetItem *top = results->topLevelItem(i);
            if (!top || (top->flags() & Qt::ItemIsUserCheckable))
                continue;

            groupedPostUninstallResults = true;
            if (top->text(0).contains(
                    QStringLiteral("Scan skipped"),
                    Qt::CaseInsensitive)) {
                ++skippedPostUninstallGroups;
            }
        }

        results->setUpdatesEnabled(false);
        setHoveredLeftoverItem(nullptr);
        pressedLeftoverItem = nullptr;

        QList<QTreeWidgetItem *> staleLeaves;
        QTreeWidgetItemIterator iterator(results);
        while (*iterator) {
            QTreeWidgetItem *item = *iterator;
            if (leftoverTreeLeafHasPath(item)) {
                const QString rowPath = QDir::cleanPath(
                    item->data(0, Qt::UserRole).toString().trimmed());

                bool removed = false;
                for (const QString &root : removedRoots) {
                    if (pathIsSameOrChildOf(rowPath, root)) {
                        removed = true;
                        break;
                    }
                }

                if (removed)
                    staleLeaves.append(item);
            }
            ++iterator;
        }

        for (QTreeWidgetItem *item : staleLeaves)
            delete item;

        bool prunedContainer = true;
        const QRegularExpression completedAppPattern(
            QStringLiteral("\\s{2}\\(\\d+\\s+leftovers?\\)$"),
            QRegularExpression::CaseInsensitiveOption);

        while (prunedContainer) {
            prunedContainer = false;
            QList<QTreeWidgetItem *> emptyContainers;
            QTreeWidgetItemIterator containerIterator(results);
            while (*containerIterator) {
                QTreeWidgetItem *item = *containerIterator;
                const bool pathLeaf = leftoverTreeLeafHasPath(item);
                const bool checkableContainer =
                    !pathLeaf &&
                    item->childCount() == 0 &&
                    (item->flags() & Qt::ItemIsUserCheckable);
                const QString label = item->text(0);
                const bool emptyCompletedApp =
                    !pathLeaf &&
                    item->childCount() == 0 &&
                    completedAppPattern.match(label).hasMatch();

                if (checkableContainer || emptyCompletedApp)
                    emptyContainers.append(item);

                ++containerIterator;
            }

            for (QTreeWidgetItem *item : emptyContainers) {
                delete item;
                prunedContainer = true;
            }
        }

        const QRegularExpression categoryCountPattern(
            QStringLiteral("\\s{2}\\(\\d+\\)$"));

        for (int i = 0; i < results->topLevelItemCount(); ++i) {
            QTreeWidgetItem *top = results->topLevelItem(i);
            if (!top)
                continue;

            QList<QTreeWidgetItem *> stack{top};
            while (!stack.isEmpty()) {
                QTreeWidgetItem *item = stack.takeLast();
                for (int childIndex = 0; childIndex < item->childCount(); ++childIndex)
                    stack.append(item->child(childIndex));

                if (item->childCount() > 0 &&
                    (item->flags() & Qt::ItemIsUserCheckable)) {
                    QString base = item->text(0);
                    base.remove(categoryCountPattern);
                    item->setText(
                        0,
                        QStringLiteral("%1  (%2)")
                            .arg(base)
                            .arg(item->childCount()));
                }
            }

            if (!(top->flags() & Qt::ItemIsUserCheckable) &&
                top->childCount() > 0) {
                const int count = leftoverLeafCount(top);
                if (count > 0) {
                    QString base = top->text(0);
                    base.remove(completedAppPattern);
                    top->setText(
                        0,
                        QStringLiteral("%1  (%2 %3)")
                            .arg(base)
                            .arg(count)
                            .arg(wordForCount(
                                count,
                                QStringLiteral("leftover"),
                                QStringLiteral("leftovers"))));
                }
            }
        }

        int remaining = 0;
        for (int i = 0; i < results->topLevelItemCount(); ++i)
            remaining += leftoverLeafCount(results->topLevelItem(i));

        if (remaining == 0 &&
            groupedPostUninstallResults &&
            skippedPostUninstallGroups == 0) {

            results->clear();
            results->setEmptyMessage(
                QStringLiteral(
                    "Nothing else was found — no additional leftovers remain for the removed applications."));
        }
        else if (results->topLevelItemCount() == 0) {
            results->setEmptyMessage(
                QStringLiteral(
                    "Nothing else was found — no additional leftovers remain in the current results."));
        }
        else {
            results->setEmptyMessage(QString());
        }

        results->setUpdatesEnabled(true);
        results->viewport()->update();

        if (resultStatus) {
            if (remaining == 0 &&
                groupedPostUninstallResults &&
                skippedPostUninstallGroups > 0) {

                resultStatus->setText(
                    QStringLiteral(
                        "Cleanup complete. No found leftovers remain; %1 %2 skipped because the available identity was too broad to search safely.")
                        .arg(skippedPostUninstallGroups)
                        .arg(wordForCount(
                            skippedPostUninstallGroups,
                            QStringLiteral("scan was"),
                            QStringLiteral("scans were"))));
            }
            else {
                resultStatus->setText(
                    remaining == 0
                        ? QStringLiteral(
                            "Cleanup complete. Nothing else remains in the current Leftovers results.")
                        : QStringLiteral(
                            "Cleanup complete. %1 %2 remain in the current Leftovers results.")
                            .arg(remaining)
                            .arg(wordForCount(
                                remaining,
                                QStringLiteral("leftover"),
                                QStringLiteral("leftovers"))));
            }
        }

        updateLeftoverContextActions();
        updateLeftoverActionModeUi();
        updateQuarantineButton();
    }


    void deleteLeftoverPathsPermanently(
        const QStringList &paths)
    {
        if (paths.isEmpty())
            return;

        if (totalSweepWarning(
                this,
                QStringLiteral("Delete Leftovers Permanently"),
                QStringLiteral(
                    "Permanent leftover deletion is enabled in Settings.\n\n"
                    "%1 selected %2 will be deleted without being added to TotalSweep Quarantine. "
                    "TotalSweep will not be able to restore %3 afterward.\n\n"
                    "Delete permanently?")
                    .arg(paths.size())
                    .arg(wordForCount(
                        paths.size(),
                        QStringLiteral("item"),
                        QStringLiteral("items")))
                    .arg(paths.size() == 1
                        ? QStringLiteral("it")
                        : QStringLiteral("them")),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No)
            != QMessageBox::Yes) {
            return;
        }

        int successful = 0;
        const QStringList failures =
            removePathsPermanentlyBatch(paths, successful);

        QString message = QStringLiteral(
            "%1 %2 deleted permanently.")
            .arg(successful)
            .arg(wordForCount(
                successful,
                QStringLiteral("item"),
                QStringLiteral("items")));
        if (!failures.isEmpty()) {
            message += QStringLiteral(
                "\n\n%1 %2 %3 left untouched:\n%4")
                .arg(failures.size())
                .arg(wordForCount(
                    failures.size(),
                    QStringLiteral("item"),
                    QStringLiteral("items")))
                .arg(failures.size() == 1
                    ? QStringLiteral("was")
                    : QStringLiteral("were"))
                .arg(failures.join(QLatin1Char('\n')));
        }

        totalSweepInformation(
            this,
            QStringLiteral("Permanent Cleanup Complete"),
            message);

        refreshLeftoverResultsAfterRemoval(paths);
    }


    QStringList rollbackQuarantineMoves(
        const QStringList &originals,
        const QStringList &quarantined)
    {
        QStringList failures;
        QStringList privilegedPairs;
        const int count =
            std::min(
                originals.size(),
                quarantined.size());

        for (int i = count - 1;
             i >= 0;
             --i) {
            const QString source =
                quarantined.at(i);
            const QString destination =
                originals.at(i);

            const QFileInfo sourceInfo(
                source);

            if (!sourceInfo.exists() &&
                !sourceInfo.isSymLink()) {
                if (QFileInfo::exists(
                        destination)) {
                    continue;
                }

                failures.append(
                    QStringLiteral(
                        "%1 — rollback source is missing")
                        .arg(
                            destination));
                continue;
            }

            QDir().mkpath(
                QFileInfo(destination)
                    .absolutePath());

            if (QFile::rename(
                    source,
                    destination)) {
                continue;
            }

            privilegedPairs
                << source
                << destination;
        }

        if (!privilegedPairs.isEmpty()) {
            const QString script =
                QStringLiteral(
                    "while [ \"$#\" -ge 2 ]; do "
                    "src=\"$1\"; dst=\"$2\"; shift 2; "
                    "parent=${dst%/*}; [ -n \"$parent\" ] || parent=/; "
                    "mkdir -p -- \"$parent\" || exit $?; "
                    "mv -- \"$src\" \"$dst\" || exit $?; "
                    "done");

            QStringList arguments{
                QStringLiteral(
                    "-c"),
                script,
                QStringLiteral(
                    "totalsweep-rollback")
            };
            arguments +=
                privilegedPairs;

            const ProcessResult result =
                runProcessResponsive(
                    this,
                    QStringLiteral(
                        "Rolling Back Quarantine"),
                    QStringLiteral(
                        "Returning Quarantine files to their original locations…"),
                    QStringLiteral(
                        "/bin/sh"),
                    arguments,
                    300000);

            for (int i = 0;
                 i + 1 <
                    privilegedPairs.size();
                 i += 2) {
                const QString source =
                    privilegedPairs.at(i);
                const QString destination =
                    privilegedPairs.at(i + 1);

                if (!QFileInfo::exists(
                        source) &&
                    QFileInfo::exists(
                        destination)) {
                    continue;
                }

                failures.append(
                    QStringLiteral(
                        "%1 — %2")
                        .arg(
                            destination,
                            result.standardError
                                    .trimmed()
                                    .isEmpty()
                                ? QStringLiteral(
                                      "rollback failed")
                                : result.standardError
                                      .trimmed()));
            }
        }

        return failures;
    }


    bool quarantineManualApplication(
        const ApplicationInfo &app,
        QString &error)
    {
        if (!app.removable) {
            error = QStringLiteral("This manual/local application is not marked as removable.");
            return false;
        }

        const ManualRemovalPlan plan =
            resolveManualRemovalPlan(
                app,
                true);

        if (!plan.resolved()) {
            error = QStringLiteral(
                "TotalSweep could not verify an unambiguous unmanaged removal location for this application.");
            return false;
        }

        const QString displayName = app.name.isEmpty() ? app.id : app.name;
        const QString session = createQuarantineSessionPath(displayName);
        const QStringList originals =
            plan.paths;

        QJsonArray items;
        QStringList movedSources;
        QStringList movedDestinations;
        QList<QuarantineMoveCandidate> allCandidates;
        QList<QuarantineMoveCandidate> unprivilegedPending;
        int number = 0;

        for (const QString &source : originals) {
            QuarantineMoveCandidate candidate;
            candidate.source = source;
            candidate.destination =
                session + QStringLiteral("/item_%1")
                    .arg(++number, 4, 10, QChar('0'));
            candidate.size = QFileInfo(source).size();
            allCandidates.append(candidate);

            const QFileInfo sourceInfo(source);
            const QFileInfo sourceParent(sourceInfo.absolutePath());
            const QFileInfo destinationParent(
                QFileInfo(candidate.destination).absolutePath());

            if (!sourceParent.isWritable() ||
                !destinationParent.isWritable()) {
                QDir(session).removeRecursively();
                error = QStringLiteral(
                    "This manual/local application requires administrator privileges to move into Quarantine. "
                    "For security, TotalSweep does not use user-profile Quarantine as a source for privileged file moves. "
                    "Nothing was removed.");
                return false;
            }

            unprivilegedPending.append(candidate);
        }

        if (!unprivilegedPending.isEmpty()) {
            runBatchMovePairs(
                unprivilegedPending,
                QStringLiteral("Updating Quarantine"),
                QStringLiteral("Moving application files into Quarantine…"));

        }

        QStringList moveFailures;
        for (const QuarantineMoveCandidate &candidate :
             std::as_const(allCandidates)) {
            const QFileInfo sourceInfo(candidate.source);
            const QFileInfo destinationInfo(candidate.destination);
            const bool sourceStillExists =
                sourceInfo.exists() || sourceInfo.isSymLink();
            const bool destinationExists =
                destinationInfo.exists() || destinationInfo.isSymLink();

            if (!sourceStillExists && destinationExists) {
                movedSources.append(candidate.source);
                movedDestinations.append(candidate.destination);

                QJsonObject item;
                item[QStringLiteral("original")] = candidate.source;
                item[QStringLiteral("quarantine")] = candidate.destination;
                item[QStringLiteral("size")] =
                    static_cast<double>(candidate.size);
                items.append(item);
            }
            else {
                moveFailures.append(candidate.source);
            }
        }

        if (!moveFailures.isEmpty()) {
            const QStringList rollbackFailures =
                rollbackQuarantineMoves(
                    movedSources,
                    movedDestinations);

            if (rollbackFailures.isEmpty()) {
                QDir(session).removeRecursively();
                error = QStringLiteral(
                    "TotalSweep could not move every verified application path into Quarantine, so the removal was rolled back.\n\n%1")
                    .arg(moveFailures.join(QLatin1Char('\n')));
            }
            else {
                error = QStringLiteral(
                    "TotalSweep could not move every verified application path and rollback was incomplete. "
                    "The remaining Quarantine files are preserved at:\n%1\n\n%2")
                    .arg(
                        session,
                        rollbackFailures.join(QLatin1Char('\n')));
            }
            return false;
        }

        const QString created = QDateTime::currentDateTime().toString(Qt::ISODate);
        QJsonObject metadata;
        metadata[QStringLiteral("schema")] = 2;
        metadata[QStringLiteral("kind")] = QStringLiteral("application");
        metadata[QStringLiteral("application")] = displayName;
        metadata[QStringLiteral("appId")] = app.id;
        metadata[QStringLiteral("appType")] = restoreTypeLabel(app);
        metadata[QStringLiteral("version")] = app.version;
        metadata[QStringLiteral("packageManager")] = app.packageManager;
        metadata[QStringLiteral("restoreMode")] = QStringLiteral("files");
        metadata[QStringLiteral("snapshotStatus")] = QStringLiteral("available");
        metadata[QStringLiteral("created")] = created;
        metadata[QStringLiteral("restored")] = false;
        metadata[QStringLiteral("items")] = items;
        if (!writeJsonObjectAtomic(session + QStringLiteral("/metadata.json"), metadata)) {
            const QStringList rollbackFailures =
                rollbackQuarantineMoves(
                    movedSources,
                    movedDestinations);

            if (rollbackFailures.isEmpty()) {
                QDir(session).removeRecursively();
                error = QStringLiteral(
                    "Could not write quarantine metadata, so the removal was rolled back.");
            }
            else {
                error = QStringLiteral(
                    "Could not write quarantine metadata and rollback was incomplete. "
                    "TotalSweep did not delete the remaining quarantined files. They are preserved at:\n%1\n\n%2")
                    .arg(
                        session,
                        rollbackFailures.join(QLatin1Char('\n')));
            }
            return false;
        }

        QJsonObject history;
        history[QStringLiteral("id")] = QFileInfo(session).fileName().section('_', 0, 2);
        history[QStringLiteral("kind")] = QStringLiteral("application");
        history[QStringLiteral("application")] = displayName;
        history[QStringLiteral("session")] = session;
        history[QStringLiteral("items")] = static_cast<int>(items.size());
        history[QStringLiteral("created")] = created;
        history[QStringLiteral("appType")] = restoreTypeLabel(app);
        history[QStringLiteral("version")] = app.version;
        history[QStringLiteral("restoreMode")] = QStringLiteral("files");
        appendHistoryObject(history);
        return true;
    }



    void uninstallSelectedApplications()
    {
        QList<ApplicationInfo> selected;

        if (applicationModel) {
            const QList<int> indexes =
                applicationModel->checkedSourceIndexes();

            for (int index : indexes) {
                if (index >= 0 && index < allApplications.size())
                    selected.append(allApplications.at(index));
            }
        }

        if (selected.isEmpty())
            return;

        if (!applicationDataFresh || applicationRefreshRunning) {
            totalSweepInformation(
                this,
                QStringLiteral("Refreshing Applications"),
                QStringLiteral(
                    "TotalSweep is still verifying the current installed-application state. "
                    "Removal will be available as soon as the refresh finishes."));
            return;
        }

        QStringList changedApplications;
        QApplication::setOverrideCursor(Qt::WaitCursor);

        for (const ApplicationInfo &app : selected) {
            QString reason;
            if (!verifyApplicationStillInstalled(app, reason)) {
                const QString displayName =
                    app.name.isEmpty() ? app.id : app.name;
                changedApplications.append(
                    QStringLiteral("%1 — %2")
                        .arg(displayName, reason));
            }
        }

        QApplication::restoreOverrideCursor();

        if (!changedApplications.isEmpty()) {
            totalSweepWarning(
                this,
                QStringLiteral("Application Recheck"),
                QString(
                    "TotalSweep rechecked the selected %1 immediately before removal. "
                    "One or more entries no longer matched a verified removal plan, so nothing was removed.\n\n%2\n\n"
                    "The application list will be refreshed now.")
                    .arg(wordForCount(
                        selected.size(),
                        QStringLiteral("application"),
                        QStringLiteral("applications")))
                    .arg(changedApplications.join(QLatin1Char('\n'))));
            refreshApplications();
            return;
        }

        const int selectedCount = selected.size();
        const bool trackPackageRemoval =
            applicationRestoreTrackingEnabled();

        QStringList rpmIds;
        QStringList userFlatpakIds;
        QStringList systemFlatpakIds;
        QVector<QString> flatpakScopes(selectedCount);
        QVector<PreparedRestore> preparedRestores(selectedCount);
        QVector<ManualRemovalPlan> manualRemovalPlans(selectedCount);
        QVector<bool> manualRemovalPlanReady(selectedCount, false);
        QVector<bool> manualRemovalNeedsPrivilege(selectedCount, false);
        QStringList snapshotWarningApps;
        bool manualPrivilegeRequired = false;

        int advancedSystemCount = 0;

        for (int i = 0; i < selectedCount; ++i) {
            const ApplicationInfo &app = selected.at(i);
            const QString displayName =
                app.name.isEmpty() ? app.id : app.name;

            if (app.systemComponent && !app.protectedComponent)
                ++advancedSystemCount;

            if (app.type == ApplicationType::RPM) {
                rpmIds.append(app.id);
            }
            else if (app.type == ApplicationType::Flatpak) {
                const QString scope = resolvedFlatpakScope(app);
                flatpakScopes[i] = scope;
                if (scope == QStringLiteral("user"))
                    userFlatpakIds.append(app.id);
                else if (scope == QStringLiteral("system"))
                    systemFlatpakIds.append(app.id);
                else {
                    totalSweepWarning(
                        this,
                        QStringLiteral("Application Recheck"),
                        QStringLiteral(
                            "TotalSweep could not determine which Flatpak installation should be removed for %1. "
                            "Nothing was removed.")
                            .arg(displayName));
                    refreshApplications();
                    return;
                }
            }
            else if (isManualLocal(app)) {
                const ManualRemovalPlan plan =
                    resolveManualRemovalPlan(
                        app,
                        true);

                if (!plan.resolved()) {
                    totalSweepWarning(
                        this,
                        QStringLiteral("Application Recheck"),
                        QStringLiteral(
                            "TotalSweep could not verify a safe removal location for %1. "
                            "Nothing was removed.")
                            .arg(displayName));
                    refreshApplications();
                    return;
                }

                manualRemovalPlans[i] = plan;
                manualRemovalPlanReady[i] = true;

                bool hasWritableParent = false;
                bool hasRestrictedParent = false;

                for (const QString &path :
                     plan.paths) {
                    const QFileInfo info(path);
                    const QFileInfo parent(
                        info.absolutePath());

                    if (parent.isWritable()) {
                        hasWritableParent = true;
                    }
                    else {
                        hasRestrictedParent = true;

                        if (!isSafePrivilegedPathOperationTarget(path)) {
                            totalSweepWarning(
                                this,
                                QStringLiteral("Application Recheck"),
                                QStringLiteral(
                                    "TotalSweep refused a permission-restricted manual/local path for %1 because one of its parent directories is user-writable or otherwise unsafe for an administrator operation. Nothing was removed.\n\n%2")
                                    .arg(displayName, path));
                            refreshApplications();
                            return;
                        }
                    }
                }

                if (hasWritableParent && hasRestrictedParent) {
                    totalSweepWarning(
                        this,
                        QStringLiteral("Application Recheck"),
                        QStringLiteral(
                            "TotalSweep found a mixed user-owned and administrator-owned manual/local removal plan for %1. "
                            "For safety, mixed-privilege manual removal is not performed automatically. Nothing was removed.")
                            .arg(displayName));
                    refreshApplications();
                    return;
                }

                manualRemovalNeedsPrivilege[i] =
                    hasRestrictedParent;
                manualPrivilegeRequired =
                    manualPrivilegeRequired ||
                    hasRestrictedParent;

                if (hasRestrictedParent &&
                    manualApplicationQuarantineEnabled()) {
                    totalSweepWarning(
                        this,
                        QStringLiteral("Protected Manual/Local Application"),
                        QStringLiteral(
                            "%1 requires administrator privileges to remove. "
                            "For security, TotalSweep will not move administrator-owned manual/local files into the user-profile Quarantine and later restore them as root. "
                            "Nothing was removed.\n\n"
                            "You can leave the application installed, or explicitly disable manual/local application-file quarantine in Advanced Settings if you intend a permanent removal.")
                            .arg(displayName));
                    return;
                }
            }

            if (trackPackageRemoval &&
                (app.type == ApplicationType::RPM ||
                 app.type == ApplicationType::Flatpak)) {

                preparedRestores[i] = preparePackageRestore(app);

                if (exactPackageSnapshotsEnabled() &&
                    !preparedRestores.at(i).exactAvailable &&
                    restorePreferences.warnWhenSnapshotUnavailable) {
                    snapshotWarningApps.append(displayName);
                }
            }
        }

        rpmIds.removeDuplicates();
        userFlatpakIds.removeDuplicates();
        systemFlatpakIds.removeDuplicates();

        const RpmRemovalPreview rpmPreview =
            previewRpmRemoval(rpmIds);

        if (trackPackageRemoval && rpmPreview.available) {
            QJsonArray transactionPackages;
            for (const QString &package : rpmPreview.allPackages)
                transactionPackages.append(package);

            QJsonArray additionalPackages;
            for (const QString &package : rpmPreview.additionalPackages)
                additionalPackages.append(package);

            QJsonArray dependentPackages;
            for (const QString &package : rpmPreview.dependentPackages)
                dependentPackages.append(package);

            QJsonArray unusedDependencies;
            for (const QString &package : rpmPreview.unusedDependencies)
                unusedDependencies.append(package);

            for (int i = 0; i < selectedCount; ++i) {
                if (selected.at(i).type != ApplicationType::RPM)
                    continue;

                preparedRestores[i].metadata[
                    QStringLiteral("dnfTransactionPackages")] =
                    transactionPackages;
                preparedRestores[i].metadata[
                    QStringLiteral("dnfAdditionalRemovedPackages")] =
                    additionalPackages;
                preparedRestores[i].metadata[
                    QStringLiteral("dnfDependentRemovedPackages")] =
                    dependentPackages;
                preparedRestores[i].metadata[
                    QStringLiteral("dnfUnusedDependencyPackages")] =
                    unusedDependencies;
                preparedRestores[i].metadata[
                    QStringLiteral("dnfTransactionFreedSpace")] =
                    rpmPreview.freedSpace;
            }
        }

        QDialog confirm(this);
        confirm.setModal(true);
        confirm.setWindowTitle(QStringLiteral("Confirm Uninstall"));
        confirm.setWindowIcon(totalSweepIcon());

        auto *confirmLayout = new QVBoxLayout(&confirm);
        confirmLayout->setContentsMargins(20, 18, 20, 18);
        confirmLayout->setSpacing(12);

        auto *question = new QLabel(&confirm);
        if (selectedCount == 1) {
            const ApplicationInfo &app = selected.first();
            const QString displayName =
                app.name.isEmpty() ? app.id : app.name;
            question->setText(
                QStringLiteral("<b>Uninstall %1?</b>")
                    .arg(displayName.toHtmlEscaped()));
        }
        else {
            question->setText(
                QStringLiteral("<b>Uninstall %1 applications?</b>")
                    .arg(selectedCount));
        }
        QFont questionFont = question->font();
        questionFont.setPointSizeF(questionFont.pointSizeF() + 2.0);
        question->setFont(questionFont);
        question->setTextFormat(Qt::RichText);
        confirmLayout->addWidget(question);

        const bool confirmationNeedsAdministrator =
            !rpmIds.isEmpty() ||
            !systemFlatpakIds.isEmpty() ||
            manualPrivilegeRequired;

        auto *explanation = new QLabel(
            confirmationNeedsAdministrator
                ? QStringLiteral(
                    "Review what TotalSweep and the package manager will remove. "
                    "This is the only TotalSweep confirmation for this uninstall. "
                    "If you continue, KDE will request administrator authentication once.")
                : QStringLiteral(
                    "Review what TotalSweep and the package manager will remove. "
                    "This is the only TotalSweep confirmation for this uninstall."),
            &confirm);
        explanation->setWordWrap(true);
        confirmLayout->addWidget(explanation);

        auto *selectedApps = new QTreeWidget(&confirm);
        selectedApps->setColumnCount(3);
        selectedApps->setHeaderLabels({
            QStringLiteral("Application"),
            QStringLiteral("Source"),
            QStringLiteral("Version")
        });
        selectedApps->setRootIsDecorated(false);
        selectedApps->setSelectionMode(QAbstractItemView::NoSelection);
        selectedApps->setAlternatingRowColors(true);
        selectedApps->setFocusPolicy(Qt::NoFocus);
        selectedApps->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        selectedApps->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

        for (const ApplicationInfo &app : selected) {
            auto *item = new QTreeWidgetItem(selectedApps);
            item->setText(0, app.name.isEmpty() ? app.id : app.name);
            item->setText(
                1,
                app.packageManager.isEmpty()
                    ? QStringLiteral("Detected")
                    : app.packageManager);
            item->setText(
                2,
                app.version.isEmpty()
                    ? QStringLiteral("—")
                    : app.version);
        }

        selectedApps->header()->setStretchLastSection(false);
        selectedApps->header()->setSectionResizeMode(0, QHeaderView::Stretch);
        selectedApps->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        selectedApps->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

        const int visibleRows = qBound(1, selectedCount, 6);
        selectedApps->setMinimumHeight(42 + visibleRows * 38);
        selectedApps->setMaximumHeight(42 + visibleRows * 38);
        confirmLayout->addWidget(selectedApps);

        if (advancedSystemCount > 0) {
            auto *systemFrame = new QFrame(&confirm);
            systemFrame->setFrameShape(QFrame::StyledPanel);
            auto *systemLayout = new QHBoxLayout(systemFrame);
            systemLayout->setContentsMargins(12, 9, 12, 9);

            auto *systemWarning = new QLabel(
                advancedSystemCount == 1
                    ? QStringLiteral(
                        "<b>Advanced removal:</b> 1 selected item is a system package or dependency. "
                        "Removing it can affect other software or the desktop.")
                    : QString(
                        "<b>Advanced removal:</b> %1 selected items are system packages or dependencies. "
                        "Removing them can affect other software or the desktop.")
                        .arg(advancedSystemCount),
                systemFrame);
            systemWarning->setTextFormat(Qt::RichText);
            systemWarning->setWordWrap(true);
            systemLayout->addWidget(systemWarning);
            confirmLayout->addWidget(systemFrame);
        }

        if (!snapshotWarningApps.isEmpty()) {
            auto *snapshotFrame = new QFrame(&confirm);
            snapshotFrame->setFrameShape(QFrame::StyledPanel);
            auto *snapshotLayout = new QVBoxLayout(snapshotFrame);
            snapshotLayout->setContentsMargins(12, 9, 12, 9);
            snapshotLayout->setSpacing(3);

            auto *snapshotWarning = new QLabel(
                QStringLiteral(
                    "<b>Exact restore snapshot unavailable:</b> %1")
                    .arg(snapshotWarningApps.join(QStringLiteral(", ")).toHtmlEscaped()),
                snapshotFrame);
            snapshotWarning->setTextFormat(Qt::RichText);
            snapshotWarning->setWordWrap(true);

            auto *snapshotDetail = new QLabel(
                restorePreferences.keepMetadataOnlyRecords
                    ? QStringLiteral(
                        "TotalSweep can keep a metadata-only recovery record, but exact restoration may depend on that version remaining available later.")
                    : QStringLiteral(
                        "Metadata-only records are disabled, so those applications will not receive a TotalSweep application-restore record."),
                snapshotFrame);
            snapshotDetail->setWordWrap(true);

            snapshotLayout->addWidget(snapshotWarning);
            snapshotLayout->addWidget(snapshotDetail);
            confirmLayout->addWidget(snapshotFrame);
        }

        if (!rpmIds.isEmpty()) {
            auto *dnfFrame = new QFrame(&confirm);
            dnfFrame->setFrameShape(QFrame::StyledPanel);
            auto *dnfLayout = new QVBoxLayout(dnfFrame);
            dnfLayout->setContentsMargins(12, 10, 12, 10);
            dnfLayout->setSpacing(6);

            auto *dnfTitle = new QLabel(
                QStringLiteral("<b>DNF transaction</b>"),
                dnfFrame);
            dnfTitle->setTextFormat(Qt::RichText);
            dnfLayout->addWidget(dnfTitle);

            QString dnfSummaryText;
            if (rpmPreview.available) {
                const int dependent = rpmPreview.dependentPackages.size();
                const int unused = rpmPreview.unusedDependencies.size();
                const int categorized = dependent + unused;
                const int other = qMax(
                    0,
                    rpmPreview.additionalPackages.size() - categorized);

                QStringList parts;
                parts.append(
                    QStringLiteral("%1 selected")
                        .arg(rpmIds.size()));

                if (dependent > 0) {
                    parts.append(
                        QStringLiteral("%1 dependent %2")
                            .arg(dependent)
                            .arg(wordForCount(
                                dependent,
                                QStringLiteral("package"),
                                QStringLiteral("packages"))));
                }

                if (unused > 0) {
                    parts.append(
                        QStringLiteral("%1 unused %2")
                            .arg(unused)
                            .arg(wordForCount(
                                unused,
                                QStringLiteral("dependency"),
                                QStringLiteral("dependencies"))));
                }

                if (other > 0) {
                    parts.append(
                        QStringLiteral("%1 other transaction %2")
                            .arg(other)
                            .arg(wordForCount(
                                other,
                                QStringLiteral("package"),
                                QStringLiteral("packages"))));
                }

                dnfSummaryText = QString(
                    "DNF plans to remove %1 RPM %2: %3%4.")
                    .arg(rpmPreview.allPackages.size())
                    .arg(wordForCount(
                        rpmPreview.allPackages.size(),
                        QStringLiteral("package"),
                        QStringLiteral("packages")))
                    .arg(parts.join(QStringLiteral(" + ")))
                    .arg(rpmPreview.freedSpace.isEmpty()
                        ? QString()
                        : QStringLiteral(" • %1 freed").arg(rpmPreview.freedSpace));
            }
            else {
                dnfSummaryText = QStringLiteral(
                    "DNF will calculate the final RPM dependency transaction during removal. "
                    "TotalSweep could not parse a preview, so no extra package count is being guessed.");
            }

            auto *dnfSummary = new QLabel(dnfSummaryText, dnfFrame);
            dnfSummary->setWordWrap(true);
            dnfLayout->addWidget(dnfSummary);

            if (!rpmPreview.dependentPackages.isEmpty()) {
                auto *dependentWarning = new QLabel(
                    QStringLiteral(
                        "<b>Important:</b> DNF also plans to remove %1 additional %2 because %3 on what you selected. "
                        "Review those packages before continuing.")
                        .arg(rpmPreview.dependentPackages.size())
                        .arg(wordForCount(
                            rpmPreview.dependentPackages.size(),
                            QStringLiteral("package"),
                            QStringLiteral("packages")))
                        .arg(rpmPreview.dependentPackages.size() == 1
                            ? QStringLiteral("it depends")
                            : QStringLiteral("they depend")),
                    dnfFrame);
                dependentWarning->setTextFormat(Qt::RichText);
                dependentWarning->setWordWrap(true);
                dnfLayout->addWidget(dependentWarning);
            }

            auto *dnfExplanation = new QLabel(
                QStringLiteral(
                    "DNF transaction packages are managed RPMs, not filesystem Leftovers. "
                    "‘No longer needed’ means DNF tracks them as dependency-installed and no longer required after this removal; "
                    "it does not prove they were originally installed with this application. "
                    "Leftovers are scanned only after the package transaction finishes."),
                dnfFrame);
            dnfExplanation->setWordWrap(true);
            dnfLayout->addWidget(dnfExplanation);

            if (!rpmPreview.additionalPackages.isEmpty()) {
                auto *reviewPackages = new QPushButton(
                    QStringLiteral("Review %1 additional %2…")
                        .arg(rpmPreview.additionalPackages.size())
                        .arg(wordForCount(
                            rpmPreview.additionalPackages.size(),
                            QStringLiteral("package"),
                            QStringLiteral("packages"))),
                    dnfFrame);

                reviewPackages->setToolTip(
                    QStringLiteral(
                        "Open a large package-details window grouped by selected packages, dependent removals and DNF dependency cleanup."));

                connect(
                    reviewPackages,
                    &QPushButton::clicked,
                    &confirm,
                    [this, rpmPreview, rpmIds]() {
                        showRpmRemovalDetails(rpmPreview, rpmIds);
                    });

                dnfLayout->addWidget(reviewPackages, 0, Qt::AlignLeft);
            }

            confirmLayout->addWidget(dnfFrame);
        }

        auto *recoveryFrame = new QFrame(&confirm);
        recoveryFrame->setFrameShape(QFrame::StyledPanel);
        auto *recoveryLayout = new QVBoxLayout(recoveryFrame);
        recoveryLayout->setContentsMargins(12, 10, 12, 10);
        recoveryLayout->setSpacing(4);

        auto *recoveryTitle = new QLabel(
            QStringLiteral("<b>Recovery for this removal</b>"),
            recoveryFrame);
        recoveryTitle->setTextFormat(Qt::RichText);

        auto *recoverySummary = new QLabel(
            futureRemovalPolicySummary(),
            recoveryFrame);
        recoverySummary->setWordWrap(true);

        recoveryLayout->addWidget(recoveryTitle);
        recoveryLayout->addWidget(recoverySummary);
        confirmLayout->addWidget(recoveryFrame);

        auto *confirmButtons = new QDialogButtonBox(Qt::Horizontal, &confirm);
        QPushButton *cancelUninstall =
            confirmButtons->addButton(QDialogButtonBox::Cancel);
        QPushButton *confirmUninstall =
            confirmButtons->addButton(
                QStringLiteral("Uninstall"),
                QDialogButtonBox::DestructiveRole);

        configureMonochromeButton(
            confirmUninstall,
            {QStringLiteral("edit-delete"), QStringLiteral("edit-delete-shred")},
            QStyle::SP_TrashIcon,
            QSize(18, 18));

        cancelUninstall->setDefault(true);
        cancelUninstall->setFocus();

        connect(cancelUninstall, &QPushButton::clicked, &confirm, &QDialog::reject);
        connect(confirmUninstall, &QPushButton::clicked, &confirm, &QDialog::accept);
        confirmLayout->addWidget(confirmButtons);

        const QScreen *confirmScreen =
            confirm.screen() ? confirm.screen() : QApplication::primaryScreen();
        const int confirmAvailableWidth =
            confirmScreen ? confirmScreen->availableGeometry().width() : 1280;
        const int confirmAvailableHeight =
            confirmScreen ? confirmScreen->availableGeometry().height() : 900;
        const int confirmWidth =
            qMax(700, qMin(940, confirmAvailableWidth - 100));
        confirm.setMinimumWidth(qMin(760, confirmWidth));
        confirm.resize(
            confirmWidth,
            qMin(confirm.sizeHint().height(), confirmAvailableHeight - 100));

        if (confirm.exec() != QDialog::Accepted)
            return;

        QStringList changedManualTargets;
        for (int i = 0; i < selectedCount; ++i) {
            if (!manualRemovalPlanReady.at(i))
                continue;

            for (const QString &path :
                 manualRemovalPlans.at(i).paths) {
                const QFileInfo info(path);

                if ((!info.exists() && !info.isSymLink()) ||
                    !safeManualRemovalTargetStatic(path) ||
                    !rpmOwnerForPath(path).isEmpty()) {
                    changedManualTargets.append(path);
                }
            }
        }

        if (!changedManualTargets.isEmpty()) {
            totalSweepWarning(
                this,
                QStringLiteral("Application Recheck"),
                QStringLiteral(
                    "One or more manual/local removal paths changed while the confirmation window was open. "
                    "For safety, nothing was removed.\n\n%1")
                    .arg(changedManualTargets.join(QLatin1Char('\n'))));
            refreshApplications();
            return;
        }

        int successful = 0;
        QStringList successfulNames;
        QList<ApplicationInfo> successfulApps;
        QStringList failures;
        QStringList postRemovalWarnings;

        const bool removeFlatpakData =
            !restorePreferences.preserveFlatpakUserData;

        const bool unifiedPrivilegeRequired =
            !rpmIds.isEmpty() ||
            !systemFlatpakIds.isEmpty() ||
            manualPrivilegeRequired;

        struct ManualBatchWork {
            bool active = false;
            bool quarantine = false;
            QString session;
            QString created;
            QStringList sources;
            QStringList destinations;
            QVector<qint64> sizes;
            QString preparationError;
        };

        QVector<ManualBatchWork>
            manualBatchWorks(selectedCount);

        QList<QStringList>
            manualDeleteGroups;

        if (unifiedPrivilegeRequired) {
            for (int i = 0;
                 i < selectedCount;
                 ++i) {

                const ApplicationInfo &app =
                    selected.at(i);

                if (!isManualLocal(app) ||
                    !manualRemovalNeedsPrivilege.at(i)) {
                    continue;
                }

                ManualBatchWork &work =
                    manualBatchWorks[i];

                if (!manualRemovalPlanReady.at(i)) {
                    work.preparationError =
                        QStringLiteral(
                            "The verified manual/local removal plan was unavailable.");
                    continue;
                }

                work.active = true;
                work.quarantine = false;
                work.sources =
                    manualRemovalPlans.at(i).paths;

                manualDeleteGroups.append(
                    work.sources);
            }
        }

        const ProcessResult privilegedPackageResult =
            runPrivilegedPackageRemovalBatch(
                rpmIds,
                systemFlatpakIds,
                removeFlatpakData,
                manualDeleteGroups);

        const bool privilegedAuthorizationStopped =
            unifiedPrivilegeRequired &&
            (!privilegedPackageResult.started ||
             privilegedPackageResult.exitCode == 126 ||
             privilegedPackageResult.exitCode == 127 ||
             privilegedPackageResult.standardError ==
                 QStringLiteral(
                     "Operation cancelled."));

        if (privilegedAuthorizationStopped) {
            for (const ManualBatchWork &work :
                 std::as_const(
                     manualBatchWorks)) {
                if (work.active &&
                    work.quarantine &&
                    !work.session.isEmpty()) {
                    QDir(work.session)
                        .removeRecursively();
                }
            }

            totalSweepInformation(
                this,
                QStringLiteral(
                    "Uninstall Cancelled"),
                QStringLiteral(
                    "Administrator authentication was cancelled or unavailable. Nothing else from this selection was removed."));
            return;
        }

        const ProcessResult userFlatpakResult =
            runUserFlatpakRemovalBatch(
                userFlatpakIds,
                removeFlatpakData);

        auto packageFailureText = [](const ProcessResult &result) {
            if (!result.standardError.trimmed().isEmpty())
                return result.standardError.trimmed();
            if (!result.standardOutput.trimmed().isEmpty())
                return result.standardOutput.trimmed();
            return QStringLiteral("The package manager did not remove the application.");
        };

        for (int i = 0; i < selectedCount; ++i) {
            const ApplicationInfo &app = selected.at(i);
            const QString displayName =
                app.name.isEmpty() ? app.id : app.name;

            if (app.type == ApplicationType::RPM ||
                app.type == ApplicationType::Flatpak) {

                bool stillInstalled = false;
                const ProcessResult *relevantResult = &privilegedPackageResult;

                if (app.type == ApplicationType::RPM) {
                    stillInstalled = commandSucceeds(
                        QStringLiteral("rpm"),
                        {QStringLiteral("-q"), app.id},
                        10000);
                }
                else {
                    const QString scope = flatpakScopes.at(i);
                    QStringList arguments{
                        QStringLiteral("info"),
                        scope == QStringLiteral("user")
                            ? QStringLiteral("--user")
                            : QStringLiteral("--system"),
                        app.id
                    };
                    stillInstalled = commandSucceeds(
                        QStringLiteral("flatpak"),
                        arguments,
                        10000);
                    if (scope == QStringLiteral("user"))
                        relevantResult = &userFlatpakResult;
                }

                if (!stillInstalled) {
                    ++successful;
                    successfulNames.append(displayName);
                    successfulApps.append(app);

                    if (trackPackageRemoval &&
                        (preparedRestores.at(i).exactAvailable ||
                         restorePreferences.keepMetadataOnlyRecords) &&
                        !commitPackageRestoreRecord(
                            app,
                            preparedRestores.at(i))) {
                        postRemovalWarnings.append(
                            QStringLiteral(
                                "%1 was uninstalled, but TotalSweep could not write its Quarantine restore record.")
                                .arg(displayName));
                    }
                }
                else {
                    failures.append(
                        QStringLiteral("%1 — %2")
                            .arg(displayName, packageFailureText(*relevantResult)));
                }

                continue;
            }

            if (isManualLocal(app)) {
                if (manualRemovalNeedsPrivilege.at(i)) {
                    const ManualBatchWork &work =
                        manualBatchWorks.at(i);

                    if (!work.preparationError.isEmpty()) {
                        failures.append(
                            QStringLiteral("%1 — %2")
                                .arg(
                                    displayName,
                                    work.preparationError));
                        continue;
                    }

                    if (!work.active) {
                        failures.append(
                            QStringLiteral(
                                "%1 — no executable manual/local removal work was prepared")
                                .arg(
                                    displayName));
                        continue;
                    }

                    bool removed = true;

                    if (work.quarantine) {
                        int movedCount = 0;
                        int sourceCount = 0;

                        for (int itemIndex = 0;
                             itemIndex <
                                work.sources.size();
                             ++itemIndex) {

                            const QString &source =
                                work.sources.at(
                                    itemIndex);
                            const QString &destination =
                                work.destinations.at(
                                    itemIndex);

                            const QFileInfo sourceInfo(
                                source);
                            const QFileInfo destinationInfo(
                                destination);

                            const bool sourceExists =
                                sourceInfo.exists() ||
                                sourceInfo.isSymLink();
                            const bool destinationExists =
                                destinationInfo.exists() ||
                                destinationInfo.isSymLink();

                            if (!sourceExists &&
                                destinationExists) {
                                ++movedCount;
                            }
                            else if (sourceExists &&
                                     !destinationExists) {
                                ++sourceCount;
                            }
                            else {
                                removed = false;
                            }
                        }

                        removed =
                            removed &&
                            movedCount ==
                                work.sources.size();

                        if (removed) {
                            QJsonObject history;
                            history[
                                QStringLiteral("id")] =
                                QFileInfo(
                                    work.session)
                                    .fileName()
                                    .section(
                                        QLatin1Char('_'),
                                        0,
                                        2);
                            history[
                                QStringLiteral("kind")] =
                                QStringLiteral(
                                    "application");
                            history[
                                QStringLiteral("application")] =
                                displayName;
                            history[
                                QStringLiteral("session")] =
                                work.session;
                            history[
                                QStringLiteral("items")] =
                                work.sources.size();
                            history[
                                QStringLiteral("created")] =
                                work.created;
                            history[
                                QStringLiteral("appType")] =
                                restoreTypeLabel(app);
                            history[
                                QStringLiteral("version")] =
                                app.version;
                            history[
                                QStringLiteral("restoreMode")] =
                                QStringLiteral("files");
                            appendHistoryObject(
                                history);
                        }
                        else if (sourceCount ==
                                 work.sources.size()) {
                            QDir(work.session)
                                .removeRecursively();
                        }
                        else {
                            QJsonObject history;
                            history[
                                QStringLiteral("id")] =
                                QFileInfo(
                                    work.session)
                                    .fileName()
                                    .section(
                                        QLatin1Char('_'),
                                        0,
                                        2);
                            history[
                                QStringLiteral("kind")] =
                                QStringLiteral(
                                    "application");
                            history[
                                QStringLiteral("application")] =
                                displayName;
                            history[
                                QStringLiteral("session")] =
                                work.session;
                            history[
                                QStringLiteral("items")] =
                                work.sources.size();
                            history[
                                QStringLiteral("created")] =
                                work.created;
                            history[
                                QStringLiteral("appType")] =
                                restoreTypeLabel(app);
                            history[
                                QStringLiteral("version")] =
                                app.version;
                            history[
                                QStringLiteral("restoreMode")] =
                                QStringLiteral("files");
                            appendHistoryObject(
                                history);

                            failures.append(
                                QStringLiteral(
                                    "%1 — removal was incomplete; the recovery map was preserved in Quarantine")
                                    .arg(
                                        displayName));
                            continue;
                        }
                    }
                    else {
                        for (const QString &path :
                             work.sources) {
                            const QFileInfo info(
                                path);
                            if (info.exists() ||
                                info.isSymLink()) {
                                removed = false;
                                break;
                            }
                        }
                    }

                    if (removed) {
                        ++successful;
                        successfulNames.append(
                            displayName);
                        successfulApps.append(
                            app);

                        if (!work.quarantine &&
                            !commitNonRestorableApplicationRecord(
                                app,
                                QStringLiteral(
                                    "Manual/local application-file quarantine was disabled in Settings; "
                                    "the application files were removed permanently."))) {
                            postRemovalWarnings.append(
                                QStringLiteral(
                                    "%1 was removed, but TotalSweep could not write its metadata-only Quarantine record.")
                                    .arg(
                                        displayName));
                        }
                    }
                    else {
                        failures.append(
                            QStringLiteral(
                                "%1 — the unified privileged removal did not complete")
                                .arg(
                                    displayName));
                    }

                    continue;
                }

                QString manualError;
                const bool quarantined =
                    manualApplicationQuarantineEnabled();
                const bool removed = quarantined
                    ? quarantineManualApplication(app, manualError)
                    : removeManualApplicationPermanently(app, manualError);

                if (removed) {
                    ++successful;
                    successfulNames.append(displayName);
                    successfulApps.append(app);

                    if (!quarantined &&
                        !commitNonRestorableApplicationRecord(
                            app,
                            QStringLiteral(
                                "Manual/local application-file quarantine was disabled in Settings; "
                                "the application files were removed permanently."))) {
                        postRemovalWarnings.append(
                            QStringLiteral(
                                "%1 was removed, but TotalSweep could not write its metadata-only Quarantine record.")
                                .arg(displayName));
                    }
                }
                else {
                    failures.append(
                        QStringLiteral("%1 — %2")
                            .arg(displayName, manualError));
                }
                continue;
            }

            failures.append(
                QStringLiteral("%1 — no supported removal method is available")
                    .arg(displayName));
        }

        search->clear();
        committedApplicationSearch.clear();

        if (successful > 0)
            loadHistory();

        refreshApplications();

        if (successful > 0 && !successfulApps.isEmpty()) {
            setCurrentPage(1);

            if (restorePreferences.autoScanLeftoversAfterUninstall) {
                if (successfulApps.size() == 1) {
                    const ApplicationInfo &removed =
                        successfulApps.first();

                    const QString displayName =
                        removed.name.isEmpty()
                            ? removed.id
                            : removed.name;

                    const QString leftoverKey =
                        removed.id.trimmed().isEmpty()
                            ? displayName
                            : removed.id.trimmed();

                    scanLeftoversAsync(
                        leftoverKey,
                        leftoverSearchTermsForApplication(removed),
                        true,
                        displayName);
                }
                else {
                    startPostUninstallLeftoverBatch(
                        successfulApps);
                }
            }
            else if (successfulApps.size() == 1) {
                const ApplicationInfo &removed =
                    successfulApps.first();

                const QString displayName =
                    removed.name.isEmpty()
                        ? removed.id
                        : removed.name;

                const QString leftoverKey =
                    removed.id.trimmed().isEmpty()
                        ? displayName
                        : removed.id.trimmed();

                currentApp = leftoverKey;

                if (leftoversSearch) {
                    const QSignalBlocker blocker(
                        leftoversSearch);
                    leftoversSearch->setText(
                        leftoverKey);
                }

                if (results)
                    results->clear();

                if (resultStatus) {
                    resultStatus->setText(
                        QStringLiteral(
                            "%1 was removed. Press Enter to scan for leftovers.")
                            .arg(displayName));
                }
            }
            else {
                currentApp.clear();

                if (leftoversSearch) {
                    const QSignalBlocker blocker(
                        leftoversSearch);
                    leftoversSearch->clear();
                }

                if (results)
                    results->clear();

                if (resultStatus) {
                    resultStatus->setText(
                        QStringLiteral(
                            "%1 applications were removed. Automatic Leftovers scanning is off; search an application whenever you want to review its leftovers.")
                            .arg(successfulApps.size()));
                }
            }
        }

        QStringList resultLines;
        for (const QString &name : successfulNames) {
            resultLines.append(
                QStringLiteral("%1 was uninstalled successfully.")
                    .arg(name));
        }

        if (!postRemovalWarnings.isEmpty()) {
            if (!resultLines.isEmpty())
                resultLines.append(QString());
            resultLines.append(QStringLiteral("Restore-record warnings:"));
            resultLines.append(postRemovalWarnings);
        }

        if (!failures.isEmpty()) {
            if (!resultLines.isEmpty())
                resultLines.append(QString());
            resultLines.append(QStringLiteral("The following could not be removed:"));
            resultLines.append(failures);
        }

        if (resultLines.isEmpty())
            resultLines.append(QStringLiteral("No applications were removed."));

        if (successful > 0 &&
            failures.isEmpty() &&
            postRemovalWarnings.isEmpty()) {
            showTransientInformation(
                QStringLiteral("Uninstall Complete"),
                resultLines.join(QLatin1Char('\n')),
                5000);
        }
        else {
            totalSweepInformation(
                this,
                QStringLiteral("Uninstall Results"),
                resultLines.join(QLatin1Char('\n')));
        }
    }

    static bool isWeakLeftoverIdentityTerm(
        QString term)
    {
        term = term.trimmed().toCaseFolded();

        if (term.isEmpty())
            return true;

        static const QSet<QString> weakTerms = {
            QStringLiteral("app"),
            QStringLiteral("application"),
            QStringLiteral("audio"),
            QStringLiteral("browser"),
            QStringLiteral("client"),
            QStringLiteral("converter"),
            QStringLiteral("desktop"),
            QStringLiteral("downloader"),
            QStringLiteral("editor"),
            QStringLiteral("file"),
            QStringLiteral("files"),
            QStringLiteral("helper"),
            QStringLiteral("launcher"),
            QStringLiteral("manager"),
            QStringLiteral("media"),
            QStringLiteral("player"),
            QStringLiteral("recorder"),
            QStringLiteral("server"),
            QStringLiteral("service"),
            QStringLiteral("settings"),
            QStringLiteral("studio"),
            QStringLiteral("system"),
            QStringLiteral("tool"),
            QStringLiteral("utility"),
            QStringLiteral("video"),
            QStringLiteral("videos"),
            QStringLiteral("viewer"),
            QStringLiteral("download"),
            QStringLiteral("downloads"),
            QStringLiteral("game"),
            QStringLiteral("games"),
            QStringLiteral("image"),
            QStringLiteral("images"),
            QStringLiteral("mail"),
            QStringLiteral("music"),
            QStringLiteral("note"),
            QStringLiteral("notes"),
            QStringLiteral("photo"),
            QStringLiteral("photos")
        };

        return weakTerms.contains(term);
    }


    QStringList sanitizeLeftoverSearchTerms(
        const QStringList &rawTerms) const
    {
        QStringList terms;
        QSet<QString> seen;

        for (QString term : rawTerms) {
            term = term.trimmed();
            if (term.isEmpty())
                continue;

            if (term.startsWith(QStringLiteral("file://")))
                term = term.mid(7);

            if (term.contains(QLatin1Char('/')))
                term = QFileInfo(term).fileName();

            if (term.endsWith(QStringLiteral(".desktop"), Qt::CaseInsensitive))
                term.chop(8);

            term.remove(QLatin1Char('*'));
            term.remove(QLatin1Char('?'));
            term.remove(QLatin1Char('['));
            term.remove(QLatin1Char(']'));
            term = term.trimmed();

            if (term.size() < 3)
                continue;

            if (!term.contains(QRegularExpression(QStringLiteral("[\\s._-]"))) &&
                isWeakLeftoverIdentityTerm(term)) {
                continue;
            }

            const QString folded = term.toCaseFolded();
            if (seen.contains(folded))
                continue;

            seen.insert(folded);
            terms.append(term);

            if (terms.size() >= 8)
                break;
        }

        return terms;
    }


    QStringList leftoverSearchTermsForApplication(
        const ApplicationInfo &app) const
    {
        QStringList raw;

        raw.append(app.id);

        const QString idTail =
            app.id.section(QLatin1Char('.'), -1).trimmed();
        if (idTail != app.id)
            raw.append(idTail);

        raw.append(app.name);

        const QStringList execParts =
            QProcess::splitCommand(
                app.executable.trimmed());
        for (const QString &part : execParts) {
            if (part.startsWith(QLatin1Char('%')))
                continue;
            const QString base = QFileInfo(part).fileName();
            if (!base.isEmpty()) {
                raw.append(base);
                break;
            }
        }

        if (!app.desktopFile.trimmed().isEmpty())
            raw.append(QFileInfo(app.desktopFile).completeBaseName());

        return sanitizeLeftoverSearchTerms(raw);
    }


    bool applicationMatchesActiveLeftoverIdentity(
        const ApplicationInfo &app) const
    {
        QStringList identities{
            app.id,
            app.name,
            QFileInfo(app.desktopFile).completeBaseName()
        };

        const QStringList execParts =
            QProcess::splitCommand(app.executable.trimmed());
        if (!execParts.isEmpty())
            identities.append(QFileInfo(execParts.first()).fileName());

        for (const QString &identity : identities) {
            const QString normalizedIdentity =
                normalizeApplicationName(identity);

            if (normalizedIdentity.size() < 3)
                continue;

            for (const QString &term : activeLeftoverSearchTerms) {
                const QString normalizedTerm =
                    normalizeApplicationName(term);

                if (normalizedTerm.size() < 3)
                    continue;

                if (normalizedIdentity == normalizedTerm)
                    return true;
            }
        }

        return false;
    }


    static bool pathIsInsideOrEqual(
        const QString &path,
        const QString &root)
    {
        const QString cleanedPath =
            QDir::cleanPath(path);
        const QString cleanedRoot =
            QDir::cleanPath(root);

        if (cleanedPath.isEmpty() ||
            cleanedRoot.isEmpty()) {
            return false;
        }

        return cleanedPath == cleanedRoot ||
            cleanedPath.startsWith(
                cleanedRoot + QLatin1Char('/'));
    }


    void rebuildProtectedOtherApplicationRoots()
    {
        protectedOtherApplicationRoots.clear();
        QSet<QString> seen;

        for (const ApplicationInfo &app : currentApplications) {
            if (!app.installed ||
                applicationMatchesActiveLeftoverIdentity(app)) {
                continue;
            }

            QStringList locations =
                app.installLocations;
            locations.prepend(app.installLocation);

            for (const QString &rawLocation : locations) {
                QString location =
                    QDir::cleanPath(rawLocation.trimmed());

                if (location.isEmpty() ||
                    !QDir::isAbsolutePath(location)) {
                    continue;
                }

                if (isManualLocal(app))
                    location =
                        collapseManualInstallRoot(app, location);

                QFileInfo info(location);
                if (info.isFile() || info.isSymLink())
                    location = info.absoluteFilePath();

                if (location.isEmpty() ||
                    seen.contains(location) ||
                    isTotalSweepManagedPath(location)) {
                    continue;
                }

                const QString home =
                    QDir::cleanPath(QDir::homePath());
                const QSet<QString> broadRoots = {
                    QStringLiteral("/"),
                    QStringLiteral("/opt"),
                    QStringLiteral("/usr"),
                    QStringLiteral("/usr/local"),
                    QStringLiteral("/var"),
                    QStringLiteral("/etc"),
                    home
                };

                if (broadRoots.contains(location))
                    continue;

                seen.insert(location);
                protectedOtherApplicationRoots.append(location);
            }
        }

        std::sort(
            protectedOtherApplicationRoots.begin(),
            protectedOtherApplicationRoots.end(),
            [](const QString &a, const QString &b) {
                return a.size() > b.size();
            });
    }


    bool pathBelongsToOtherInstalledApplication(
        const QString &path) const
    {
        for (const QString &root :
             protectedOtherApplicationRoots) {
            if (pathIsInsideOrEqual(path, root))
                return true;
        }

        return false;
    }


    bool componentMatchesActiveLeftoverIdentity(
        const QString &component) const
    {
        const QString normalizedComponent =
            normalizeApplicationName(component);

        if (normalizedComponent.size() < 3)
            return false;

        for (const QString &term :
             activeLeftoverSearchTerms) {

            if (isWeakLeftoverIdentityTerm(
                    term.trimmed().toCaseFolded())) {
                continue;
            }

            const QString normalizedTerm =
                normalizeApplicationName(term);

            if (normalizedTerm.size() < 3)
                continue;

            if (normalizedTerm.size() == 3) {
                if (normalizedComponent == normalizedTerm)
                    return true;
                continue;
            }

            if (normalizedComponent == normalizedTerm ||
                normalizedComponent.contains(normalizedTerm)) {
                return true;
            }
        }

        return false;
    }


    QString applicationIdentityComponentForPath(
        const QString &path) const
    {
        const QString cleaned =
            QDir::cleanPath(path);
        const QString home =
            QDir::cleanPath(QDir::homePath());

        const QString applicationsRoot =
            home + QStringLiteral("/.local/share/applications/");

        if (cleaned.startsWith(applicationsRoot))
            return QFileInfo(cleaned).completeBaseName();

        const QStringList roots = {
            home + QStringLiteral("/.config"),
            home + QStringLiteral("/.cache"),
            home + QStringLiteral("/.local/share"),
            home + QStringLiteral("/.local/state"),
            home + QStringLiteral("/.local/lib"),
            home + QStringLiteral("/.var/app"),
            QStringLiteral("/opt"),
            QStringLiteral("/usr/local/share"),
            QStringLiteral("/usr/local/lib"),
            QStringLiteral("/usr/local/lib64")
        };

        for (const QString &root : roots) {
            const QString prefix =
                QDir::cleanPath(root) + QLatin1Char('/');

            if (!cleaned.startsWith(prefix))
                continue;

            const QString relative =
                cleaned.mid(prefix.size());

            return relative.section(
                QLatin1Char('/'),
                0,
                0);
        }

        return QFileInfo(cleaned).completeBaseName();
    }


    bool isStrongRecommendedLeftoverMatch(
        const QString &path) const
    {
        return componentMatchesActiveLeftoverIdentity(
            applicationIdentityComponentForPath(path));
    }


    void appendLeftoverNameExpression(
        QStringList &arguments,
        const QStringList &terms) const
    {
        arguments.append(QStringLiteral("("));

        for (int i = 0; i < terms.size(); ++i) {
            if (i > 0)
                arguments.append(QStringLiteral("-o"));

            arguments.append(QStringLiteral("-iname"));
            arguments.append(
                QStringLiteral("*") +
                terms.at(i) +
                QStringLiteral("*"));
        }

        arguments.append(QStringLiteral(")"));
        arguments.append(QStringLiteral("-print"));
    }


    bool isPackageManagerMetadataPath(
        const QString &path) const
    {
        const QString cleaned =
            QDir::cleanPath(path).toLower();

        const QString userFlatpakRoot =
            QDir::cleanPath(
                QDir::homePath() +
                QStringLiteral("/.local/share/flatpak"))
                .toLower();

        return
            cleaned == QStringLiteral("/var/lib/flatpak") ||
            cleaned.startsWith(QStringLiteral("/var/lib/flatpak/")) ||
            cleaned == userFlatpakRoot ||
            cleaned.startsWith(userFlatpakRoot + QLatin1Char('/')) ||
            cleaned == QStringLiteral("/var/cache/dnf") ||
            cleaned.startsWith(QStringLiteral("/var/cache/dnf/")) ||
            cleaned == QStringLiteral("/var/cache/libdnf5") ||
            cleaned.startsWith(QStringLiteral("/var/cache/libdnf5/")) ||
            cleaned == QStringLiteral("/var/lib/dnf") ||
            cleaned.startsWith(QStringLiteral("/var/lib/dnf/")) ||
            cleaned == QStringLiteral("/var/lib/packagekit") ||
            cleaned.startsWith(QStringLiteral("/var/lib/packagekit/"));
    }



    int classify(const QString &path)
    {
        const QString x =
            QDir::cleanPath(path).toLower();

        if (pathBelongsToOtherInstalledApplication(path))
            return 3;

        if (isStandardUserContentPath(path) ||
            x.contains("/backups/") ||
            x.contains("/backup/")) {

            return 3;
        }

        if (x.contains("/.floorp/") ||
            x.contains("kactivitymanagerd") ||
            x.contains("baloo") ||
            x.contains("klipper")) {

            return 3;
        }

        if (x.startsWith(QStringLiteral("/opt/"))) {
            return isStrongRecommendedLeftoverMatch(path)
                ? 1
                : 3;
        }

        if (x.contains("/var/cache/") ||
            x.contains(
                "/var/lib/systemd/coredump")) {

            return 2;
        }

        const bool normalUserAppData =
            x.contains("/.cache/") ||
            x.contains("/.config/") ||
            x.contains("/.local/lib/") ||
            x.contains("/.local/share/") ||
            x.contains("/.var/app/");

        if (normalUserAppData) {
            return isStrongRecommendedLeftoverMatch(path)
                ? 1
                : 2;
        }

        if (x.startsWith(QStringLiteral("/usr/local/"))) {
            return isStrongRecommendedLeftoverMatch(path)
                ? 1
                : 2;
        }

        return 2;
    }

    QString categoryFor(int risk) const
    {
        if (risk == 1)
            return "Confirmed Leftovers";

        if (risk == 3)
            return "Danger — Possibly Unrelated";

        return "Review / Possible";
    }


    void setSearchControlsForLeftoverScan(
        bool scanning)
    {
        if (leftoversSearch)
            leftoversSearch->setEnabled(true);

        if (cancelLeftoverScanBtn)
            cancelLeftoverScanBtn->setVisible(scanning);

        updatePageToolbar();
    }


    void clearPostUninstallLeftoverBatchState()
    {
        pendingPostUninstallLeftoverApps.clear();
        postUninstallBatchTotal = 0;
        postUninstallBatchCompleted = 0;
        postUninstallBatchResultCount = 0;
        postUninstallBatchSkipped = 0;
        postUninstallBatchActive = false;
        activePostUninstallAppGroup = nullptr;
    }


    void startPostUninstallLeftoverBatch(
        const QList<ApplicationInfo> &applications)
    {
        if (applications.isEmpty())
            return;

        if (leftoverScanRunning ||
            leftoverHomeProcess ||
            leftoverSystemProcess ||
            !pendingLeftoverItems.isEmpty()) {

            stopLeftoverScan();
        }

        clearPostUninstallLeftoverBatchState();

        pendingPostUninstallLeftoverApps =
            applications;

        postUninstallBatchTotal =
            pendingPostUninstallLeftoverApps.size();

        postUninstallBatchActive = true;

        currentApp.clear();

        if (leftoversSearch) {
            const QSignalBlocker blocker(
                leftoversSearch);
            leftoversSearch->clear();
        }

        if (results) {
            setHoveredLeftoverItem(nullptr);
            pressedLeftoverItem = nullptr;
            results->clear();
            results->setEmptyMessage(QString());
        }

        if (resultStatus) {
            resultStatus->setText(
                QStringLiteral(
                    "Scanning leftovers for %1 removed applications...")
                    .arg(postUninstallBatchTotal));
        }

        setCurrentPage(1);

        QTimer::singleShot(
            0,
            this,
            [this]() {
                scanNextPostUninstallLeftover();
            });
    }


    void scanNextPostUninstallLeftover()
    {
        if (!postUninstallBatchActive)
            return;

        if (pendingPostUninstallLeftoverApps.isEmpty()) {
            const int total =
                postUninstallBatchTotal;

            const int found =
                postUninstallBatchResultCount;
            const int skipped =
                postUninstallBatchSkipped;

            postUninstallBatchActive = false;
            activePostUninstallAppGroup = nullptr;
            currentApp.clear();

            if (leftoversSearch) {
                const QSignalBlocker blocker(
                    leftoversSearch);
                leftoversSearch->clear();
            }

            if (resultStatus) {
                if (skipped > 0) {
                    resultStatus->setText(
                        QStringLiteral(
                            "Leftovers scan finished for %1 removed applications: %2 %3 found; %4 %5 skipped because the available identity was too broad to search safely. Results are grouped by application.")
                            .arg(total)
                            .arg(found)
                            .arg(wordForCount(
                                found,
                                QStringLiteral("result"),
                                QStringLiteral("results")))
                            .arg(skipped)
                            .arg(wordForCount(
                                skipped,
                                QStringLiteral("scan was"),
                                QStringLiteral("scans were"))));
                }
                else if (found == 0) {
                    resultStatus->setText(
                        QStringLiteral(
                            "Nothing else was found. TotalSweep did not find any remaining leftovers for the %1 removed applications.")
                            .arg(total));
                }
                else {
                    resultStatus->setText(
                        QStringLiteral(
                            "Leftovers scan complete for %1 removed applications: %2 %3 found. Results are grouped by application.")
                            .arg(total)
                            .arg(found)
                            .arg(wordForCount(
                                found,
                                QStringLiteral("result"),
                                QStringLiteral("results"))));
                }
            }

            if (results) {
                if (found == 0 && skipped == 0) {
                    results->clear();
                    results->setEmptyMessage(
                        QStringLiteral(
                            "Nothing else was found — no additional leftovers remain for the removed applications."));
                }
                else {
                    results->setEmptyMessage(QString());
                }
            }

            pendingPostUninstallLeftoverApps.clear();
            postUninstallBatchTotal = 0;
            postUninstallBatchCompleted = 0;
            postUninstallBatchResultCount = 0;
            postUninstallBatchSkipped = 0;

            updateQuarantineButton();
            return;
        }

        const ApplicationInfo removed =
            pendingPostUninstallLeftoverApps.takeFirst();

        const QString displayName =
            removed.name.isEmpty()
                ? removed.id
                : removed.name;

        const QString leftoverKey =
            removed.id.trimmed().isEmpty()
                ? displayName
                : removed.id.trimmed();

        activePostUninstallAppGroup =
            results
                ? new QTreeWidgetItem(results)
                : nullptr;

        if (activePostUninstallAppGroup) {
            activePostUninstallAppGroup->setText(
                0,
                QStringLiteral("%1 — Scanning…")
                    .arg(displayName));
            activePostUninstallAppGroup->setToolTip(
                0,
                QStringLiteral(
                    "Automatic Leftovers scan for %1.")
                    .arg(displayName));
            activePostUninstallAppGroup->setFlags(
                Qt::ItemIsEnabled |
                Qt::ItemIsSelectable);
            activePostUninstallAppGroup->setExpanded(true);
            activePostUninstallAppGroup->setSizeHint(
                0,
                QSize(0, 36));
        }

        scanLeftoversAsync(
            leftoverKey,
            leftoverSearchTermsForApplication(removed),
            true,
            displayName,
            true);
    }


    void scanLeftoversAsync(
        const QString &application,
        const QStringList &searchTerms = {},
        bool fromPostUninstallTransition = false,
        const QString &removedDisplayName = {},
        bool preserveExistingResults = false)
    {
        const QString query =
            application.trimmed();

        if (query.isEmpty())
            return;

        postUninstallLeftoverScan =
            fromPostUninstallTransition;
        postUninstallLeftoverDisplayName =
            removedDisplayName.trimmed();

        if (leftoverScanRunning ||
            leftoverHomeProcess ||
            leftoverSystemProcess ||
            !pendingLeftoverItems.isEmpty()) {

            stopLeftoverScan();
        }

        ++leftoverScanGeneration;
        const int generation =
            leftoverScanGeneration;

        leftoverScanRunning = true;
        currentApp = query;

        activeLeftoverSearchTerms =
            sanitizeLeftoverSearchTerms(
                searchTerms.isEmpty()
                    ? QStringList{query}
                    : searchTerms);

        if (activeLeftoverSearchTerms.isEmpty()) {
            leftoverScanRunning = false;

            scanProgress->setVisible(false);
            setSearchControlsForLeftoverScan(false);

            const QString skippedName =
                removedDisplayName.trimmed().isEmpty()
                    ? query
                    : removedDisplayName.trimmed();

            if (postUninstallBatchActive &&
                activePostUninstallAppGroup) {

                activePostUninstallAppGroup->setText(
                    0,
                    QStringLiteral("%1  (Scan skipped — identity too broad)")
                        .arg(skippedName));
                activePostUninstallAppGroup->setToolTip(
                    0,
                    QStringLiteral(
                        "TotalSweep did not scan this application because its available name/identity was too broad to search safely."));

                ++postUninstallBatchCompleted;
                ++postUninstallBatchSkipped;
                postUninstallLeftoverScan = false;
                postUninstallLeftoverDisplayName.clear();
                activePostUninstallAppGroup = nullptr;

                if (resultStatus) {
                    resultStatus->setText(
                        QStringLiteral(
                            "Skipped an unsafe broad Leftovers search. Continuing with the remaining removed applications..."));
                }

                QTimer::singleShot(
                    0,
                    this,
                    [this]() {
                        scanNextPostUninstallLeftover();
                    });

                return;
            }

            if (results) {
                if (!preserveExistingResults)
                    results->clear();

                results->setEmptyMessage(
                    QStringLiteral(
                        "This search is too broad to identify leftovers safely. "
                        "Use the application's full name, package/application ID, "
                        "or executable name."));
            }

            if (resultStatus) {
                resultStatus->setText(
                    QStringLiteral(
                        "Leftovers scan not started — the search term is too broad to use safely."));
            }

            postUninstallLeftoverScan = false;
            postUninstallLeftoverDisplayName.clear();
            return;
        }

        rebuildProtectedOtherApplicationRoots();

        if (leftoversSearch &&
            leftoversSearch->text().trimmed() != query) {

            const QSignalBlocker blocker(
                leftoversSearch);

            leftoversSearch->setText(query);
        }

        hits.clear();
        pendingLeftoverItems.clear();
        pendingLeftoverIndex = 0;

        setHoveredLeftoverItem(nullptr);
        pressedLeftoverItem = nullptr;

        if (!preserveExistingResults) {
            if (postUninstallBatchActive)
                clearPostUninstallLeftoverBatchState();

            results->clear();
            results->setEmptyMessage(
                QString(
                    "Scanning leftovers for \"%1\"…")
                    .arg(query));
        }

        homeScanResults.clear();
        systemScanResults.clear();

        completedScanProcesses = 0;

        scanProgress->setVisible(true);
        scanProgress->setRange(0, 100);
        scanProgress->setValue(5);

        quarantineSelectedBtn->setEnabled(false);
        setSearchControlsForLeftoverScan(true);

        resultStatus->setText(
            QString(
                "Scanning Leftovers for \"%1\"...")
                .arg(query));

        setCurrentPage(1);

        QProcess *process =
            new QProcess(this);

        leftoverHomeProcess = process;

        connect(
            process,
            &QProcess::readyReadStandardOutput,
            this,
            [this, process, generation]() {
                const QByteArray output =
                    process->readAllStandardOutput();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                homeScanResults +=
                    QString::fromLocal8Bit(output)
                        .split('\n', Qt::SkipEmptyParts);
            });

        connect(
            process,
            qOverload<int, QProcess::ExitStatus>(
                &QProcess::finished),
            this,
            [this, process, generation](
                int exitCode,
                QProcess::ExitStatus) {

                Q_UNUSED(exitCode);

                const QByteArray output =
                    process->readAllStandardOutput();

                if (leftoverHomeProcess == process)
                    leftoverHomeProcess = nullptr;

                process->deleteLater();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                homeScanResults +=
                    QString::fromLocal8Bit(output)
                        .split('\n', Qt::SkipEmptyParts);

                completedScanProcesses++;
                updateScanProgress();
                startSystemLeftoverScan(generation);
            });

        connect(
            process,
            &QProcess::errorOccurred,
            this,
            [this, process, generation](
                QProcess::ProcessError error) {

                if (error != QProcess::FailedToStart)
                    return;

                if (leftoverHomeProcess == process)
                    leftoverHomeProcess = nullptr;

                process->deleteLater();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                completedScanProcesses++;
                updateScanProgress();
                startSystemLeftoverScan(generation);
            });

        QStringList arguments{
            QDir::homePath(),
            QStringLiteral("-xdev"),
            QStringLiteral("(") ,
            QStringLiteral("-path"),
            totalSweepData(),
            QStringLiteral("-o"),
            QStringLiteral("-path"),
            QDir::homePath() +
                QStringLiteral("/.local/share/flatpak"),
            QStringLiteral(")"),
            QStringLiteral("-prune"),
            QStringLiteral("-o")
        };

        appendLeftoverNameExpression(
            arguments,
            activeLeftoverSearchTerms);

        process->start(
            QStringLiteral("find"),
            arguments);
    }


    void startSystemLeftoverScan(
        int generation)
    {
        if (!leftoverScanRunning ||
            generation != leftoverScanGeneration) {

            return;
        }

        QProcess *process =
            new QProcess(this);

        leftoverSystemProcess = process;

        connect(
            process,
            &QProcess::readyReadStandardOutput,
            this,
            [this, process, generation]() {
                const QByteArray output =
                    process->readAllStandardOutput();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                systemScanResults +=
                    QString::fromLocal8Bit(output)
                        .split('\n', Qt::SkipEmptyParts);
            });

        connect(
            process,
            qOverload<int, QProcess::ExitStatus>(
                &QProcess::finished),
            this,
            [this, process, generation](
                int exitCode,
                QProcess::ExitStatus) {

                Q_UNUSED(exitCode);

                const QByteArray output =
                    process->readAllStandardOutput();

                if (leftoverSystemProcess == process)
                    leftoverSystemProcess = nullptr;

                process->deleteLater();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                systemScanResults +=
                    QString::fromLocal8Bit(output)
                        .split('\n', Qt::SkipEmptyParts);

                completedScanProcesses++;
                updateScanProgress();
                finishLeftoverScan(generation);
            });

        connect(
            process,
            &QProcess::errorOccurred,
            this,
            [this, process, generation](
                QProcess::ProcessError error) {

                if (error != QProcess::FailedToStart)
                    return;

                if (leftoverSystemProcess == process)
                    leftoverSystemProcess = nullptr;

                process->deleteLater();

                if (generation != leftoverScanGeneration ||
                    !leftoverScanRunning) {
                    return;
                }

                completedScanProcesses++;
                updateScanProgress();
                finishLeftoverScan(generation);
            });

        QStringList arguments{
            QStringLiteral("/etc"),
            QStringLiteral("/opt"),
            QStringLiteral("/usr/local"),
            QStringLiteral("/var/lib"),
            QStringLiteral("/var/cache"),
            QStringLiteral("/var/log"),
            QStringLiteral("-xdev"),
            QStringLiteral("(") ,
            QStringLiteral("-path"),
            QStringLiteral("/var/lib/flatpak"),
            QStringLiteral("-o"),
            QStringLiteral("-path"),
            QStringLiteral("/var/cache/dnf"),
            QStringLiteral("-o"),
            QStringLiteral("-path"),
            QStringLiteral("/var/cache/libdnf5"),
            QStringLiteral("-o"),
            QStringLiteral("-path"),
            QStringLiteral("/var/lib/dnf"),
            QStringLiteral("-o"),
            QStringLiteral("-path"),
            QStringLiteral("/var/lib/PackageKit"),
            QStringLiteral(")"),
            QStringLiteral("-prune"),
            QStringLiteral("-o")
        };

        appendLeftoverNameExpression(
            arguments,
            activeLeftoverSearchTerms);

        process->start(
            QStringLiteral("find"),
            arguments);
    }


    void updateScanProgress()
    {
        if (!scanProgress)
            return;

        if (completedScanProcesses == 0)
            scanProgress->setValue(5);
        else if (completedScanProcesses == 1)
            scanProgress->setValue(45);
        else
            scanProgress->setValue(75);
    }


    void disposeLeftoverProcess(
        QProcess *&process)
    {
        if (!process)
            return;

        QProcess *oldProcess = process;
        process = nullptr;

        QObject::disconnect(
            oldProcess,
            nullptr,
            this,
            nullptr);

        if (oldProcess->state() !=
            QProcess::NotRunning) {

            connect(
                oldProcess,
                qOverload<int, QProcess::ExitStatus>(
                    &QProcess::finished),
                oldProcess,
                &QObject::deleteLater);

            oldProcess->kill();
        }
        else {
            oldProcess->deleteLater();
        }
    }


    void stopLeftoverScan()
    {
        ++leftoverScanGeneration;
        leftoverScanRunning = false;

        disposeLeftoverProcess(
            leftoverHomeProcess);

        disposeLeftoverProcess(
            leftoverSystemProcess);

        pendingLeftoverItems.clear();
        pendingLeftoverIndex = 0;

        if (scanProgress) {
            scanProgress->setVisible(false);
            scanProgress->setValue(0);
        }

        setSearchControlsForLeftoverScan(false);

        if (postUninstallBatchActive) {
            if (activePostUninstallAppGroup) {
                const QString cancelledName =
                    postUninstallLeftoverDisplayName.trimmed();

                activePostUninstallAppGroup->setText(
                    0,
                    cancelledName.isEmpty()
                        ? QStringLiteral("Scan cancelled")
                        : QStringLiteral("%1  (Scan cancelled)")
                            .arg(cancelledName));
            }

            clearPostUninstallLeftoverBatchState();
        }

        updateQuarantineButton();
    }


    void finishLeftoverScan(
        int generation)
    {
        if (!leftoverScanRunning ||
            generation != leftoverScanGeneration) {

            return;
        }

        scanProgress->setValue(75);
        resultStatus->setText(
            QStringLiteral(
                "Preparing Leftovers results..."));

        QMap<QString, QVector<Hit>> groups;
        QSet<QString> seen;

        const QStringList all =
            homeScanResults +
            systemScanResults;

        hits.clear();
        hits.reserve(all.size());

        for (const QString &path : all) {
            if (path.isEmpty() ||
                seen.contains(path) ||
                isTotalSweepManagedPath(path) ||
                isPackageManagerMetadataPath(path)) {

                continue;
            }

            seen.insert(path);

            const int risk =
                classify(path);

            const QString category =
                categoryFor(risk);

            const Hit hit{
                path,
                category,
                risk
            };

            hits.push_back(hit);
            groups[category].push_back(hit);
        }

        pendingLeftoverItems.clear();
        pendingLeftoverIndex = 0;

        const QStringList order = {
            "Confirmed Leftovers",
            "Review / Possible",
            "Danger — Possibly Unrelated"
        };

        results->setUpdatesEnabled(false);

        for (const QString &categoryName : order) {
            const QVector<Hit> categoryHits =
                groups.value(categoryName);

            if (categoryHits.isEmpty())
                continue;

            QStringList paths;
            paths.reserve(categoryHits.size());

            for (const Hit &hit : categoryHits)
                paths.append(hit.path);

            QTreeWidgetItem *categoryItem =
                addCategory(
                    categoryName,
                    paths,
                    postUninstallBatchActive
                        ? activePostUninstallAppGroup
                        : nullptr);

            for (const Hit &hit : categoryHits) {
                pendingLeftoverItems.push_back(
                    {
                        categoryItem,
                        hit.path,
                        hit.risk
                    });
            }
        }

        results->setUpdatesEnabled(true);

        if (pendingLeftoverItems.isEmpty()) {
            completeLeftoverScan(generation);
            return;
        }

        QTimer::singleShot(
            0,
            this,
            [this, generation]() {
                populateNextLeftoverBatch(generation);
            });
    }


    void populateNextLeftoverBatch(
        int generation)
    {
        if (!leftoverScanRunning ||
            generation != leftoverScanGeneration) {

            return;
        }

        constexpr int batchSize = 30;

        const int total =
            pendingLeftoverItems.size();

        const int end =
            qMin(
                pendingLeftoverIndex + batchSize,
                total);

        results->setUpdatesEnabled(false);

        for (int i = pendingLeftoverIndex;
             i < end;
             ++i) {

            const PendingLeftoverItem &pending =
                pendingLeftoverItems.at(i);

            addItem(
                pending.category,
                pending.path,
                pending.risk);
        }

        pendingLeftoverIndex = end;
        results->setUpdatesEnabled(true);
        results->viewport()->update();

        const int progress =
            total > 0
                ? 75 +
                    ((pendingLeftoverIndex * 24) / total)
                : 99;

        scanProgress->setValue(
            qMin(progress, 99));

        resultStatus->setText(
            QString(
                "Preparing Leftovers results... %1 of %2")
                .arg(pendingLeftoverIndex)
                .arg(total));

        if (pendingLeftoverIndex < total) {
            QTimer::singleShot(
                0,
                this,
                [this, generation]() {
                    populateNextLeftoverBatch(generation);
                });

            return;
        }

        completeLeftoverScan(generation);
    }


    void completeLeftoverScan(
        int generation)
    {
        if (!leftoverScanRunning ||
            generation != leftoverScanGeneration) {

            return;
        }

        leftoverScanRunning = false;

        pendingLeftoverItems.clear();
        pendingLeftoverIndex = 0;

        scanProgress->setValue(100);

        const QString completedApplication =
            postUninstallLeftoverDisplayName.isEmpty()
                ? currentApp
                : postUninstallLeftoverDisplayName;

        if (postUninstallBatchActive &&
            activePostUninstallAppGroup) {

            const int found =
                hits.size();

            postUninstallBatchResultCount +=
                found;
            ++postUninstallBatchCompleted;

            if (found == 0) {
                activePostUninstallAppGroup->setText(
                    0,
                    QStringLiteral("%1  (Nothing found)")
                        .arg(completedApplication));
                activePostUninstallAppGroup->setToolTip(
                    0,
                    QStringLiteral(
                        "TotalSweep scanned %1 and did not find any remaining leftovers.")
                        .arg(completedApplication));
                activePostUninstallAppGroup->setExpanded(false);
            }
            else {
                activePostUninstallAppGroup->setText(
                    0,
                    QStringLiteral("%1  (%2 %3)")
                        .arg(completedApplication)
                        .arg(found)
                        .arg(wordForCount(
                            found,
                            QStringLiteral("leftover"),
                            QStringLiteral("leftovers"))));
                activePostUninstallAppGroup->setToolTip(
                    0,
                    QStringLiteral(
                        "%1 leftover results found for %2.")
                        .arg(found)
                        .arg(completedApplication));
                activePostUninstallAppGroup->setExpanded(true);
            }

            postUninstallLeftoverScan = false;
            postUninstallLeftoverDisplayName.clear();
            activePostUninstallAppGroup = nullptr;

            scanProgress->setVisible(false);
            setSearchControlsForLeftoverScan(false);

            if (resultStatus) {
                resultStatus->setText(
                    QStringLiteral(
                        "Scanned %1 of %2 removed applications...")
                        .arg(postUninstallBatchCompleted)
                        .arg(postUninstallBatchTotal));
            }

            QTimer::singleShot(
                0,
                this,
                [this]() {
                    scanNextPostUninstallLeftover();
                });

            return;
        }

        const bool postUninstallEmpty =
            postUninstallLeftoverScan &&
            hits.isEmpty();

        if (postUninstallEmpty) {
            resultStatus->setText(
                completedApplication.trimmed().isEmpty()
                    ? QStringLiteral(
                        "Nothing else was found. TotalSweep did not find any remaining leftovers.")
                    : QStringLiteral(
                        "Nothing else was found. %1 was uninstalled and TotalSweep did not find any remaining leftovers.")
                        .arg(completedApplication));
        }
        else {
            resultStatus->setText(
                QString(
                    "Leftovers scan complete: %1 %2. "
                    "Confirmed results are selected by recommendation; "
                    "danger results are never selected automatically.")
                    .arg(hits.size())
                    .arg(wordForCount(
                        hits.size(),
                        QStringLiteral("result"),
                        QStringLiteral("results"))));
        }

        if (results) {
            if (postUninstallEmpty) {
                results->setEmptyMessage(
                    completedApplication.trimmed().isEmpty()
                        ? QStringLiteral(
                            "Nothing else was found — there are no additional leftovers to clean up.")
                        : QStringLiteral(
                            "Nothing else was found — no additional leftovers remain for %1.")
                            .arg(completedApplication));
            }
            else {
                results->setEmptyMessage(
                    hits.isEmpty()
                        ? QStringLiteral(
                            "No leftovers found for this search.")
                        : QString());
            }
        }

        postUninstallLeftoverScan = false;
        postUninstallLeftoverDisplayName.clear();

        scanProgress->setVisible(false);
        setSearchControlsForLeftoverScan(false);
        updateQuarantineButton();
    }

    QTreeWidgetItem *addCategory(
        const QString &name,
        const QStringList &paths,
        QTreeWidgetItem *parent = nullptr)
    {
        auto *category =
            parent
                ? new QTreeWidgetItem(parent)
                : new QTreeWidgetItem(results);

        category->setText(
            0,
            QString(
                "%1  (%2)")
            .arg(
                name)
            .arg(
                paths.size()));

        category->setFlags(
            category->flags() |
            Qt::ItemIsUserCheckable |
            Qt::ItemIsAutoTristate);

        category->setCheckState(
            0,
            Qt::Unchecked);

        category->setExpanded(
            true);

        category->setSizeHint(
            0,
            QSize(0, 34));

        category->setData(0, Qt::UserRole, paths.isEmpty() ? QString() : paths.first());

        return category;
    }

    void addItem(
        QTreeWidgetItem *category,
        const QString &path,
        int risk)
    {
        auto *item =
        new QTreeWidgetItem(
            category);

        QFileInfo info(path);

        item->setText(
            0,
            info.fileName().isEmpty()
            ? path
            : info.fileName());

        item->setText(
            1,
            path);
        item->setToolTip(
            1,
            path);

        QString type = QStringLiteral("Item");
        QIcon itemIcon;

        if (info.isSymLink()) {
            type = QStringLiteral("Symlink");
            itemIcon = monochromeSemanticIcon(
                {
                    QStringLiteral("emblem-symbolic-link"),
                    QStringLiteral("insert-link")
                },
                QStyle::SP_FileIcon);
        }
        else if (info.isDir()) {
            type = QStringLiteral("Folder");
            itemIcon = monochromeSemanticIcon(
                {
                    QStringLiteral("folder-symbolic"),
                    QStringLiteral("folder")
                },
                QStyle::SP_DirIcon);
        }
        else if (info.isFile()) {
            type = QStringLiteral("File");
            itemIcon = monochromeSemanticIcon(
                {
                    QStringLiteral("text-x-generic-symbolic"),
                    QStringLiteral("text-x-generic"),
                    QStringLiteral("unknown")
                },
                QStyle::SP_FileIcon);
        }
        else {
            itemIcon = monochromeSemanticIcon(
                {
                    QStringLiteral("unknown"),
                    QStringLiteral("help-about")
                },
                QStyle::SP_FileIcon);
        }

        item->setText(2, type);
        item->setIcon(0, itemIcon);
        item->setSizeHint(0, QSize(0, 38));

        if (info.isFile()) {
            item->setText(
                3,
                formatByteSize(info.size()));
        }
        else {
            item->setText(
                3,
                QStringLiteral("—"));
            if (info.isDir()) {
                item->setToolTip(
                    3,
                    QStringLiteral(
                        "Folder size is not calculated during the scan so Leftovers remains responsive."));
            }
        }

        const QDateTime modified = info.lastModified();
        item->setText(
            4,
            modified.isValid()
                ? modified.toString(QStringLiteral("yyyy-MM-dd HH:mm"))
                : QStringLiteral("Unknown"));

        const QString riskLabel =
            risk == 1
                ? QStringLiteral("Recommended")
                : (risk == 2
                    ? QStringLiteral("Review")
                    : QStringLiteral("Danger"));
        item->setText(5, riskLabel);
        item->setToolTip(
            5,
            risk == 1
                ? QStringLiteral("Strong match for application leftovers; selected automatically by recommendation.")
                : (risk == 2
                    ? QStringLiteral("Possible leftover; review before cleanup.")
                    : QStringLiteral("Possibly unrelated; never selected automatically.")));

        item->setFlags(
            item->flags() |
            Qt::ItemIsUserCheckable);

        item->setCheckState(
                0,
                autoSelectRecommendedLeftovers &&
                    risk == 1
                ? Qt::Checked
                : Qt::Unchecked);

        item->setData(
                0,
                Qt::UserRole,
                path);

        item->setData(
                0,
                Qt::UserRole + 1,
                risk);

        refreshSecondaryItemVisual(
            results,
            item,
            false);

    }


    QString currentLeftoverPath() const
    {
        if (!results)
            return {};

        QTreeWidgetItem *item =
            results->currentItem();

        if (!item ||
            item->childCount() > 0) {

            return {};
        }

        return item->data(
            0,
            Qt::UserRole)
            .toString()
            .trimmed();
    }


    QStringList selectedLeftoverActionPaths() const
    {
        QStringList paths;

        if (!results)
            return paths;

        QTreeWidgetItemIterator iterator(results);

        while (*iterator) {
            QTreeWidgetItem *item =
                *iterator;

            if (item &&
                item->childCount() == 0 &&
                item->data(
                    0,
                    Qt::UserRole + 1)
                    .isValid() &&
                item->checkState(0) == Qt::Checked) {

                const QString path =
                    item->data(
                        0,
                        Qt::UserRole)
                        .toString()
                        .trimmed();

                if (!path.isEmpty())
                    paths.append(path);
            }

            ++iterator;
        }

        paths.removeDuplicates();

        return paths;
    }

    void updateLeftoverContextActions()
    {
        if (!openLeftoverLocationBtn)
            return;

        openLeftoverLocationBtn->setEnabled(
            !currentLeftoverPath().isEmpty());
    }


    void openCurrentLeftoverLocation()
    {
        const QString path = currentLeftoverPath();
        if (!path.isEmpty())
            openLocation(path);
    }


    void openLocation(
        const QString &path)
    {
        QFileInfo info(path);

        const QString target =
        info.isDir()
        ? info.absoluteFilePath()
        : info.absolutePath();

        if (!QProcess::startDetached(
            "dolphin",
            {target})) {

            QProcess::startDetached(
                "xdg-open",
                {target});
            }
    }

    void deleteCategory(
        QTreeWidgetItem *category)
    {
        if (!category)
            return;

        QStringList paths;

        for (int i = 0;
             i < category->childCount();
             ++i) {

            auto *item =
                category->child(i);

            if (item->checkState(0) ==
                Qt::Checked) {

                paths.append(
                    item->data(
                        0,
                        Qt::UserRole)
                    .toString());
            }
        }

        quarantinePaths(paths);
    }

    void setRecommended()
    {
        if (!results)
            return;

        QTreeWidgetItemIterator iterator(results);

        while (*iterator) {
            QTreeWidgetItem *item =
                *iterator;

            if (item &&
                item->childCount() == 0 &&
                item->data(
                    0,
                    Qt::UserRole + 1)
                    .isValid()) {

                const int risk =
                    item->data(
                        0,
                        Qt::UserRole + 1)
                        .toInt();

                item->setCheckState(
                    0,
                    risk == 1
                        ? Qt::Checked
                        : Qt::Unchecked);
            }

            ++iterator;
        }

        updateQuarantineButton();
    }

    void setAll(bool value)
    {
        if (!results)
            return;

        QTreeWidgetItemIterator iterator(results);

        while (*iterator) {
            QTreeWidgetItem *item =
                *iterator;

            if (item &&
                item->childCount() == 0 &&
                item->data(
                    0,
                    Qt::UserRole + 1)
                    .isValid()) {

                item->setCheckState(
                    0,
                    value
                        ? Qt::Checked
                        : Qt::Unchecked);
            }

            ++iterator;
        }

        if (!value) {
            results->setCurrentItem(nullptr);
            setHoveredLeftoverItem(nullptr);
        }

        updateQuarantineButton();
    }

    void updateQuarantineButton()
    {
        if (!quarantineSelectedBtn)
            return;

        const bool canAct =
            !leftoverScanRunning &&
            !postUninstallBatchActive &&
            !selectedLeftoverActionPaths().isEmpty();

        quarantineSelectedBtn->setEnabled(canAct);

        updateLeftoverActionModeUi();
        updateLeftoverContextActions();
    }


    void quarantineOne(
        const QString &path)
    {
        quarantinePaths(
            {path});
    }

    void quarantineSelected()
    {
        quarantinePaths(
            selectedLeftoverActionPaths());
    }


    struct QuarantineMoveCandidate {
        QString source;
        QString destination;
        qint64 size = 0;
    };


    ProcessResult runBatchMovePairs(
        const QList<QuarantineMoveCandidate> &pairs,
        const QString &title,
        const QString &label)
    {
        if (pairs.isEmpty())
            return {true, true, 0, {}, {}};

        const QString script = QStringLiteral(
            "while [ \"$#\" -ge 2 ]; do "
            "src=\"$1\"; dst=\"$2\"; shift 2; "
            "parent=${dst%/*}; [ -n \"$parent\" ] || parent=/; "
            "mkdir -p -- \"$parent\" || exit $?; "
            "mv -- \"$src\" \"$dst\" || exit $?; "
            "done");

        QStringList args{
            QStringLiteral("-c"),
            script,
            QStringLiteral("totalsweep-batch-move")
        };
        for (const QuarantineMoveCandidate &pair : pairs)
            args << pair.source << pair.destination;

        return runProcessResponsive(
            this,
            title,
            label,
            QStringLiteral("/bin/sh"),
            args,
            600000);
    }


    void quarantinePaths(
        const QStringList &paths)
    {
        if (paths.isEmpty())
            return;

        if (!leftoverQuarantineEnabled()) {
            deleteLeftoverPathsPermanently(paths);
            return;
        }

        if (totalSweepWarning(
                this,
                QStringLiteral("Move to Quarantine"),
                QString(
                    "Move %1 selected %2 to TotalSweep Quarantine?\n\n%3 original %4 will be saved so %5 can be restored later.")
                    .arg(paths.size())
                    .arg(wordForCount(
                        paths.size(),
                        QStringLiteral("item"),
                        QStringLiteral("items")))
                    .arg(paths.size() == 1
                        ? QStringLiteral("Its")
                        : QStringLiteral("Their"))
                    .arg(wordForCount(
                        paths.size(),
                        QStringLiteral("location"),
                        QStringLiteral("locations")))
                    .arg(paths.size() == 1
                        ? QStringLiteral("it")
                        : QStringLiteral("they")),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No)
            != QMessageBox::Yes) {
            return;
        }

        const QString application = currentApp.trimmed().isEmpty()
            ? QStringLiteral("Leftovers")
            : currentApp.trimmed();
        const QString session = createQuarantineSessionPath(application);
        const QString created = QDateTime::currentDateTime().toString(Qt::ISODate);

        QJsonArray items;
        QStringList movedOriginals;
        QStringList movedDestinations;
        int successful = 0;
        int number = 0;
        QStringList failures;
        QList<QuarantineMoveCandidate> unprivilegedPending;

        auto recordMoved = [&](const QuarantineMoveCandidate &candidate) {
            QJsonObject object;
            object[QStringLiteral("original")] = candidate.source;
            object[QStringLiteral("quarantine")] = candidate.destination;
            object[QStringLiteral("size")] = static_cast<double>(candidate.size);
            items.append(object);
            movedOriginals.append(candidate.source);
            movedDestinations.append(candidate.destination);
            ++successful;
        };

        QSet<QString> seenPaths;
        for (const QString &path : paths) {
            const QString cleaned = QDir::cleanPath(path.trimmed());
            if (cleaned.isEmpty() || seenPaths.contains(cleaned))
                continue;
            seenPaths.insert(cleaned);

            if (isProtectedPermanentDeleteTarget(cleaned) ||
                isTotalSweepManagedPath(cleaned)) {
                failures.append(QStringLiteral("%1 — protected TotalSweep/system path refused").arg(cleaned));
                continue;
            }

            QFileInfo info(cleaned);
            if (!info.exists() && !info.isSymLink())
                continue;

            const QString destination = session + QStringLiteral("/item_%1")
                .arg(++number, 4, 10, QChar('0'));
            QDir().mkpath(QFileInfo(destination).absolutePath());

            QuarantineMoveCandidate candidate{cleaned, destination, info.size()};
            if (QFile::rename(cleaned, destination)) {
                recordMoved(candidate);
                continue;
            }

            if (QFileInfo(info.absolutePath()).isWritable()) {
                unprivilegedPending.append(candidate);
            }
            else {
                failures.append(
                    QStringLiteral(
                        "%1 — permission-restricted item left untouched; TotalSweep does not move root-managed files into user-profile Quarantine")
                        .arg(cleaned));
            }
        }

        if (!unprivilegedPending.isEmpty()) {
            const ProcessResult result = runBatchMovePairs(
                unprivilegedPending,
                QStringLiteral("Updating Quarantine"),
                QStringLiteral("Moving %1 selected %2 into Quarantine…")
                    .arg(unprivilegedPending.size())
                    .arg(wordForCount(
                        unprivilegedPending.size(),
                        QStringLiteral("item"),
                        QStringLiteral("items"))));
            for (const QuarantineMoveCandidate &candidate : unprivilegedPending) {
                if (!QFileInfo::exists(candidate.source) &&
                    QFileInfo::exists(candidate.destination)) {
                    recordMoved(candidate);
                }
                else {
                    failures.append(
                        QStringLiteral(
                            "%1 — move failed without privilege escalation; item left untouched")
                            .arg(candidate.source));
                }
            }
            if (result.standardError == QStringLiteral("Operation cancelled.")) {
                for (const QuarantineMoveCandidate &candidate : unprivilegedPending) {
                    const QFileInfo sourceInfo(candidate.source);
                    const QFileInfo destinationInfo(candidate.destination);
                    if ((sourceInfo.exists() || sourceInfo.isSymLink()) &&
                        !destinationInfo.exists()) {
                        failures.append(
                            QStringLiteral("%1 — operation cancelled")
                                .arg(candidate.source));
                    }
                }
            }
        }

        if (successful == 0) {
            QDir(session).removeRecursively();
            totalSweepWarning(
                this,
                QStringLiteral("Quarantine Failed"),
                failures.isEmpty()
                    ? QStringLiteral("No selected items could be moved into Quarantine.")
                    : failures.join('\n'));
            return;
        }

        QJsonObject metadata;
        metadata[QStringLiteral("schema")] = 2;
        metadata[QStringLiteral("kind")] = QStringLiteral("leftovers");
        metadata[QStringLiteral("application")] = application;
        metadata[QStringLiteral("appType")] = QStringLiteral("Leftovers");
        metadata[QStringLiteral("restoreMode")] = QStringLiteral("files");
        metadata[QStringLiteral("snapshotStatus")] = QStringLiteral("available");
        metadata[QStringLiteral("created")] = created;
        metadata[QStringLiteral("restored")] = false;
        metadata[QStringLiteral("items")] = items;

        if (!writeJsonObjectAtomic(
                session + QStringLiteral("/metadata.json"),
                metadata)) {
            const QStringList rollbackFailures =
                rollbackQuarantineMoves(
                    movedOriginals,
                    movedDestinations);
            if (rollbackFailures.isEmpty())
                QDir(session).removeRecursively();

            totalSweepCritical(
                this,
                QStringLiteral("Quarantine Rolled Back"),
                rollbackFailures.isEmpty()
                    ? QStringLiteral(
                        "TotalSweep could not save the Quarantine restore metadata, so all moved leftovers were returned to their original locations.")
                    : QStringLiteral(
                        "TotalSweep could not save the Quarantine restore metadata. Rollback was incomplete, so TotalSweep did not delete the remaining quarantined files. "
                        "They are preserved at:\n%1\n\n%2")
                        .arg(
                            session,
                            rollbackFailures.join(QLatin1Char('\n'))));
            return;
        }

        QJsonObject history;
        history[QStringLiteral("id")] = QFileInfo(session).fileName().section('_', 0, 2);
        history[QStringLiteral("kind")] = QStringLiteral("leftovers");
        history[QStringLiteral("application")] = application;
        history[QStringLiteral("session")] = session;
        history[QStringLiteral("items")] = static_cast<int>(items.size());
        history[QStringLiteral("created")] = created;
        history[QStringLiteral("appType")] = QStringLiteral("Leftovers");
        history[QStringLiteral("version")] = QString();
        history[QStringLiteral("restoreMode")] = QStringLiteral("files");
        appendHistoryObject(history);

        loadHistory();

        QString message = QStringLiteral("%1 %2 moved to Quarantine.")
            .arg(successful)
            .arg(wordForCount(
                successful,
                QStringLiteral("item"),
                QStringLiteral("items")));
        if (!failures.isEmpty()) {
            message += QStringLiteral("\n\n%1 %2 could not be moved and %3 left untouched.")
                .arg(failures.size())
                .arg(wordForCount(
                    failures.size(),
                    QStringLiteral("item"),
                    QStringLiteral("items")))
                .arg(failures.size() == 1
                    ? QStringLiteral("was")
                    : QStringLiteral("were"));
        }

        if (failures.isEmpty()) {
            showTransientInformation(
                QStringLiteral("Quarantine"),
                message,
                5000);
        }
        else {
            totalSweepInformation(
                this,
                QStringLiteral("Quarantine Results"),
                message);
        }

        refreshLeftoverResultsAfterRemoval(movedOriginals);
    }

    void applyQuarantineSearch()
    {
        committedQuarantineSearch =
            quarantineSearch
                ? quarantineSearch->text().trimmed()
                : QString();

        filterQuarantineHistory();
    }


    void filterQuarantineHistory()
    {
        if (!historyTree)
            return;

        const QString query =
            committedQuarantineSearch;

        historyTree->setUpdatesEnabled(false);

        int visibleItems = 0;

        for (int i = 0;
             i < historyTree->topLevelItemCount();
             ++i) {

            QTreeWidgetItem *item =
                historyTree->topLevelItem(i);

            if (!item)
                continue;

            const QString searchable =
                item->data(
                    0,
                    Qt::UserRole + 20)
                    .toString();

            const bool hidden =
                !query.isEmpty() &&
                !searchable.contains(
                    query,
                    Qt::CaseInsensitive);

            item->setHidden(hidden);

            if (!hidden)
                ++visibleItems;
        }

        if (visibleItems == 0) {
            historyTree->setEmptyMessage(
                query.isEmpty()
                    ? QStringLiteral(
                        "Quarantine is empty.")
                    : QStringLiteral(
                        "No matching quarantine entries found."));
        }
        else {
            historyTree->setEmptyMessage(
                QString());
        }

        historyTree->setUpdatesEnabled(true);
        historyTree->viewport()->update();
        updateQuarantineContextActions();
    }


    QString quarantineStatusFor(
        const QJsonObject &metadata) const
    {
        const QString state = metadata[QStringLiteral("restoreState")].toString();
        if (metadata[QStringLiteral("restored")].toBool(false) || state == QStringLiteral("restored"))
            return QStringLiteral("Restored");
        if (state == QStringLiteral("partial"))
            return QStringLiteral("Partially restored");

        const QString mode = metadata[QStringLiteral("restoreMode")].toString();
        const QString snapshot = metadata[QStringLiteral("snapshotStatus")].toString();
        if (mode == QStringLiteral("none"))
            return QStringLiteral("Recorded only — not restorable");
        if (mode == QStringLiteral("files"))
            return QStringLiteral("Exact files preserved");
        if (mode == QStringLiteral("rpm-local") || mode == QStringLiteral("flatpak-bundle"))
            return QStringLiteral("Exact version preserved");
        if (snapshot == QStringLiteral("disabled") && mode.endsWith(QStringLiteral("-metadata")))
            return QStringLiteral("Metadata only — package snapshot disabled");
        if (snapshot == QStringLiteral("metadata-only") || mode.endsWith(QStringLiteral("-metadata")))
            return QStringLiteral("Metadata only — exact payload unavailable");
        return QStringLiteral("Ready to restore");
    }


    void loadHistory()
    {
        setHoveredQuarantineItem(nullptr);
        pressedQuarantineItem = nullptr;
        historyTree->clear();

        const QString historyPath = totalSweepData() + QStringLiteral("/history.json");
        QJsonArray array = readJsonArray(historyPath);

        QJsonArray existingSessions;
        bool prunedHistory = false;
        for (const QJsonValue &value : array) {
            const QString session =
                value.toObject()[QStringLiteral("session")].toString().trimmed();
            if (isManagedQuarantineSession(session))
                existingSessions.append(value);
            else
                prunedHistory = true;
        }
        if (prunedHistory)
            array = existingSessions;

        QSet<QString> knownSessions;
        for (const QJsonValue &value : array) {
            const QString session =
                QDir::cleanPath(
                    value.toObject()[QStringLiteral("session")].toString());
            if (!session.isEmpty())
                knownSessions.insert(session);
        }

        bool repairedHistory = false;
        const QDir quarantineRoot(
            totalSweepData() + QStringLiteral("/quarantine"));
        const QStringList sessionNames = quarantineRoot.entryList(
            QDir::Dirs | QDir::NoDotAndDotDot,
            QDir::Name);

        for (const QString &sessionName : sessionNames) {
            const QString session =
                QDir::cleanPath(quarantineRoot.filePath(sessionName));

            if (!isManagedQuarantineSession(session) ||
                knownSessions.contains(session)) {
                continue;
            }

            const QJsonObject metadata =
                readManagedQuarantineMetadata(
                    session);
            if (metadata.isEmpty())
                continue;

            QJsonObject discovered;
            discovered[QStringLiteral("id")] = sessionName.section('_', 0, 2);
            discovered[QStringLiteral("kind")] = metadata[QStringLiteral("kind")].toString(QStringLiteral("leftovers"));
            discovered[QStringLiteral("application")] = metadata[QStringLiteral("application")].toString(QStringLiteral("Quarantine Item"));
            discovered[QStringLiteral("session")] = session;
            discovered[QStringLiteral("items")] = metadata[QStringLiteral("items")].toArray().size();
            discovered[QStringLiteral("created")] = metadata[QStringLiteral("created")].toString();
            discovered[QStringLiteral("appType")] = metadata[QStringLiteral("appType")].toString(QStringLiteral("Leftovers"));
            discovered[QStringLiteral("version")] = metadata[QStringLiteral("version")].toString();
            discovered[QStringLiteral("restoreMode")] = metadata[QStringLiteral("restoreMode")].toString(QStringLiteral("files"));
            array.append(discovered);
            knownSessions.insert(session);
            repairedHistory = true;
        }

        if (repairedHistory || prunedHistory)
            writeJsonArrayAtomic(historyPath, array);

        for (const QJsonValue &value : array) {
            const QJsonObject object = value.toObject();
            const QString session =
                QDir::cleanPath(
                    object[QStringLiteral("session")].toString());

            if (!isManagedQuarantineSession(session))
                continue;

            QJsonObject metadata =
                readManagedQuarantineMetadata(
                    session);

            if (metadata.isEmpty()) {
                metadata[QStringLiteral("application")] = object[QStringLiteral("application")].toString();
                metadata[QStringLiteral("created")] = object[QStringLiteral("created")].toString();
                metadata[QStringLiteral("kind")] = QStringLiteral("leftovers");
                metadata[QStringLiteral("appType")] = QStringLiteral("Leftovers");
                metadata[QStringLiteral("restoreMode")] = QStringLiteral("none");
                metadata[QStringLiteral("snapshotStatus")] = QStringLiteral("unavailable");
            }
            else if (!metadata.contains(QStringLiteral("kind"))) {
                metadata[QStringLiteral("kind")] = QStringLiteral("leftovers");
                metadata[QStringLiteral("appType")] = QStringLiteral("Leftovers");
                metadata[QStringLiteral("restoreMode")] = QStringLiteral("files");
                metadata[QStringLiteral("snapshotStatus")] = QStringLiteral("available");
            }

            const QString application = metadata[QStringLiteral("application")].toString(
                object[QStringLiteral("application")].toString());
            const QString type = metadata[QStringLiteral("appType")].toString(
                object[QStringLiteral("appType")].toString(QStringLiteral("Leftovers")));
            const QString created = metadata[QStringLiteral("created")].toString(
                object[QStringLiteral("created")].toString());
            const QString version = metadata[QStringLiteral("version")].toString(
                object[QStringLiteral("version")].toString());
            const QString mode = metadata[QStringLiteral("restoreMode")].toString(QStringLiteral("files"));
            const QString status = quarantineStatusFor(metadata);

            const QString restoreState =
                metadata[QStringLiteral("restoreState")]
                    .toString();
            const bool fullyRestored =
                metadata[QStringLiteral("restored")]
                    .toBool(false) ||
                restoreState == QStringLiteral("restored");

            if (fullyRestored)
                continue;

            const QString kind = metadata[QStringLiteral("kind")].toString(QStringLiteral("leftovers"));
            const QString entryKind = kind == QStringLiteral("application")
                ? QStringLiteral("Application")
                : QStringLiteral("Leftovers");

            QStringList dnfAdditionalPackages;
            QStringList dnfDependentPackages;
            QStringList dnfUnusedPackages;

            for (const QJsonValue &packageValue :
                 metadata[QStringLiteral("dnfAdditionalRemovedPackages")].toArray()) {
                const QString package = packageValue.toString().trimmed();
                if (!package.isEmpty())
                    dnfAdditionalPackages.append(package);
            }
            for (const QJsonValue &packageValue :
                 metadata[QStringLiteral("dnfDependentRemovedPackages")].toArray()) {
                const QString package = packageValue.toString().trimmed();
                if (!package.isEmpty())
                    dnfDependentPackages.append(package);
            }
            for (const QJsonValue &packageValue :
                 metadata[QStringLiteral("dnfUnusedDependencyPackages")].toArray()) {
                const QString package = packageValue.toString().trimmed();
                if (!package.isEmpty())
                    dnfUnusedPackages.append(package);
            }

            dnfAdditionalPackages.removeDuplicates();
            dnfDependentPackages.removeDuplicates();
            dnfUnusedPackages.removeDuplicates();

            QStringList originalLocations;
            qint64 storedBytes = 0;
            bool sizeKnown = false;

            const QJsonArray storedItems =
                metadata[QStringLiteral("items")].toArray();

            for (const QJsonValue &storedValue : storedItems) {
                const QJsonObject storedObject = storedValue.toObject();

                const QString original =
                    storedObject[QStringLiteral("original")]
                        .toString()
                        .trimmed();
                if (!original.isEmpty())
                    originalLocations.append(original);

                if (storedObject.contains(QStringLiteral("size"))) {
                    const double value =
                        storedObject[QStringLiteral("size")].toDouble(-1.0);
                    if (value >= 0.0) {
                        storedBytes += static_cast<qint64>(value);
                        sizeKnown = true;
                    }
                }
            }

            originalLocations.removeDuplicates();

            if (!sizeKnown) {
                const QString snapshotPath =
                    metadata[QStringLiteral("snapshotPath")]
                        .toString()
                        .trimmed();
                const QFileInfo snapshotInfo(snapshotPath);
                if (!snapshotPath.isEmpty() &&
                    snapshotInfo.exists() &&
                    snapshotInfo.isFile()) {

                    storedBytes = snapshotInfo.size();
                    sizeKnown = true;
                }
            }

            QString originalLocation;
            if (originalLocations.size() == 1) {
                originalLocation = originalLocations.first();
            }
            else if (originalLocations.size() > 1) {
                originalLocation = QStringLiteral("%1  (+%2 more)")
                    .arg(originalLocations.first())
                    .arg(originalLocations.size() - 1);
            }
            else if (mode.startsWith(QStringLiteral("rpm-")) ||
                     mode.startsWith(QStringLiteral("flatpak-"))) {
                if (mode.startsWith(QStringLiteral("rpm-")) &&
                    !dnfAdditionalPackages.isEmpty()) {
                    originalLocation = QStringLiteral("Package-managed • %1 RPM transaction")
                        .arg(dnfAdditionalPackages.size() + 1);
                }
                else {
                    originalLocation = QStringLiteral("Package-managed");
                }
            }
            else {
                originalLocation = QStringLiteral("—");
            }

            const QString storedSize = sizeKnown
                ? formatByteSize(storedBytes)
                : QStringLiteral("—");

            auto *item = new QTreeWidgetItem(historyTree);

            item->setFlags(
                item->flags() |
                Qt::ItemIsUserCheckable);

            item->setCheckState(
                0,
                Qt::Unchecked);

            item->setSizeHint(
                0,
                QSize(0, 38));

            const QIcon entryIcon =
                kind == QStringLiteral("application")
                    ? monochromeSemanticIcon(
                        {
                            QStringLiteral("application-x-executable-symbolic"),
                            QStringLiteral("application-x-executable"),
                            QStringLiteral("system-run")
                        },
                        QStyle::SP_ComputerIcon)
                    : monochromeSemanticIcon(
                        {
                            QStringLiteral("edit-clear-all"),
                            QStringLiteral("edit-clear"),
                            QStringLiteral("view-filter")
                        },
                        QStyle::SP_FileDialogDetailedView);

            item->setIcon(
                0,
                entryIcon);

            const QString displayedEntry =
                !dnfAdditionalPackages.isEmpty() && kind == QStringLiteral("application")
                    ? QStringLiteral("%1 — %2 (+%3 DNF %4)")
                        .arg(application, entryKind)
                        .arg(dnfAdditionalPackages.size())
                        .arg(wordForCount(
                            dnfAdditionalPackages.size(),
                            QStringLiteral("package"),
                            QStringLiteral("packages")))
                    : QStringLiteral("%1 — %2")
                        .arg(application, entryKind);

            const QString displayedType =
                !dnfAdditionalPackages.isEmpty() && mode.startsWith(QStringLiteral("rpm-"))
                    ? QStringLiteral("%1 • %2 RPM transaction")
                        .arg(type)
                        .arg(dnfAdditionalPackages.size() + 1)
                    : type;

            item->setText(0, displayedEntry);
            item->setText(1, displayedType);
            item->setText(2, originalLocation);
            item->setText(3, storedSize);
            item->setText(4, created);
            item->setText(5, status);

            if (!originalLocations.isEmpty()) {
                item->setToolTip(
                    2,
                    originalLocations.join(QLatin1Char('\n')));
            }

            QString entryToolTip = QStringLiteral("Application: %1\nEntry: %2")
                .arg(application, entryKind);
            if (!version.trimmed().isEmpty()) {
                entryToolTip += QStringLiteral("\nRemoved version: %1").arg(version);
            }

            if (!dnfAdditionalPackages.isEmpty()) {
                QSet<QString> dependentSet;
                for (const QString &package : dnfDependentPackages)
                    dependentSet.insert(package);

                QSet<QString> unusedSet;
                for (const QString &package : dnfUnusedPackages)
                    unusedSet.insert(package);

                QStringList transactionLines;
                for (const QString &package : dnfAdditionalPackages) {
                    const QString reason = dependentSet.contains(package)
                        ? QStringLiteral("depends on selection")
                        : (unusedSet.contains(package)
                            ? QStringLiteral("no longer needed according to DNF")
                            : QStringLiteral("included in DNF transaction"));
                    transactionLines.append(
                        QStringLiteral("%1 — %2").arg(package, reason));
                }

                entryToolTip += QStringLiteral(
                    "\n\nDNF also removed %1 additional %2. "
                    "These are tracked with this application transaction, not as filesystem leftovers or separate snapshots. "
                    "Restoring the application lets DNF resolve the dependencies it needs; packages that were already unneeded may not all be reinstalled automatically.\n%3")
                    .arg(dnfAdditionalPackages.size())
                    .arg(wordForCount(
                        dnfAdditionalPackages.size(),
                        QStringLiteral("package"),
                        QStringLiteral("packages")))
                    .arg(transactionLines.join(QLatin1Char('\n')));

                item->setToolTip(1, transactionLines.join(QLatin1Char('\n')));
                item->setToolTip(2, entryToolTip);
            }

            item->setToolTip(0, entryToolTip);

            const QString snapshotWarning =
                metadata[QStringLiteral("snapshotWarning")].toString().trimmed();
            if (!snapshotWarning.isEmpty())
                item->setToolTip(5, snapshotWarning);

            item->setData(
                0,
                Qt::UserRole + 20,
                application + QLatin1Char(' ') + entryKind + QLatin1Char(' ') + displayedType + QLatin1Char(' ') +
                originalLocations.join(QLatin1Char(' ')) + QLatin1Char(' ') +
                dnfAdditionalPackages.join(QLatin1Char(' ')) + QLatin1Char(' ') +
                storedSize + QLatin1Char(' ') + created + QLatin1Char(' ') +
                version + QLatin1Char(' ') + status + QLatin1Char(' ') + session);

            item->setData(0, Qt::UserRole + 21, session);
            item->setData(0, Qt::UserRole + 22, mode);
            item->setData(0, Qt::UserRole + 23, kind);
            item->setData(0, Qt::UserRole + 24,
                metadata[QStringLiteral("restored")].toBool(false));
            item->setData(0, Qt::UserRole + 25, application);
            item->setData(0, Qt::UserRole + 26, storedItems.size());
            item->setData(0, Qt::UserRole + 27, entryKind);
            item->setData(0, Qt::UserRole + 28, version);

            refreshSecondaryItemVisual(
                historyTree,
                item,
                false);
        }

        filterQuarantineHistory();
        updateQuarantineContextActions();
    }


    QList<QTreeWidgetItem *> selectedQuarantineItems() const
    {
        QList<QTreeWidgetItem *> selected;

        if (!historyTree)
            return selected;

        for (int i = 0;
             i < historyTree->topLevelItemCount();
             ++i) {

            QTreeWidgetItem *item =
                historyTree->topLevelItem(i);

            if (item &&
                item->checkState(0) == Qt::Checked) {

                selected.append(item);
            }
        }

        return selected;
    }


    void clearQuarantineSelection()
    {
        if (!historyTree)
            return;

        for (int i = 0;
             i < historyTree->topLevelItemCount();
             ++i) {

            QTreeWidgetItem *item =
                historyTree->topLevelItem(i);

            if (item &&
                item->checkState(0) != Qt::Unchecked) {

                item->setCheckState(
                    0,
                    Qt::Unchecked);
            }
        }

        historyTree->setCurrentItem(nullptr);
        setHoveredQuarantineItem(nullptr);
        updateQuarantineContextActions();
    }


    QString selectedQuarantineSession() const
    {
        const QList<QTreeWidgetItem *> selected = selectedQuarantineItems();
        if (selected.size() != 1 || !selected.first())
            return {};
        return selected.first()->data(0, Qt::UserRole + 21).toString();
    }


    void updateQuarantineContextActions()
    {
        if (!historyTree || !clearQuarantineSelectionBtn ||
            !openQuarantineBtn || !restoreQuarantineBtn ||
            !deleteQuarantineBtn)
            return;

        const QList<QTreeWidgetItem *> selected = selectedQuarantineItems();
        const int count = selected.size();

        clearQuarantineSelectionBtn->setEnabled(count > 0);
        openQuarantineBtn->setEnabled(
            count == 1 &&
            isManagedQuarantineSession(
                selectedQuarantineSession()));
        deleteQuarantineBtn->setEnabled(count > 0);
        deleteQuarantineBtn->setText(count > 1
            ? QStringLiteral("Delete Permanently (%1)").arg(count)
            : QStringLiteral("Delete Permanently"));

        bool restorable = false;
        QString restoreLabel = QStringLiteral("Restore Selected");
        if (count == 1 && selected.first()) {
            const QString mode = selected.first()->data(0, Qt::UserRole + 22).toString();
            const QString kind = selected.first()->data(0, Qt::UserRole + 23).toString();
            const bool restored = selected.first()->data(0, Qt::UserRole + 24).toBool();
            restorable = !restored && mode != QStringLiteral("none") && !mode.isEmpty();
            restoreLabel = kind == QStringLiteral("application")
                ? QStringLiteral("Restore Application")
                : QStringLiteral("Restore Leftovers");
        }
        else if (count > 1) {
            restoreLabel = QStringLiteral("Restore One Entry");
        }

        restoreQuarantineBtn->setText(restoreLabel);
        restoreQuarantineBtn->setEnabled(count == 1 && restorable);
        updateQuarantineInfoLabel();
    }


    void openSelectedQuarantine()
    {
        const QString session = selectedQuarantineSession();
        if (!isManagedQuarantineSession(session)) {
            totalSweepWarning(
                this,
                QStringLiteral("Open Quarantine Failed"),
                QStringLiteral(
                    "The selected Quarantine session is outside TotalSweep's managed Quarantine storage or is not a safe session directory."));
            return;
        }

        QProcess::startDetached(
            QStringLiteral("dolphin"),
            {session});
    }


    QString verifiedRpmSnapshotIdentity(
        const QString &snapshot,
        const QString &expectedHash) const
    {
        const QString normalizedHash =
            expectedHash.trimmed().toLower();

        if (!isManagedSnapshotPath(
                snapshot,
                QStringLiteral("rpm")) ||
            !isSafeSha256Token(normalizedHash) ||
            sha256File(snapshot) != normalizedHash) {
            return {};
        }

        if (!commandSucceeds(
                QStringLiteral("/usr/bin/rpmkeys"),
                {
                    QStringLiteral("--define"),
                    QStringLiteral("_pkgverify_level all"),
                    QStringLiteral("--checksig"),
                    snapshot
                },
                30000)) {
            return {};
        }

        const QStringList identities = runCommand(
            QStringLiteral("/usr/bin/rpm"),
            {
                QStringLiteral("--define"),
                QStringLiteral("_pkgverify_level all"),
                QStringLiteral("-qp"),
                QStringLiteral("--qf"),
                QStringLiteral("%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"),
                snapshot
            },
            30000);

        if (identities.size() != 1)
            return {};

        const QString identity =
            identities.first().trimmed();

        return isSafeRpmNevraToken(identity)
            ? identity
            : QString();
    }


    void restoreSelectedQuarantine()
    {
        const QList<QTreeWidgetItem *> selected = selectedQuarantineItems();
        const QString session = selectedQuarantineSession();
        if (selected.size() != 1 ||
            !selected.first()) {
            return;
        }

        if (!isManagedQuarantineSession(session)) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The selected Quarantine session is outside TotalSweep's managed Quarantine storage or is not a safe session directory."));
            return;
        }

        QTreeWidgetItem *item = selected.first();
        const QString application =
            item->data(0, Qt::UserRole + 25).toString();
        const QString kind =
            item->data(0, Qt::UserRole + 23).toString();
        const QString entryKind =
            item->data(0, Qt::UserRole + 27).toString();
        const QString mode =
            item->data(0, Qt::UserRole + 22).toString();
        const int itemCount =
            item->data(0, Qt::UserRole + 26).toInt();

        QMessageBox confirm(this);
        confirm.setIcon(QMessageBox::Information);
        confirm.setWindowTitle(QStringLiteral("Confirm Restore"));
        confirm.setText(
            QStringLiteral("<b>Restore %1 — %2?</b>")
                .arg(
                    application.toHtmlEscaped(),
                    entryKind.toHtmlEscaped()));
        confirm.setTextFormat(Qt::RichText);

        const QJsonObject restoreMetadata =
            readManagedQuarantineMetadata(session);
        QStringList restoreDetails;

        if (mode == QStringLiteral("files") &&
            !restoreMetadata.isEmpty()) {
            const QJsonArray restoreItems =
                restoreMetadata[QStringLiteral("items")].toArray();

            restoreDetails.append(
                QStringLiteral("Restore destinations:"));

            for (const QJsonValue &value : restoreItems) {
                const QString destinationRaw =
                    value.toObject()[QStringLiteral("original")]
                        .toString()
                        .trimmed();
                const QString destination =
                    destinationRaw.isEmpty()
                        ? QString()
                        : QDir::cleanPath(destinationRaw);

                if (!destination.isEmpty())
                    restoreDetails.append(destination);
            }
        }
        else if (mode.startsWith(QStringLiteral("rpm-")) &&
                 !restoreMetadata.isEmpty()) {
            const QString savedAppId =
                restoreMetadata[QStringLiteral("appId")]
                    .toString()
                    .trimmed();
            const QString savedIdentity =
                restoreMetadata[QStringLiteral("exactIdentity")]
                    .toString()
                    .trimmed();

            restoreDetails
                << QStringLiteral("RPM package: %1")
                    .arg(savedAppId)
                << QStringLiteral("Saved exact identity: %1")
                    .arg(savedIdentity);

            if (mode == QStringLiteral("rpm-local")) {
                const QString snapshot =
                    restoreMetadata[QStringLiteral("snapshotPath")]
                        .toString();
                const QString expectedHash =
                    restoreMetadata[QStringLiteral("snapshotSha256")]
                        .toString()
                        .trimmed();
                const QString liveIdentity =
                    verifiedRpmSnapshotIdentity(
                        snapshot,
                        expectedHash);

                if (!liveIdentity.isEmpty()) {
                    restoreDetails
                        << QStringLiteral(
                            "Preserved RPM preflight: SHA-256 plus trusted signature/digests verified")
                        << QStringLiteral(
                            "Live verified payload identity: %1")
                            .arg(liveIdentity);

                    if (liveIdentity != savedIdentity ||
                        !liveIdentity.startsWith(
                            savedAppId + QLatin1Char('-'))) {
                        restoreDetails << QStringLiteral(
                            "WARNING: the verified payload does not match the saved package metadata; privileged local restore will be refused.");
                    }
                }
                else {
                    restoreDetails << QStringLiteral(
                        "Preserved RPM preflight: not currently trusted/valid; TotalSweep will not install this local payload with administrator privileges.");
                }
            }
        }
        else if (mode.startsWith(QStringLiteral("flatpak-")) &&
                 !restoreMetadata.isEmpty()) {
            restoreDetails
                << QStringLiteral("Flatpak ID: %1")
                    .arg(restoreMetadata[QStringLiteral("appId")].toString())
                << QStringLiteral("Scope: %1")
                    .arg(restoreMetadata[QStringLiteral("flatpakScope")].toString())
                << QStringLiteral("Saved commit: %1")
                    .arg(restoreMetadata[QStringLiteral("flatpakCommit")].toString());
        }

        if (kind == QStringLiteral("application")) {
            QString method = QStringLiteral("TotalSweep will use the saved application restore method.");
            if (mode == QStringLiteral("files")) {
                method = QStringLiteral("TotalSweep will return the preserved application files to their original locations. Review the exact destinations in Details before continuing.");
            }
            else if (mode == QStringLiteral("rpm-local")) {
                method = QStringLiteral(
                    "TotalSweep will use the preserved exact RPM only if its SHA-256, trusted RPM signature/digests, package name, and exact identity pass verification again immediately before the administrator install. Otherwise an approved fallback choice may appear. Review Details before continuing.");
            }
            else if (mode == QStringLiteral("flatpak-bundle")) {
                const QString scope =
                    restoreMetadata[QStringLiteral("flatpakScope")]
                        .toString();
                method = scope == QStringLiteral("system")
                    ? QStringLiteral(
                        "For security, TotalSweep will not elevate the preserved user-writable Flatpak bundle into the system installation. An approved saved-remote/current-version fallback may appear instead. Review Details before continuing.")
                    : QStringLiteral(
                        "TotalSweep will try the preserved exact user-scope Flatpak bundle first. Review the saved package identity in Details before continuing.");
            }
            else if (mode.endsWith(QStringLiteral("-metadata"))) {
                method = QStringLiteral("TotalSweep will try the saved package version; a fallback choice may appear if it is unavailable. Review the saved package identity in Details before continuing.");
            }
            confirm.setInformativeText(method);
        }
        else {
            confirm.setInformativeText(
                QStringLiteral("%1 %2 will be returned to their original locations. Existing destination files are left untouched. Review the exact destinations in Details before continuing.")
                    .arg(itemCount)
                    .arg(wordForCount(
                        itemCount,
                        QStringLiteral("file"),
                        QStringLiteral("files"))));
        }

        if (!restoreDetails.isEmpty())
            confirm.setDetailedText(restoreDetails.join(QLatin1Char('\n')));

        QPushButton *restoreButton =
            confirm.addButton(QStringLiteral("Restore"), QMessageBox::AcceptRole);
        QPushButton *cancelButton = confirm.addButton(QMessageBox::Cancel);
        confirm.setDefaultButton(cancelButton);
        prepareMessageBox(confirm);
        confirm.exec();

        if (confirm.clickedButton() != restoreButton)
            return;

        restoreSession(session);
        loadHistory();
    }


    QSet<QString> referencedSnapshotPathsExcept(
        const QSet<QString> &excludedSessions) const
    {
        QSet<QString> referenced;
        const QDir quarantineRoot(totalSweepData() + QStringLiteral("/quarantine"));
        const QStringList sessions = quarantineRoot.entryList(
            QDir::Dirs | QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString &name : sessions) {
            const QString session =
                QDir::cleanPath(
                    quarantineRoot.filePath(name));

            if (excludedSessions.contains(session) ||
                !isManagedQuarantineSession(session)) {
                continue;
            }

            const QJsonObject metadata =
                readManagedQuarantineMetadata(
                    session);

            const QString snapshotRaw =
                metadata[QStringLiteral("snapshotPath")].toString().trimmed();

            if (isManagedSnapshotPath(snapshotRaw))
                referenced.insert(QDir::cleanPath(snapshotRaw));
        }
        return referenced;
    }


    void removeSnapshotFromCacheIndex(const QString &snapshotPath)
    {
        QJsonObject root = readJsonObject(cacheIndexPath());
        bool changed = false;
        for (const QString &groupName : {QStringLiteral("rpm"), QStringLiteral("flatpak")}) {
            QJsonObject group = root[groupName].toObject();
            const QStringList keys = group.keys();
            for (const QString &key : keys) {
                if (QDir::cleanPath(group[key].toObject()[QStringLiteral("path")].toString()) ==
                    QDir::cleanPath(snapshotPath)) {
                    group.remove(key);
                    changed = true;
                }
            }
            root[groupName] = group;
        }
        if (changed)
            writeJsonObjectAtomic(cacheIndexPath(), root);
    }


    void deleteSelectedQuarantine()
    {
        const QList<QTreeWidgetItem *> selected = selectedQuarantineItems();
        if (selected.isEmpty())
            return;

        QSet<QString> sessions;
        QSet<QString> snapshotCandidates;
        for (QTreeWidgetItem *item : selected) {
            if (!item)
                continue;
            const QString session = QDir::cleanPath(
                item->data(0, Qt::UserRole + 21).toString());

            if (!isManagedQuarantineSession(session))
                continue;

            sessions.insert(session);

            const QJsonObject metadata =
                readManagedQuarantineMetadata(
                    session);

            const QString snapshotRaw =
                metadata[QStringLiteral("snapshotPath")].toString().trimmed();

            if (isManagedSnapshotPath(snapshotRaw))
                snapshotCandidates.insert(QDir::cleanPath(snapshotRaw));
        }
        if (sessions.isEmpty())
            return;

        if (totalSweepWarning(
                this,
                QStringLiteral("Delete Quarantine Entries Permanently"),
                QStringLiteral(
                    "Delete %1 Quarantine %2 permanently?\n\n"
                    "The saved restore data will be removed and cannot be recovered.")
                    .arg(sessions.size())
                    .arg(sessions.size() == 1 ? QStringLiteral("entry") : QStringLiteral("entries")),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes) {
            return;
        }

        QSet<QString> deletedSessions;

        for (const QString &session : sessions) {
            QDir dir(session);
            if (!dir.exists() || dir.removeRecursively())
                deletedSessions.insert(session);
        }

        QStringList failures;
        for (const QString &session : sessions) {
            if (!deletedSessions.contains(session))
                failures.append(session);
        }

        if (!deletedSessions.isEmpty()) {
            const QString historyPath = totalSweepData() + QStringLiteral("/history.json");
            const QJsonArray oldHistory = readJsonArray(historyPath);
            QJsonArray newHistory;
            for (const QJsonValue &value : oldHistory) {
                const QString session = QDir::cleanPath(
                    value.toObject()[QStringLiteral("session")].toString());
                if (!deletedSessions.contains(session))
                    newHistory.append(value);
            }
            writeJsonArrayAtomic(historyPath, newHistory);

            const QSet<QString> references =
                referencedSnapshotPathsExcept({});

            for (const QString &snapshot : snapshotCandidates) {
                if (references.contains(snapshot) ||
                    !isManagedSnapshotPath(snapshot)) {
                    continue;
                }

                const QString clean =
                    QDir::cleanPath(snapshot);

                const bool removed =
                    !QFileInfo::exists(clean) ||
                    QFile::remove(clean);

                if (removed &&
                    !QFileInfo::exists(clean)) {
                    removeSnapshotFromCacheIndex(clean);
                }
            }
        }

        loadHistory();

        QString message = QStringLiteral("%1 Quarantine entr%2 deleted permanently.")
            .arg(deletedSessions.size())
            .arg(deletedSessions.size() == 1 ? QStringLiteral("y") : QStringLiteral("ies"));
        if (!failures.isEmpty()) {
            message += QStringLiteral("\n\n%1 entr%2 could not be deleted and remain in Quarantine.")
                .arg(failures.size())
                .arg(failures.size() == 1 ? QStringLiteral("y") : QStringLiteral("ies"));
        }
        if (failures.isEmpty()) {
            showTransientInformation(
                QStringLiteral("Quarantine"),
                message,
                5000);
        }
        else {
            totalSweepInformation(
                this,
                QStringLiteral("Quarantine Cleanup Results"),
                message);
        }
    }


    void saveRestoreState(
        const QString &session,
        QJsonObject metadata,
        const QString &state,
        const QString &summary)
    {
        if (!isManagedQuarantineSession(session))
            return;

        metadata[QStringLiteral("restored")] = state == QStringLiteral("restored");
        metadata[QStringLiteral("restoreState")] = state;
        metadata[QStringLiteral("lastRestoreAt")] = QDateTime::currentDateTime().toString(Qt::ISODate);
        metadata[QStringLiteral("lastRestoreSummary")] = summary;
        writeJsonObjectAtomic(session + QStringLiteral("/metadata.json"), metadata);
    }


    bool restoreFileSession(
        const QString &session,
        QJsonObject metadata)
    {
        if (!isManagedQuarantineSession(session)) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The Quarantine session is outside TotalSweep's managed Quarantine storage or is not a safe session directory."));
            return false;
        }

        const QJsonArray items = metadata[QStringLiteral("items")].toArray();
        int restored = 0;
        int existing = 0;
        int alreadyRestored = 0;
        int missing = 0;
        int failed = 0;
        QStringList failures;
        QList<QuarantineMoveCandidate> unprivilegedPending;

        const QString cleanSession = QDir::cleanPath(session);
        auto recordFailure = [&](const QString &destination, const QString &reason) {
            ++failed;
            failures.append(QStringLiteral("%1 — %2").arg(destination, reason));
        };

        for (const QJsonValue &value : items) {
            const QJsonObject object = value.toObject();
            const QString sourceRaw =
                object[QStringLiteral("quarantine")].toString().trimmed();
            const QString destinationRaw =
                object[QStringLiteral("original")].toString().trimmed();
            const QString source = sourceRaw.isEmpty()
                ? QString()
                : QDir::cleanPath(sourceRaw);
            const QString destination = destinationRaw.isEmpty()
                ? QString()
                : QDir::cleanPath(destinationRaw);

            if (source.isEmpty() || destination.isEmpty() ||
                !source.startsWith(cleanSession + QLatin1Char('/')) ||
                !QDir::isAbsolutePath(destination) ||
                isProtectedPermanentDeleteTarget(destination)) {
                recordFailure(destination.isEmpty() ? QStringLiteral("<invalid destination>") : destination,
                    QStringLiteral("invalid or unsafe restore metadata"));
                continue;
            }

            const auto decision = totalsweep_restore::decideFileRestore(
                std::filesystem::u8path(source.toUtf8().constData()),
                std::filesystem::u8path(destination.toUtf8().constData()));

            if (decision == totalsweep_restore::FileRestoreDecision::SkipExistingDestination) {
                ++existing;
                continue;
            }
            if (decision == totalsweep_restore::FileRestoreDecision::AlreadyRestored) {
                ++alreadyRestored;
                continue;
            }
            if (decision == totalsweep_restore::FileRestoreDecision::MissingSource) {
                ++missing;
                continue;
            }
            if (decision == totalsweep_restore::FileRestoreDecision::FilesystemError) {
                recordFailure(
                    destination,
                    QStringLiteral("filesystem status check failed"));
                continue;
            }

            if (!isManagedQuarantineSourceForMove(
                    source,
                    session)) {
                recordFailure(
                    destination,
                    QStringLiteral("Quarantine source resolves outside the managed session"));
                continue;
            }

            const QFileInfo sourceInfo(source);
            const QString destinationParentPath = QFileInfo(destination).absolutePath();
            QDir().mkpath(destinationParentPath);

            if (!QFileInfo(sourceInfo.absolutePath()).isWritable() ||
                !QFileInfo(destinationParentPath).isWritable()) {
                recordFailure(
                    destination,
                    QStringLiteral(
                        "administrator-level file restore refused; user-profile Quarantine is not a trusted root restore source"));
                continue;
            }

            QuarantineMoveCandidate candidate{source, destination, sourceInfo.size()};
            if (QFile::rename(source, destination)) {
                ++restored;
                continue;
            }

            unprivilegedPending.append(candidate);
        }

        if (!unprivilegedPending.isEmpty()) {
            const ProcessResult result = runBatchMovePairs(
                unprivilegedPending,
                QStringLiteral("Restoring Quarantined Files"),
                QStringLiteral("Restoring %1 selected %2…")
                    .arg(unprivilegedPending.size())
                    .arg(wordForCount(
                        unprivilegedPending.size(),
                        QStringLiteral("file"),
                        QStringLiteral("files"))));

            for (const QuarantineMoveCandidate &candidate : unprivilegedPending) {
                if (!QFileInfo::exists(candidate.source) && QFileInfo::exists(candidate.destination)) {
                    ++restored;
                }
                else {
                    recordFailure(
                        candidate.destination,
                        result.standardError.trimmed().isEmpty()
                            ? QStringLiteral("restore move failed without privilege escalation")
                            : result.standardError.trimmed());
                }
            }
        }

        const bool complete = items.size() > 0 &&
            (restored + alreadyRestored) == static_cast<int>(items.size());
        const bool partial = restored > 0 || alreadyRestored > 0 || existing > 0;
        const QString state = complete
            ? QStringLiteral("restored")
            : (partial ? QStringLiteral("partial") : QStringLiteral("ready"));

        const QString summary = QString(
            "%1 restored, %2 already restored, %3 destination %4 left untouched, "
            "%5 missing snapshot %6, %7 failed.")
            .arg(restored)
            .arg(alreadyRestored)
            .arg(existing)
            .arg(wordForCount(
                existing,
                QStringLiteral("collision"),
                QStringLiteral("collisions")))
            .arg(missing)
            .arg(wordForCount(
                missing,
                QStringLiteral("item"),
                QStringLiteral("items")))
            .arg(failed);
        saveRestoreState(session, metadata, state, summary);

        QString message = summary;
        if (!failures.isEmpty())
            message += QStringLiteral("\n\n") + failures.join('\n');

        totalSweepInformation(
            this,
            complete ? QStringLiteral("Restore Complete") : QStringLiteral("Restore Results"),
            message);
        return complete;
    }


    QString currentRpmNevra(const QString &packageId) const
    {
        const QStringList lines = runCommand(
            QStringLiteral("rpm"),
            {
                QStringLiteral("-q"),
                QStringLiteral("--qf"),
                QStringLiteral("%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"),
                packageId
            },
            10000);
        return lines.isEmpty() ? QString() : lines.first().trimmed();
    }


    bool restoreCurrentRpm(
        const QString &session,
        QJsonObject metadata)
    {
        const QString appId =
            metadata[QStringLiteral("appId")].toString().trimmed();

        if (!isManagedQuarantineSession(session) ||
            !isSafeRpmNameToken(appId)) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The saved RPM restore metadata is invalid or outside TotalSweep's managed storage."));
            return false;
        }
        const ProcessResult result = runProcessResponsive(
            this,
            QStringLiteral("Reinstalling Current Version"),
            QStringLiteral("Installing the current repository version of %1…")
                .arg(metadata[QStringLiteral("application")].toString()),
            QStringLiteral("pkexec"),
            {QStringLiteral("/usr/bin/dnf"), QStringLiteral("install"), QStringLiteral("-y"), appId},
            600000);

        if (!result.success) {
            totalSweepWarning(this, QStringLiteral("Restore Failed"),
                result.standardError.isEmpty() ? QStringLiteral("DNF could not install the current version.") : result.standardError);
            return false;
        }

        metadata[QStringLiteral("restoredVersionMode")] = QStringLiteral("current");
        saveRestoreState(session, metadata, QStringLiteral("restored"), QStringLiteral("Current repository version installed."));
        return true;
    }


    bool restoreRpmSession(
        const QString &session,
        QJsonObject metadata)
    {
        const QString appId =
            metadata[QStringLiteral("appId")].toString().trimmed();
        const QString expected =
            metadata[QStringLiteral("exactIdentity")].toString().trimmed();

        if (!isManagedQuarantineSession(session) ||
            !isSafeRpmNameToken(appId) ||
            (!expected.isEmpty() &&
             (!isSafeRpmNevraToken(expected) ||
              !expected.startsWith(appId + QLatin1Char('-'))))) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The saved RPM restore metadata is invalid or outside TotalSweep's managed storage."));
            return false;
        }

        const QString snapshot =
            metadata[QStringLiteral("snapshotPath")].toString();
        const QString expectedHash =
            metadata[QStringLiteral("snapshotSha256")].toString().trimmed();

        bool exactRestored = false;
        QString exactError;

        const bool localSnapshotCandidate =
            !expected.isEmpty() &&
            isManagedSnapshotPath(snapshot, QStringLiteral("rpm")) &&
            isSafeSha256Token(expectedHash) &&
            sha256File(snapshot) == expectedHash;

        if (localSnapshotCandidate) {
            const QString script = QStringLiteral(
                "set -eu; "
                "expected_nevra=\"$1\"; expected_hash=\"$2\"; expected_name=\"$3\"; "
                "umask 077; "
                "tmp=$(/usr/bin/mktemp -d /var/tmp/totalsweep-rpm-restore.XXXXXX); "
                "trap '/usr/bin/rm -rf -- \"$tmp\"' EXIT HUP INT TERM; "
                "pkg=\"$tmp/package.rpm\"; "
                "/usr/bin/cat > \"$pkg\"; "
                "actual_hash=$(/usr/bin/sha256sum \"$pkg\"); actual_hash=${actual_hash%% *}; "
                "if [ \"$actual_hash\" != \"$expected_hash\" ]; then "
                "echo 'Preserved RPM SHA-256 changed before administrator verification.' >&2; exit 64; fi; "
                "/usr/bin/rpmkeys --define \"_pkgverify_level all\" --checksig \"$pkg\"; "
                "actual_name=$(/usr/bin/rpm --define \"_pkgverify_level all\" -qp --qf '%{NAME}\\n' \"$pkg\"); "
                "if [ \"$actual_name\" != \"$expected_name\" ]; then "
                "echo 'Preserved RPM package name did not match the saved application.' >&2; exit 65; fi; "
                "actual_nevra=$(/usr/bin/rpm --define \"_pkgverify_level all\" -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' \"$pkg\"); "
                "if [ \"$actual_nevra\" != \"$expected_nevra\" ]; then "
                "echo 'Preserved RPM identity did not match the saved exact version.' >&2; exit 66; fi; "
                "/usr/bin/dnf install -y --allow-downgrade \"$pkg\"; "
                "installed=$(/usr/bin/rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' \"$expected_name\") || exit 67; "
                "printf '%s\\n' \"$installed\" | /usr/bin/grep -Fqx -- \"$expected_nevra\" || { "
                "echo 'Installed RPM identity did not match the verified restore payload.' >&2; exit 68; }");

            const ProcessResult result = runProcessResponsive(
                this,
                QStringLiteral("Restoring Exact RPM Version"),
                QStringLiteral("Restoring %1 from the preserved exact RPM…")
                    .arg(metadata[QStringLiteral("application")].toString()),
                QStringLiteral("pkexec"),
                {
                    QStringLiteral("/bin/sh"),
                    QStringLiteral("-c"),
                    script,
                    QStringLiteral("totalsweep-rpm-restore"),
                    expected,
                    expectedHash.toLower(),
                    appId
                },
                600000,
                QProcessEnvironment(),
                snapshot);

            if (result.success && currentRpmNevra(appId) == expected) {
                exactRestored = true;
            }
            else {
                exactError = result.standardError.trimmed();
                if (result.success) {
                    exactError = QStringLiteral(
                        "DNF completed, but the installed RPM identity did not match the removed version.");
                }
            }
        }

        if (!exactRestored && !expected.isEmpty()) {
            const ProcessResult repoResult = runProcessResponsive(
                this,
                QStringLiteral("Restoring Exact RPM Version"),
                QStringLiteral("Trying the exact repository RPM version for %1…")
                    .arg(metadata[QStringLiteral("application")].toString()),
                QStringLiteral("pkexec"),
                {
                    QStringLiteral("/usr/bin/dnf"),
                    QStringLiteral("install"),
                    QStringLiteral("-y"),
                    QStringLiteral("--allow-downgrade"),
                    expected
                },
                600000);

            if (repoResult.success && currentRpmNevra(appId) == expected) {
                exactRestored = true;
                exactError.clear();
            }
            else if (!repoResult.success && exactError.isEmpty()) {
                exactError = repoResult.standardError.trimmed();
            }
            else if (repoResult.success && !exactRestored) {
                exactError = QStringLiteral(
                    "DNF completed, but the installed RPM identity did not match the removed version.");
            }
        }

        if (exactRestored) {
            metadata[QStringLiteral("restoredVersionMode")] =
                QStringLiteral("exact");
            saveRestoreState(
                session,
                metadata,
                QStringLiteral("restored"),
                QStringLiteral("Exact removed RPM version restored."));
            totalSweepInformation(
                this,
                QStringLiteral("Restore Complete"),
                QStringLiteral("%1 was restored to the exact removed RPM version.")
                    .arg(metadata[QStringLiteral("application")].toString()));
            return true;
        }

        const QString explanation = exactError.trimmed().isEmpty()
            ? QStringLiteral("The exact removed RPM version is not currently restorable.")
            : exactError.trimmed();

        if (!restorePreferences.offerCurrentVersionFallback) {
            totalSweepInformation(
                this,
                QStringLiteral("Exact Version Could Not Be Restored"),
                explanation + QStringLiteral(
                    "\n\nCurrent-version fallback offers are disabled in Settings. Nothing else was installed."));
            return false;
        }

        if (totalSweepWarning(
                this,
                QStringLiteral("Exact Version Could Not Be Restored"),
                explanation + QStringLiteral(
                    "\n\nTotalSweep will not silently substitute a newer version. "
                    "Would you like to install the current repository version instead?"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No)
            == QMessageBox::Yes) {
            return restoreCurrentRpm(session, metadata);
        }
        return false;
    }


    QString currentFlatpakCommit(
        const QString &scope,
        const QString &appId) const
    {
        if (!isValidFlatpakScope(scope) ||
            appId.trimmed().isEmpty()) {
            return {};
        }

        const QStringList lines = runCommand(
            QStringLiteral("flatpak"),
            {
                QStringLiteral("info"),
                scope == QStringLiteral("user") ? QStringLiteral("--user") : QStringLiteral("--system"),
                QStringLiteral("--show-commit"),
                appId
            },
            10000);
        return lines.isEmpty() ? QString() : lines.first().trimmed();
    }


    bool restoreCurrentFlatpak(
        const QString &session,
        QJsonObject metadata)
    {
        const QString scope =
            metadata[QStringLiteral("flatpakScope")].toString();

        const QString appId =
            metadata[QStringLiteral("appId")].toString().trimmed();
        const QString origin =
            metadata[QStringLiteral("flatpakOrigin")].toString().trimmed();

        if (!isManagedQuarantineSession(session) ||
            !isValidFlatpakScope(scope) ||
            !isSafeFlatpakIdToken(appId) ||
            !isSafeFlatpakRemoteToken(origin)) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The saved Flatpak restore metadata is invalid or outside TotalSweep's managed storage."));
            return false;
        }

        totalsweep_restore::FlatpakIdentity identity;
        identity.appId = appId.toStdString();
        identity.scope = scope.toStdString();
        identity.origin = origin.toStdString();

        QString program = QStringLiteral("flatpak");
        QStringList args = toQStringList(totalsweep_restore::flatpakRestoreCurrentArgs(identity));
        if (identity.scope == "system") {
            args.prepend(QStringLiteral("/usr/bin/flatpak"));
            program = QStringLiteral("pkexec");
        }

        const ProcessResult result = runProcessResponsive(
            this,
            QStringLiteral("Reinstalling Current Version"),
            QStringLiteral("Installing the current Flatpak version of %1…")
                .arg(metadata[QStringLiteral("application")].toString()),
            program,
            args,
            600000);

        if (!result.success) {
            totalSweepWarning(this, QStringLiteral("Restore Failed"),
                result.standardError.isEmpty() ? QStringLiteral("Flatpak could not install the current version.") : result.standardError);
            return false;
        }

        metadata[QStringLiteral("restoredVersionMode")] = QStringLiteral("current");
        saveRestoreState(session, metadata, QStringLiteral("restored"), QStringLiteral("Current Flatpak version installed."));
        return true;
    }


    bool restoreFlatpakSession(
        const QString &session,
        QJsonObject metadata)
    {
        const QString appId =
            metadata[QStringLiteral("appId")].toString().trimmed();
        const QString scope =
            metadata[QStringLiteral("flatpakScope")].toString();
        const QString origin =
            metadata[QStringLiteral("flatpakOrigin")].toString().trimmed();
        const QString expectedCommit =
            metadata[QStringLiteral("flatpakCommit")].toString().trimmed();

        if (!isManagedQuarantineSession(session) ||
            !isValidFlatpakScope(scope) ||
            !isSafeFlatpakIdToken(appId) ||
            !isSafeFlatpakRemoteToken(origin) ||
            (!expectedCommit.isEmpty() &&
             !isSafeSha256Token(expectedCommit))) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The saved Flatpak restore metadata is invalid or outside TotalSweep's managed storage."));
            return false;
        }
        const QString snapshot = metadata[QStringLiteral("snapshotPath")].toString();
        const QString expectedHash =
            metadata[QStringLiteral("snapshotSha256")].toString().trimmed();

        if (scope == QStringLiteral("user") &&
            !expectedCommit.isEmpty() &&
            isManagedSnapshotPath(
                snapshot,
                QStringLiteral("flatpak")) &&
            isSafeSha256Token(expectedHash) &&
            sha256File(snapshot) == expectedHash) {

            totalsweep_restore::FlatpakIdentity identity;
            identity.appId = appId.toStdString();
            identity.scope = scope.toStdString();
            const QString program = QStringLiteral("flatpak");
            const QStringList args = toQStringList(
                totalsweep_restore::flatpakRestoreBundleArgs(identity, snapshot.toStdString()));

            const ProcessResult result = runProcessResponsive(
                this,
                QStringLiteral("Restoring Exact Flatpak Version"),
                QStringLiteral("Installing the preserved Flatpak bundle for %1…")
                    .arg(metadata[QStringLiteral("application")].toString()),
                program,
                args,
                600000);

            if (result.success && currentFlatpakCommit(scope, appId) == expectedCommit) {
                metadata[QStringLiteral("restoredVersionMode")] = QStringLiteral("exact");
                saveRestoreState(session, metadata, QStringLiteral("restored"), QStringLiteral("Exact removed Flatpak commit restored."));
                totalSweepInformation(this, QStringLiteral("Restore Complete"),
                    QStringLiteral("%1 was restored to the exact removed Flatpak commit.")
                        .arg(metadata[QStringLiteral("application")].toString()));
                return true;
            }

            const QString reason = result.standardError.isEmpty()
                ? QStringLiteral("The exact bundle could not be installed or did not restore the expected commit.")
                : result.standardError;
            totalSweepWarning(this, QStringLiteral("Exact Flatpak Restore Failed"), reason);
        }

        const QString exactFlatpakExplanation =
            scope == QStringLiteral("system") &&
            !snapshot.trimmed().isEmpty()
                ? QStringLiteral(
                    "For security, TotalSweep does not elevate a user-writable local Flatpak bundle into the system installation. "
                    "The saved remote can still be used for an explicitly approved current-version restore.")
                : QStringLiteral(
                    "The preserved exact Flatpak commit is not currently restorable.");

        if (!restorePreferences.offerCurrentVersionFallback) {
            totalSweepInformation(
                this,
                QStringLiteral("Exact Flatpak Version Unavailable"),
                exactFlatpakExplanation + QStringLiteral(
                    " Current-version fallback offers are disabled in Settings. Nothing else was installed."));
            return false;
        }

        if (totalSweepWarning(
                this,
                QStringLiteral("Exact Flatpak Version Unavailable"),
                exactFlatpakExplanation + QStringLiteral(
                    "\n\nTotalSweep will not silently substitute a newer version. "
                    "Install the current version from the saved Flatpak remote instead?"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No)
            == QMessageBox::Yes) {
            return restoreCurrentFlatpak(session, metadata);
        }
        return false;
    }


    void restoreSession(
        const QString &session)
    {
        if (!isManagedQuarantineSession(session)) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral(
                    "The selected Quarantine session is outside TotalSweep's managed Quarantine storage or is not a safe session directory."));
            return;
        }

        QJsonObject metadata =
            readManagedQuarantineMetadata(
                session);

        if (metadata.isEmpty()) {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Failed"),
                QStringLiteral("The quarantine metadata could not be opened."));
            return;
        }

        const QString mode = metadata[QStringLiteral("restoreMode")].toString(QStringLiteral("files"));
        if (mode == QStringLiteral("files")) {
            restoreFileSession(session, metadata);
        }
        else if (mode.startsWith(QStringLiteral("rpm-"))) {
            restoreRpmSession(session, metadata);
        }
        else if (mode.startsWith(QStringLiteral("flatpak-"))) {
            restoreFlatpakSession(session, metadata);
        }
        else {
            totalSweepWarning(
                this,
                QStringLiteral("Restore Unsupported"),
                QStringLiteral("This Quarantine entry does not contain a supported restore method."));
        }

        loadHistory();
        refreshApplications();

        if (!currentApp.isEmpty() && pages && pages->currentIndex() == 1)
            scanLeftoversAsync(currentApp);
    }

};

int main(
    int argc,
    char **argv)
{
    QApplication app(
        argc,
        argv);

    app.setApplicationName(
        "TotalSweep Uninstaller");

    app.setApplicationDisplayName(
        "TotalSweep Uninstaller");

    app.setApplicationVersion(
        "8.10.0");

    Window window;

    window.show();

    return app.exec();
}