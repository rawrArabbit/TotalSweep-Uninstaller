#pragma once

#include <QString>
#include <QStringList>

enum class ApplicationType {
    Unknown,
    RPM,
    DEB,
    Pacman,
    Zypper,
    APK,
    Portage,
    Flatpak,
    Snap,
    AppImage,
    Script,
    Binary,
    SourceBuild,
    Custom
};

enum class RiskLevel {
    Safe = 0,
    Review = 1,
    Advanced = 2,
    Danger = 3,
    Unknown = 4
};

struct ApplicationInfo {
    QString name;
    QString id;
    QString version;
    QString installedSize;
    QString installDate;
    QString description;
    QString executable;
    QString desktopFile;
    QString installLocation;
    QString packageManager;
    QString source;
    QStringList dependencies;
    QStringList files;
    QStringList installLocations;

    ApplicationType type = ApplicationType::Unknown;
    RiskLevel risk = RiskLevel::Unknown;

    bool installed = false;
    bool removable = false;
    bool userInstalled = false;
    bool systemComponent = false;
    bool protectedComponent = false;
    bool installDateEstimated = false;
};
