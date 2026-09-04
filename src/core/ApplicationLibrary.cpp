#include "ApplicationLibrary.h"

#include <algorithm>


ApplicationLibrary::ApplicationLibrary(
    ApplicationBackendManager *backendManager)
: m_backendManager(backendManager)
{
}


void ApplicationLibrary::refresh()
{
    m_applications.clear();

    if (!m_backendManager)
        return;

    m_applications =
    m_backendManager->detectAllApplications();

    normalize();
    removeDuplicates();
}


QList<ApplicationInfo>
ApplicationLibrary::applications() const
{
    return m_applications;
}


QList<ApplicationInfo>
ApplicationLibrary::search(
    const QString &query) const
    {
        const QString needle =
        query.trimmed();

        /*
         * Empty search means return the cached inventory immediately.
         *
         * No RPM/Flatpak command is executed here.
         */
        if (needle.isEmpty())
            return m_applications;

        QList<ApplicationInfo> matches;

        for (const ApplicationInfo &app :
            m_applications) {

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
                            Qt::CaseInsensitive)) {

                matches.append(app);
                            }
            }

            return matches;
    }


    int ApplicationLibrary::count() const
    {
        return m_applications.size();
    }


    void ApplicationLibrary::normalize()
    {
        for (ApplicationInfo &app :
            m_applications) {

            if (app.name.isEmpty())
                app.name = app.id;

            if (app.packageManager.isEmpty()) {

                switch (app.type) {

                    case ApplicationType::RPM:
                        app.packageManager =
                        QStringLiteral("RPM / DNF");
                        break;

                    case ApplicationType::DEB:
                        app.packageManager =
                        QStringLiteral("DEB / APT");
                        break;

                    case ApplicationType::Pacman:
                        app.packageManager =
                        QStringLiteral("Pacman");
                        break;

                    case ApplicationType::Zypper:
                        app.packageManager =
                        QStringLiteral("Zypper");
                        break;

                    case ApplicationType::APK:
                        app.packageManager =
                        QStringLiteral("APK");
                        break;

                    case ApplicationType::Portage:
                        app.packageManager =
                        QStringLiteral("Portage");
                        break;

                    case ApplicationType::Flatpak:
                        app.packageManager =
                        QStringLiteral("Flatpak");
                        break;

                    case ApplicationType::Snap:
                        app.packageManager =
                        QStringLiteral("Snap");
                        break;

                    case ApplicationType::AppImage:
                        app.packageManager =
                        QStringLiteral("AppImage");
                        break;

                    case ApplicationType::Script:
                        app.packageManager =
                        QStringLiteral("Script");
                        break;

                    case ApplicationType::Binary:
                        app.packageManager =
                        QStringLiteral("Standalone Binary");
                        break;

                    case ApplicationType::SourceBuild:
                        app.packageManager =
                        QStringLiteral("Source Build");
                        break;

                    case ApplicationType::Custom:
                        app.packageManager =
                        QStringLiteral("Custom");
                        break;

                    case ApplicationType::Unknown:
                        app.packageManager =
                        QStringLiteral("Unknown");
                        break;
                }
            }
            }

            std::sort(
                m_applications.begin(),
                      m_applications.end(),
                      [](const ApplicationInfo &a,
                         const ApplicationInfo &b) {

                          const int nameCompare =
                          QString::compare(
                              a.name,
                              b.name,
                              Qt::CaseInsensitive);

                          if (nameCompare != 0)
                              return nameCompare < 0;

                          return QString::compare(
                              a.id,
                              b.id,
                              Qt::CaseInsensitive) < 0;
                         });
    }


    void ApplicationLibrary::removeDuplicates()
    {
        QList<ApplicationInfo> unique;

        for (const ApplicationInfo &app :
            m_applications) {

            bool duplicate = false;

        for (const ApplicationInfo &existing :
            unique) {

            if (app.type == existing.type &&
                app.id == existing.id) {

                duplicate = true;
            break;
                }
            }

            if (!duplicate)
                unique.append(app);
            }

            m_applications = unique;
    }
