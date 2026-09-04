#include "FlatpakRemover.h"
#include <QProcess>

QString FlatpakRemover::name() const
{
    return QStringLiteral("Flatpak");
}

bool FlatpakRemover::supports(const ApplicationInfo &application) const
{
    return application.type == ApplicationType::Flatpak &&
           application.removable &&
           !application.protectedComponent;
}

RemovalResult FlatpakRemover::remove(const RemovalRequest &request)
{
    RemovalResult result;

    if (!supports(request.application)) {
        result.error = QStringLiteral("This Flatpak application cannot be removed.");
        return result;
    }

    if (request.application.id.isEmpty()) {
        result.error = QStringLiteral("Flatpak application identifier is missing.");
        return result;
    }

    QStringList args = {"flatpak", "uninstall", "-y"};

    if (request.removeUserData)
        args.append("--delete-data");

    args.append(request.application.id);

    QProcess p;
    p.start("pkexec", args);

    /*
     * Do not attempt to kill a pkexec child after authorization: pkexec may
     * already have become the root target process.  Authentication itself is
     * cancellable; once authorized, wait for the real privileged result.
     */
    if (!p.waitForFinished(-1)) {
        result.error = QStringLiteral("Could not wait for the privileged Flatpak removal to finish.");
        return result;
    }

    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
        result.error = QString::fromLocal8Bit(p.readAllStandardError()).trimmed();
        if (result.error.isEmpty())
            result.error = QStringLiteral("Flatpak failed to remove the application.");
        return result;
    }

    result.success = true;
    result.message = QStringLiteral("Flatpak application removed successfully.");
    result.removedItems.append(request.application.id);
    return result;
}
