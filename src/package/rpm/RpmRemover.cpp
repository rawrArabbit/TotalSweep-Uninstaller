#include "RpmRemover.h"
#include <QProcess>

QString RpmRemover::name() const
{
    return QStringLiteral("RPM / DNF");
}

bool RpmRemover::supports(const ApplicationInfo &application) const
{
    return application.type == ApplicationType::RPM &&
           application.removable &&
           !application.protectedComponent;
}

RemovalResult RpmRemover::remove(const RemovalRequest &request)
{
    RemovalResult result;

    if (!supports(request.application)) {
        result.error = QStringLiteral("This RPM application cannot be removed.");
        return result;
    }

    if (request.application.id.isEmpty()) {
        result.error = QStringLiteral("RPM package identifier is missing.");
        return result;
    }

    QProcess p;
    p.start("pkexec", {"dnf", "remove", "-y", request.application.id});

    /*
     * Do not attempt to kill a pkexec child after authorization: pkexec may
     * already have become the root target process.  Authentication itself is
     * cancellable; once authorized, wait for the real privileged result.
     */
    if (!p.waitForFinished(-1)) {
        result.error = QStringLiteral("Could not wait for the privileged RPM removal to finish.");
        return result;
    }

    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
        result.error = QString::fromLocal8Bit(p.readAllStandardError()).trimmed();
        if (result.error.isEmpty())
            result.error = QStringLiteral("DNF failed to remove the RPM package.");
        return result;
    }

    result.success = true;
    result.message = QStringLiteral("RPM package removed successfully.");
    result.removedItems.append(request.application.id);
    return result;
}
