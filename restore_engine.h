#pragma once

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace totalsweep_restore {

enum class AppKind {
    Rpm,
    Flatpak,
    AppImage,
    Custom,
    Script,
    Binary,
    SourceBuild,
    Leftovers
};

struct RestorePolicy {
    /* Future-removal policy. Existing restore records remain usable. */
    bool restoreProtection = true;
    bool trackApplicationUninstalls = true;
    bool preserveExactPackagePayloads = true;
    bool quarantineManualApplications = true;
    bool quarantineLeftovers = true;
    bool keepMetadataOnlyRecords = true;
    bool preserveFlatpakUserData = true;
    bool autoScanLeftoversAfterUninstall = true;
    bool warnWhenSnapshotUnavailable = true;
    bool offerCurrentVersionFallback = true;

    bool applicationTrackingEnabled() const
    {
        return restoreProtection && trackApplicationUninstalls;
    }

    bool exactPackageSnapshotsEnabled() const
    {
        return applicationTrackingEnabled() && preserveExactPackagePayloads;
    }

    bool manualApplicationQuarantineEnabled() const
    {
        return applicationTrackingEnabled() && quarantineManualApplications;
    }

    bool leftoverQuarantineEnabled() const
    {
        return restoreProtection && quarantineLeftovers;
    }
};

inline const char *kindLabel(AppKind kind)
{
    switch (kind) {
    case AppKind::Rpm: return "RPM";
    case AppKind::Flatpak: return "Flatpak";
    case AppKind::AppImage: return "AppImage";
    case AppKind::Custom: return "Manual / Custom";
    case AppKind::Script: return "Script";
    case AppKind::Binary: return "Binary";
    case AppKind::SourceBuild: return "Source Build";
    case AppKind::Leftovers: return "Leftovers";
    }
    return "Unknown";
}

inline bool usesExactFileQuarantine(AppKind kind)
{
    return kind == AppKind::AppImage ||
           kind == AppKind::Custom ||
           kind == AppKind::Script ||
           kind == AppKind::Binary ||
           kind == AppKind::SourceBuild ||
           kind == AppKind::Leftovers;
}

struct RpmIdentity {
    std::string name;
    std::string epoch;
    std::string version;
    std::string release;
    std::string arch;

    std::string fullNevra() const
    {
        const std::string effectiveEpoch = epoch.empty() ? "0" : epoch;
        return name + "-" + effectiveEpoch + ":" + version + "-" + release + "." + arch;
    }
};

inline std::vector<std::string> rpmDownloadArgs(
    const RpmIdentity &id,
    const std::string &destDir)
{
    return {
        "download",
        "--destdir=" + destDir,
        id.fullNevra()
    };
}

inline std::vector<std::string> rpmRestoreLocalArgs(
    const std::string &rpmPath)
{
    return {
        "install",
        "-y",
        "--allow-downgrade",
        rpmPath
    };
}

inline std::vector<std::string> rpmRestoreRepoArgs(
    const RpmIdentity &id)
{
    return {
        "install",
        "-y",
        "--allow-downgrade",
        id.fullNevra()
    };
}

struct FlatpakIdentity {
    std::string appId;
    std::string ref;
    std::string commit;
    std::string origin;
    std::string scope; // "user" or "system"
    std::string runtimeRepoUrl;

    std::string branch() const
    {
        const auto pos = ref.rfind('/');
        if (pos == std::string::npos || pos + 1 >= ref.size())
            return "stable";
        return ref.substr(pos + 1);
    }
};

inline std::vector<std::string> flatpakBundleArgs(
    const FlatpakIdentity &id,
    const std::string &repoPath,
    const std::string &bundlePath)
{
    std::vector<std::string> args = {
        "build-bundle",
        repoPath,
        bundlePath,
        id.appId,
        id.branch()
    };

    if (!id.runtimeRepoUrl.empty())
        args.push_back("--runtime-repo=" + id.runtimeRepoUrl);

    return args;
}

inline std::vector<std::string> flatpakRestoreBundleArgs(
    const FlatpakIdentity &id,
    const std::string &bundlePath)
{
    std::vector<std::string> args = {
        "install",
        "-y"
    };

    args.push_back(id.scope == "user" ? "--user" : "--system");
    args.push_back(bundlePath);
    return args;
}

inline std::vector<std::string> flatpakRestoreCurrentArgs(
    const FlatpakIdentity &id)
{
    std::vector<std::string> args = {
        "install",
        "-y"
    };

    args.push_back(id.scope == "user" ? "--user" : "--system");
    if (!id.origin.empty())
        args.push_back(id.origin);
    args.push_back(id.appId);
    return args;
}

enum class FileRestoreDecision {
    Move,
    SkipExistingDestination,
    AlreadyRestored,
    MissingSource,
    FilesystemError
};

inline FileRestoreDecision decideFileRestore(
    const std::filesystem::path &source,
    const std::filesystem::path &destination) noexcept
{
    /*
     * symlink_status() observes the directory entry itself, so a dangling
     * symlink is still treated as a real quarantined/destination object.
     * The error_code overloads keep unusual permission/filesystem failures
     * from throwing through the Qt event loop and terminating TotalSweep.
     */
    std::error_code sourceError;
    std::error_code destinationError;

    std::filesystem::file_status sourceStatus =
        std::filesystem::symlink_status(
            source,
            sourceError);

    std::filesystem::file_status destinationStatus =
        std::filesystem::symlink_status(
            destination,
            destinationError);

    /*
     * libstdc++ reports a missing path through error_code for
     * symlink_status(). Missing is a normal restore state, not a
     * filesystem failure. Preserve every other error as a safe failure.
     */
    if (sourceError ==
        std::make_error_code(
            std::errc::no_such_file_or_directory)) {
        sourceError.clear();
        sourceStatus = std::filesystem::file_status(
            std::filesystem::file_type::not_found);
    }

    if (destinationError ==
        std::make_error_code(
            std::errc::no_such_file_or_directory)) {
        destinationError.clear();
        destinationStatus = std::filesystem::file_status(
            std::filesystem::file_type::not_found);
    }

    if (sourceError || destinationError)
        return FileRestoreDecision::FilesystemError;

    const bool sourceExists =
        std::filesystem::exists(
            sourceStatus);

    const bool destinationExists =
        std::filesystem::exists(
            destinationStatus);

    if (!sourceExists && destinationExists)
        return FileRestoreDecision::AlreadyRestored;
    if (!sourceExists)
        return FileRestoreDecision::MissingSource;
    if (destinationExists)
        return FileRestoreDecision::SkipExistingDestination;
    return FileRestoreDecision::Move;
}

} // namespace totalsweep_restore
