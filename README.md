<h1><img src="org.kde.totalsweep.svg" alt="TotalSweep Uninstaller icon" width="48" height="48" align="absmiddle"> TotalSweep Uninstaller</h1>

**TotalSweep Uninstaller** is a KDE/Qt 6 application for uninstalling applications, finding related leftovers, and preserving recoverable removals through its Quarantine and Restore Protection system.

Current release: **8.10.0**

> **Platform status:** TotalSweep Uninstaller is currently developed and tested on **Fedora 44 with KDE Plasma**. RPM/DNF, Flatpak, and safeguarded manual/local application handling are supported. Other Linux distributions are not currently supported or tested.

## Features

- Discover installed RPM and Flatpak applications
- Detect supported manual/local applications
- Search and filter installed applications
- Uninstall one or multiple selected applications
- Scan for application leftovers
- Categorize leftovers by confidence and risk
- Protect dangerous or potentially unrelated files from automatic selection
- Quarantine supported removals instead of immediately deleting them
- Restore quarantined files and supported applications
- Preserve exact RPM and Flatpak restore information when available
- Reverify preserved local RPMs in root-private storage for SHA-256, trusted signature/digests, package name, and exact identity before administrator installation
- Offer controlled current-version fallback when an exact package restore is unavailable
- Preserve Flatpak user data when Restore Protection is enabled
- Maintain persistent Quarantine and History records
- Permanently delete selected leftovers or Quarantine entries when explicitly requested
- Configurable Restore Protection and advanced removal behavior
- Persistent table layout, columns, separators, and application settings
- KDE/Qt theme integration

## Safety

TotalSweep is designed to provide more control than a traditional application uninstaller. That also means it can expose files, packages, dependencies, and system components that should not be removed casually.

The application separates leftover results into different risk levels and does not automatically select items classified as potentially unrelated or dangerous.

**Quarantine is TotalSweep's primary safety net.** With the recommended Restore Protection settings, TotalSweep preserves supported application information or files so many accidental removals can be recovered.

Advanced Settings can disable some or all future restore protection. Items removed permanently may not be recoverable by TotalSweep.

Always review system packages, dependencies, and unfamiliar files before removing them.

## Supported Application Types

### RPM / DNF

RPM applications installed on Fedora are detected through the system RPM database and removed through DNF.

Where Restore Protection permits it, TotalSweep can preserve information needed to attempt an exact package restore.

### Flatpak

Flatpak applications are detected and handled through the Flatpak command-line tools.

TotalSweep can preserve restore information and, when enabled, application user data.

### Manual / Local Applications

TotalSweep can identify supported applications installed outside RPM or Flatpak, including certain:

- AppImages
- standalone binaries
- scripts
- source-built applications
- custom/local installations

Manual/local removal uses additional path and ownership safeguards because these applications do not have a package manager defining their files.

For the first public release, TotalSweep deliberately refuses to place administrator-owned manual/local files into the user-profile Quarantine. User-profile Quarantine is writable by the desktop user and is therefore not treated as a trusted source for later root-level file restoration. User-owned manual/local applications remain supported; permission-restricted manual/local applications are left untouched while manual/local Quarantine protection is enabled.

## Leftover Scanning

After an application is removed, TotalSweep can search for files and directories that appear related to it.

Results are classified into categories such as:

- **Confirmed Leftovers**
- **Review / Possible**
- **Danger — Possibly Unrelated**

Higher-risk results require explicit user review and are not automatically selected for removal.

Permission-restricted leftovers are not elevated into the user-profile Quarantine. They are left untouched rather than turning user-writable restore metadata into a root-level file-move authority. Permanent deletion, when explicitly enabled and confirmed, uses separate privileged-path safeguards.

## Quarantine and Restore Protection

TotalSweep's Quarantine keeps records of supported removals and can preserve files or package information required for restoration.

Depending on the application type and available data, restoration may include:

- moving quarantined files back to their original locations
- restoring an RPM package from an exact preserved package when available and trusted by the system RPM keyring
- restoring an exact user-scope Flatpak revision from a preserved bundle when available
- offering a current-version package fallback when explicitly permitted
- restoring supported manual/local application files

Restore capability depends on what was preserved when the item was removed and whether required package or repository data remains available.

Security boundary: user-profile Quarantine and its metadata are intentionally treated as untrusted input for administrator operations. TotalSweep does not automatically restore files to permission-restricted destinations from that data. For an exact local RPM restore, TotalSweep opens the preserved payload at desktop-user privilege, streams it into fresh root-private temporary storage, and immediately rechecks its saved SHA-256, system-trusted RPM signature/digests, package name, and exact NEVRA before DNF is allowed to install that private copy. A user-writable local Flatpak bundle is never elevated into the system-wide Flatpak installation; system-scope restore instead offers the explicitly approved saved-remote/current-version fallback when available.

## Requirements

The current Fedora build requires:

- Fedora 44
- KDE Plasma
- Qt 6 Widgets
- CMake
- GCC C++
- DNF / RPM
- Flatpak for Flatpak application management
- Polkit for operations requiring administrator authorization

## Install TotalSweep

Download `TotalSweep-Uninstaller-8.10.0.rpm` from the latest release.

The command below works if the RPM was downloaded to your `Downloads` folder:

```bash
sudo dnf install "$HOME/Downloads/TotalSweep-Uninstaller-8.10.0.rpm"
```

If you downloaded the RPM somewhere else, replace the path in the command with the actual location of the downloaded file.

### Install using the included script

From the TotalSweep source directory:

```bash
chmod +x install.sh
./install.sh
```

The installer builds TotalSweep and installs it under `/usr/local`.

After installation, TotalSweep should appear in the KDE application launcher.

You can also start it from a terminal with:

```bash
totalsweep
```

### Build manually

Install the required build dependencies:

```bash
sudo dnf install gcc-c++ cmake qt6-qtbase-devel polkit flatpak
```

Then build:

```bash
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
cmake --build . --parallel
sudo cmake --install .
```

Refresh KDE's application database if needed:

```bash
kbuildsycoca6
```

## Uninstallation

Run:

```bash
./uninstall.sh
```

The uninstall script gives you two choices:

1. **Remove TotalSweep but keep your data** — removes the installed application while preserving Quarantine, History, package cache, application cache, and saved settings. This is useful if you plan to reinstall TotalSweep later.
2. **Complete removal** — removes the installed application and permanently deletes all TotalSweep-created Quarantine, History, package-cache, staging/application-cache data, and saved settings.

Complete removal requires an additional `PURGE` confirmation because deleting Quarantine and package snapshots can permanently remove the only restore copies TotalSweep has.

For command-line use, the same modes are available directly:

```bash
./uninstall.sh --keep-data
./uninstall.sh --purge
```

The uninstall script removes TotalSweep's installed files under `/usr/local`. Complete removal also removes:

```text
~/.local/share/TotalSweep Uninstaller/
~/.config/TotalSweep/Uninstaller.conf
```

If `XDG_CONFIG_HOME` is set, the settings file is removed from the corresponding `TotalSweep/Uninstaller.conf` path instead.

The uninstall script deliberately does **not** remove the source-code directory, downloaded release archives, shared Fedora packages, or system dependencies, because those files may be user-managed or required by other software.

## Source Layout

```text
.
├── CMakeLists.txt
├── install.sh
├── uninstall.sh
├── main.cpp
├── restore_engine.h
├── org.kde.totalsweep.desktop
├── org.kde.totalsweep.svg
└── src
    ├── core
    └── package
        ├── flatpak
        └── rpm
```

## Current Platform Support

| Platform / Package Type | Status |
| --- | --- |
| Fedora 44 KDE Plasma | Tested |
| RPM / DNF | Supported |
| Flatpak | Supported |
| Safeguarded manual/local applications | Supported |
| Debian / Ubuntu APT | Not currently supported |
| Arch / Manjaro Pacman | Not currently supported |
| openSUSE Zypper | Not currently supported |
| Snap package management | Not currently supported |

Support for additional Linux package-management systems may be considered in future releases.

## Reporting Problems

When reporting a problem, please include:

- TotalSweep version
- Fedora version
- KDE Plasma version
- whether the application involved was RPM, Flatpak, or manual/local
- what operation was being performed
- relevant terminal or application error output

For destructive-operation or security-related issues, avoid publishing sensitive system information or security details publicly until they can be reviewed.

## Development Note

TotalSweep Uninstaller was developed with AI-assisted code generation under human direction, iterative testing, and release review.

The public project is maintained under the **rawrArabbit** developer identity.

## Acknowledgements

TotalSweep Uninstaller is built using **Qt 6** and is designed primarily for the **KDE Plasma** desktop environment on **Fedora Linux**.

It relies on standard system technologies and tools including RPM, DNF, Flatpak, and Polkit for supported package-management and privileged operations.

TotalSweep Uninstaller is an independent project and is not affiliated with or endorsed by Fedora, Red Hat, KDE, Qt, Flatpak, or OpenAI.

## License

Copyright (C) 2026 rawrArabbit

TotalSweep Uninstaller is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

TotalSweep Uninstaller is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**.

See the [LICENSE](LICENSE) file for the complete GNU General Public License version 3.
