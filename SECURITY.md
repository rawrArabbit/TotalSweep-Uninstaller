# Security Policy

## Supported Versions

The first public release of TotalSweep Uninstaller is **8.9.13**.

Security fixes will be provided for the current public release line as practical while the project is actively maintained.

## Reporting a Security Issue

Please do **not** open a public issue for a vulnerability that could cause unintended file deletion, privilege escalation, command injection, unsafe restoration, or other destructive behavior.

Instead, contact the maintainer privately through the security-reporting method provided on the project's GitHub repository once private vulnerability reporting is enabled.

When reporting a security issue, please include:

- the TotalSweep version
- Fedora and KDE Plasma versions
- whether the affected application was RPM, Flatpak, or manual/local
- the exact operation being performed
- steps required to reproduce the issue
- relevant logs or error output with personal information removed
- whether any files, packages, or system data were altered

Please avoid including passwords, authentication secrets, private keys, access tokens, or unrelated personal data.

## Privilege and Quarantine Trust Boundary

TotalSweep treats Quarantine metadata, package-cache files, and other data in the desktop user's profile as **untrusted at every administrator boundary**.

- Metadata-driven file restores are not escalated to administrator privileges. Permission-restricted destinations remain untouched rather than turning user-writable metadata into a root file-placement instruction.
- Permanent cleanup of user-profile Quarantine data is performed without privilege escalation. TotalSweep does not run a root recursive delete over a path chosen from Quarantine metadata.
- For an exact local RPM restore, the preserved RPM is opened at desktop-user privilege and streamed into fresh root-private temporary storage. The privileged side rechecks the saved SHA-256, requires system-trusted RPM signature and digest verification, verifies the RPM package name and exact NEVRA, installs only that root-private verified copy, and verifies the installed identity afterward.
- A user-writable local Flatpak bundle is never passed to a root/system Flatpak install. System-scope restore uses an explicitly approved configured-remote/current-version path instead.
- Privileged filesystem operations reject paths whose parent chain can be replaced by the desktop user or escapes through a symlink.

When a protected recovery cannot be completed without crossing this boundary safely, TotalSweep fails closed and preserves the remaining data instead of escalating it.

## Scope

Security-sensitive areas include:

- privileged operations performed through Polkit / `pkexec`
- RPM/DNF removal and restoration
- Flatpak removal and restoration
- manual/local application removal
- leftover scanning and deletion
- Quarantine operations
- restore operations
- path validation and protected-path handling
- package ownership detection
- handling of user-controlled application names and filesystem paths

TotalSweep Uninstaller is currently developed and tested on **Fedora 44 KDE Plasma**. Other distributions are not currently supported or tested.
