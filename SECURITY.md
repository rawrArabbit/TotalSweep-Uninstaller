# Security

## Supported Version

The current public version of TotalSweep Uninstaller is **8.9.13**.

Security fixes will mainly be made for the latest release while the project is being actively maintained.

## Reporting a Security Problem

If you find something that could cause files to be deleted when they shouldn't be, allow commands to run with higher privileges, restore files somewhere unsafe, or otherwise affect the security of the system, please **do not post the details in a public issue**.

Use GitHub's private vulnerability reporting instead.

When reporting a problem, it helps if you include:

- the TotalSweep version
- your Fedora version
- your KDE Plasma version
- whether the app involved was RPM, Flatpak or manual/local
- what you were trying to do
- steps to reproduce the problem
- any useful logs or error messages
- whether anything on the system was changed or deleted

Please remove personal information from logs before sending them, and never include passwords, access tokens, private keys or anything similar.

## Administrator Access

Some things TotalSweep does require administrator access.

TotalSweep uses Polkit / `pkexec` for those operations instead of running the entire app as root.

Anything stored in your normal user folders, including TotalSweep's Quarantine and package cache, is treated as untrusted before it is used for an administrator-level operation.

This is important because files in your home folder can be changed by your user account.

For example:

- TotalSweep does not take a path from Quarantine and blindly restore it somewhere as root.
- Files in the normal user Quarantine are deleted without giving the whole Quarantine folder root access.
- A saved RPM is checked again before DNF is allowed to install it.
- The RPM's SHA-256, package identity and trusted RPM signature/digests are checked again from a private root-owned temporary copy.
- A Flatpak bundle stored in a user-writable location is not used for a system-wide Flatpak install.
- Privileged file operations check paths again before doing anything and reject unsafe symlink or user-writable path situations.

If TotalSweep cannot safely complete something that needs administrator access, it stops and leaves the remaining files alone instead of trying to force the operation through.

## Security-Sensitive Areas

The main security-sensitive areas are:

- administrator operations through Polkit / `pkexec`
- RPM / DNF uninstall and restore
- Flatpak uninstall and restore
- manual/local app removal
- leftover deletion
- Quarantine
- restoring files
- checking filesystem paths
- protected system locations
- package ownership detection
- anything involving user-controlled file paths or app names

TotalSweep is currently built and tested on **Fedora 44 KDE Plasma**.

Other Linux distributions are not supported yet.
