# Changelog

All notable public changes to TotalSweep Uninstaller will be documented in this file.

## [8.10.0] - 2026-09-05

### Application Detection
- improved support for Manual / Local apps installed outside RPM and Flatpak
- added detection for apps installed under `/opt` and apps launched through local wrappers
- improved handling of app suites that share the same installation folder
- bundled tools are now separated from apps that can be safely removed on their own

### AppImage Support
- improved detection for manually installed and Gear Lever-managed AppImages
- AppImages can now be detected by their actual file format instead of only by the `.AppImage` extension
- added support for more common AppImage install locations
- read embedded desktop and AppStream metadata when the AppImage provides it

### Metadata
- improved version and description detection for Flatpak, AppImage and Manual / Local apps
- added support for version information stored in Mozilla-style `application.ini` files
- improved handling of desktop-file descriptions and generic names
- added size and estimated install-date detection for supported Manual / Local apps
- version information is kept exactly as reported by the app's own metadata

### Reliability
- improved matching between apps, launchers and their installation files
- installer, helper and uninstaller launchers are less likely to appear as separate removable apps
- unavailable metadata is left as `Unknown` or `—` instead of using unreliable values

## [8.9.13] - 2026-08-27
- stream preserved RPM payloads into root-private temporary storage and reverify SHA-256, trusted signature/digests, package name, exact NEVRA, and installed identity before privileged exact restore
- keep user-profile Quarantine cleanup and metadata-driven file restore unprivileged rather than granting user-writable metadata root filesystem authority
- use `Exec=totalsweep` in the desktop launcher so source installs under `/usr/local` and distribution packages under `/usr` share one launcher
- hardened the final restore trust boundary so user-writable Quarantine metadata cannot become a root file-placement authority
- require system-trusted RPM signatures before privileged local RPM restore
- refuse elevation of user-writable Flatpak bundles into the system-wide Flatpak installation
- refuse permission-restricted manual/local and leftover Quarantine moves until a root-owned Quarantine backend is available
- prevent privileged filesystem operations through user-writable parent chains
- keep user-owned manual/local operations unprivileged even in mixed package-removal selections
- made CMake install paths package-friendly while keeping source installs under `/usr/local`
- source installer now installs the Flatpak CLI required for Flatpak management

### First Public Release

- Fedora 44 KDE Plasma tested release
- RPM/DNF application detection and removal
- Flatpak application detection and removal
- safeguarded manual/local application handling
- leftover scanning with risk classification
- Quarantine and persistent removal history
- Restore Protection for supported removals
- exact RPM and Flatpak restore information when available
- controlled current-version fallback where supported
- configurable advanced restore and removal settings
- persistent table layout, columns, row/column separators, and application settings
- KDE/Qt 6 theme integration
- uninstall script with both keep-data and complete-purge removal modes
- protected-core RPM classification applied consistently to launcher-owned packages
- hardened Quarantine/session and package-snapshot path validation
- strict Flatpak restore-scope validation
- symlink-aware, non-throwing restore filesystem checks
- generalized protection for standard user-content directories during leftover classification
- destructive path guard rejects symlinked parent-directory escapes before move/delete/restore operations
- restore metadata CLI tokens are validated before RPM/DNF or Flatpak commands are allowed
- preserved RPM snapshots are identity-checked before exact local restore
- restore confirmation exposes exact file destinations or saved package identity in Details

### Platform Support

- Fedora 44 KDE Plasma: tested
- RPM/DNF: supported
- Flatpak: supported
- safeguarded manual/local applications: supported
- Snap: planned for a later release
- other Linux distributions/package managers: not currently supported or tested
