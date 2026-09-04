#!/usr/bin/env bash
set -u

BIN="/usr/local/bin/totalsweep"
DESKTOP="/usr/local/share/applications/org.kde.totalsweep.desktop"
ICON="/usr/local/share/icons/hicolor/scalable/apps/org.kde.totalsweep.svg"

DATA_DIR="$HOME/.local/share/TotalSweep Uninstaller"
CONFIG_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/TotalSweep"
SETTINGS_FILE="$CONFIG_ROOT/Uninstaller.conf"

usage() {
    cat <<'EOF'
Usage:
  ./uninstall.sh              Interactive removal menu
  ./uninstall.sh --keep-data  Remove the application but preserve TotalSweep user data/settings
  ./uninstall.sh --purge      Remove the application and permanently delete TotalSweep user data/settings
  ./uninstall.sh --help       Show this help

The purge option removes TotalSweep-created Quarantine, History, package-cache,
staging/application-cache data, and saved application settings.

It does NOT remove this source-code directory, downloaded release archives,
Fedora packages shared with other software, or system dependencies.
EOF
}

remove_installed_files() {
    sudo rm -f -- "$BIN" "$DESKTOP" "$ICON" || {
        echo "ERROR: Could not remove one or more installed application files."
        return 1
    }

    sudo update-desktop-database /usr/local/share/applications >/dev/null 2>&1 || true
    kbuildsycoca6 >/dev/null 2>&1 || true
}

ensure_not_running() {
    if pgrep -x totalsweep >/dev/null 2>&1; then
        echo
        echo "TotalSweep is currently running."
        echo "Close TotalSweep before uninstalling so it cannot recreate settings or data."
        echo
        return 1
    fi
}

keep_data() {
    ensure_not_running || return 1

    echo
    echo "Removing the installed TotalSweep application..."
    remove_installed_files || return 1

    echo
    echo "TotalSweep Uninstaller was removed successfully."
    echo
    echo "Preserved:"
    [[ -e "$DATA_DIR" ]] && echo "  $DATA_DIR"
    [[ -e "$SETTINGS_FILE" ]] && echo "  $SETTINGS_FILE"

    if [[ ! -e "$DATA_DIR" && ! -e "$SETTINGS_FILE" ]]; then
        echo "  No TotalSweep user data/settings were present."
    fi
}

purge_all() {
    ensure_not_running || return 1

    echo
    echo "============================================================"
    echo " WARNING — COMPLETE TOTALSWEEP REMOVAL"
    echo "============================================================"
    echo
    echo "This will permanently remove:"
    echo "  - the installed TotalSweep application"
    echo "  - Quarantine"
    echo "  - History"
    echo "  - preserved package snapshots/cache"
    echo "  - staging/application cache data"
    echo "  - saved TotalSweep settings"
    echo
    echo "After this, TotalSweep will not be able to restore anything"
    echo "that existed only inside its Quarantine or package cache."
    echo
    echo "This does NOT delete this source-code folder or shared system dependencies."
    echo

    printf 'Type PURGE to continue: '
    IFS= read -r answer

    if [[ "$answer" != "PURGE" ]]; then
        echo
        echo "Complete removal cancelled. Nothing was changed."
        return 0
    fi

    echo
    echo "Removing installed application files..."
    remove_installed_files || return 1

    echo "Removing TotalSweep user data..."
    rm -rf -- "$DATA_DIR" || {
        echo "ERROR: Could not remove TotalSweep user data:"
        echo "$DATA_DIR"
        return 1
    }

    echo "Removing TotalSweep settings..."
    rm -f -- "$SETTINGS_FILE" || {
        echo "ERROR: Could not remove TotalSweep settings:"
        echo "$SETTINGS_FILE"
        return 1
    }

    # Remove the TotalSweep settings directory only if nothing else is in it.
    rmdir -- "$CONFIG_ROOT" >/dev/null 2>&1 || true

    echo
    echo "TotalSweep Uninstaller and all TotalSweep-created user data/settings"
    echo "were removed successfully."
}

interactive_menu() {
    echo "============================================================"
    echo " TotalSweep Uninstaller — Uninstall"
    echo "============================================================"
    echo
    echo "Choose what you want to remove:"
    echo
    echo "  1) Remove TotalSweep but KEEP Quarantine, History, cache, and settings"
    echo "  2) COMPLETELY remove TotalSweep and all TotalSweep-created user data/settings"
    echo "  0) Cancel"
    echo
    printf "Selection [1]: "

    IFS= read -r choice
    choice="${choice:-1}"

    case "$choice" in
        1)
            keep_data
            ;;
        2)
            purge_all
            ;;
        0)
            echo "Uninstall cancelled."
            ;;
        *)
            echo "ERROR: Invalid selection."
            return 1
            ;;
    esac
}

case "${1:-}" in
    "")
        interactive_menu
        ;;
    --keep-data)
        keep_data
        ;;
    --purge)
        purge_all
        ;;
    --help|-h)
        usage
        ;;
    *)
        echo "ERROR: Unknown option: $1"
        echo
        usage
        exit 2
        ;;
esac
