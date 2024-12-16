#!/bin/sh

APP_NAME="CSWIV"
SETTINGS_FILE="/etc/$APP_NAME/settings.conf"
LOG_FILE="/var/log/$APP_NAME.log"
STATUS_FILE="/etc/$APP_NAME/status.log"
STARTUP_FILE="/etc/init.d/cswiv_startup"

GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

log() { printf "${GREEN}[*] $1${RESET}\n"; echo "[INFO] $1" >> "$LOG_FILE"; }
error() { echo -e "${RED}[!] $1${RESET}"; echo "[ERROR] $1" >> "$LOG_FILE"; exit 1; }

# --- Display Warning ---
display_warning() {
    cat <<EOF
${RED}WARNING:${RESET} 
This script modifies system-level files and settings on your device.
It may cause irreparable damage and is provided AS-IS with no warranty.
The authors of this tool are NOT responsible for any damage, data loss, 
or issues caused by using this script. Proceed only if you understand 
the risks and have backed up your data.

Press Ctrl+C to cancel or wait 10 seconds to proceed...
EOF
    sleep 10
}

# --- Ensure iSH Environment ---
check_ish_environment() {
    if ! uname -a | grep -qi "Linux"; then
        error "This script must be run inside the iSH app or a Linux-like shell."
    fi
    log "iSH/Linux environment detected."
}

# --- Install Minimal Dependencies ---
install_dependencies() {
    log "Installing minimal dependencies..."
    apk update || error "Failed to update APK repositories."
    apk add curl openssh python3 py3-pip busybox-initscripts || error "Failed to install required dependencies."
}

# --- Disable Restrictive Systems (e.g., crutil, fdisk) ---
disable_restrictive_systems() {
    log "Disabling restrictive systems..."
    if [ -f "/System/Library/LaunchDaemons/com.apple.mobile.crutil.plist" ]; then
        plutil -replace KeepAlive -bool NO "/System/Library/LaunchDaemons/com.apple.mobile.crutil.plist" || error "Failed to disable crutil."
        log "crutil disabled."
    else
        log "crutil not found or already disabled."
    fi

    if command -v fdisk >/dev/null 2>&1; then
        chmod 000 "$(command -v fdisk)" || error "Failed to disable fdisk."
        log "fdisk disabled."
    else
        log "fdisk not found or already disabled."
    fi
}

# --- Enable Modification-Friendly Systems ---
enable_modification_systems() {
    log "Enabling modification-friendly systems..."
    rc-service sshd start || error "Failed to start SSH service."
    log "SSH service started."

    DEVICE_UDID=$(idevice_id -l | head -n 1)
    if [ -n "$DEVICE_UDID" ]; then
        idevicedebug -u "$DEVICE_UDID" enable || error "Failed to enable Developer Mode."
        log "Developer Mode enabled for UDID: $DEVICE_UDID."
    else
        log "No connected device found for Developer Mode."
    fi
}

# --- Create Settings File ---
create_settings_file() {
    log "Creating settings file at $SETTINGS_FILE..."
    mkdir -p "$(dirname "$SETTINGS_FILE")"
    cat <<EOF > "$SETTINGS_FILE"
# CSWIV Settings File
ENABLE_CRUTIL_DISABLE=true
ENABLE_FDISK_DISABLE=true
ENABLE_DEVELOPER_MODE=true
ENABLE_SSH=true
SHOW_STARTUP_STATUS=true
EOF
    log "Settings file created."
}

# --- Apply Settings ---
apply_settings() {
    log "Applying settings from $SETTINGS_FILE..."
    [ -f "$SETTINGS_FILE" ] || error "Settings file not found. Please run the script to generate it first."

    # Source the settings file
    . "$SETTINGS_FILE"

    if [ "$ENABLE_CRUTIL_DISABLE" = "true" ]; then
        disable_restrictive_systems
    fi

    if [ "$ENABLE_FDISK_DISABLE" = "true" ]; then
        disable_restrictive_systems
    fi

    if [ "$ENABLE_DEVELOPER_MODE" = "true" ]; then
        enable_modification_systems
    fi

    if [ "$ENABLE_SSH" = "true" ]; then
        enable_modification_systems
    fi
}

# --- Create Status Check ---
generate_status_report() {
    log "Generating status report..."
    mkdir -p "$(dirname "$STATUS_FILE")"
    echo "CSWIV Operational Status:" > "$STATUS_FILE"

    echo "SSH Service: $(rc-status | grep sshd >/dev/null && echo 'Enabled' || echo 'Disabled')" >> "$STATUS_FILE"
    echo "crutil Status: $(plutil -p /System/Library/LaunchDaemons/com.apple.mobile.crutil.plist | grep -q 'KeepAlive = 0' && echo 'Disabled' || echo 'Enabled')" >> "$STATUS_FILE"
    echo "fdisk Status: $(test -x "$(command -v fdisk)" && echo 'Enabled' || echo 'Disabled')" >> "$STATUS_FILE"

    log "Status report saved to $STATUS_FILE."
}

# --- Configure Startup Item ---
configure_startup() {
    log "Configuring startup item at $STARTUP_FILE..."
    cat <<EOF > "$STARTUP_FILE"
#!/bin/sh
# CSWIV Startup Script

sh /etc/$APP_NAME/cswiv_jailbreak.sh --status
EOF
    chmod +x "$STARTUP_FILE"
    rc-update add $(basename "$STARTUP_FILE") || error "Failed to add startup script to init system."
    log "Startup item configured."
}

# --- Show Status ---
show_status() {
    if [ -f "$STATUS_FILE" ]; then
        cat "$STATUS_FILE"
    else
        error "Status file not found."
    fi
}

# --- Main Function ---
main() {
    display_warning
    check_ish_environment
    install_dependencies
    create_settings_file
    apply_settings
    generate_status_report
    configure_startup
    if [ "$1" = "--status" ]; then
        show_status
    fi
    log "$APP_NAME installation and configuration completed!"
}

main "$@"
