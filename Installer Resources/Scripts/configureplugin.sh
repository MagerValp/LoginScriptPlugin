#!/bin/bash


declare -r RIGHT="system.login.console"
declare -r PLUGIN="LoginScriptPlugin"
declare -r PLUGIN_PATH="/Library/Security/SecurityAgentPlugins/$PLUGIN.bundle"
declare -r SCRIPT_DIR="/Library/Application Support/$PLUGIN"


declare -ri EX_OK=0
declare -ri EX_USAGE=64         # The command was used incorrectly.
declare -ri EX_DATAERR=65       # Input data was incorrect in some way.
declare -ri EX_NOINPUT=66       # Input file did not exist or wasn't readable.
declare -ri EX_NOUSER=67        # The user specified did not exist.
declare -ri EX_NOHOST=68        # The host specified did not exist.
declare -ri EX_UNAVAILABLE=69   # A service is unavailable.
declare -ri EX_SOFTWARE=70      # An internal software error has been detected.
declare -ri EX_OSERR=71         # An operating system error has been detected.
declare -ri EX_OSFILE=72        # Some system file is unavailable.
declare -ri EX_CANTCREAT=73     # A specified output file cannot be created.
declare -ri EX_IOERR=74         # An error occurred while doing I/O.
declare -ri EX_TEMPFAIL=75      # Temporary failure.
declare -ri EX_PROTOCOL=76      # Remote protocol failure.
declare -ri EX_NOPERM=77        # Required permission missing.
declare -ri EX_CONFIG=78        # Something was unconfigured or misconfigured.


# Ensure that permissions are valid.
function check_script_perms() {
    local path="$1"
    local result=0
    
    # Reject if path isn't on boot volume.
    if [[ $(stat -f "%d" "$path") != $(stat -f "%d" "/") ]]; then
        echo "Warning: $path is not on boot volume"
        result=1
    fi
    
    # Reject symbolic links.
    if [[ -h "$path" ]]; then
        echo "Warning: $path is a symbolic link"
        result=1
    fi
    
    # Ensure that it's owned by root.
    if [[ $(stat -f "%u" "$path") -ne 0 ]]; then
        echo "Warning: $path isn't owned by root"
        result=1
    fi
    
    # Reject world writable paths.
    if [[ $(ls -ld "$path" | cut -c 9) == "w" ]]; then
        echo "Warning: $path is world writable"
        result=1
    fi
    
    # Reject group writable paths unless the gid is wheel.
    if [[ $(ls -ld "$path" | cut -c 6) == "w" ]]; then
        if [[ $(stat -f "%g" "$path") -ne 0 ]]; then
            echo "Warning: $path is group writable"
            result=1
        fi
    fi
    
    # Path must be executable.
    if [[ ! -x "$path" ]]; then
        echo "Warning: $path isn't executable"
        result=1
    fi
    
    return $result
}

# Check permissions on the plugin's support directory.
function check_script_dir() {
    local script_names=( \
        "premount-root"  \
        "premount-user"  \
        "postmount-root" \
        "postmount-user" \
    )
    local path
    local script
    
    if [[ ! -d "$SCRIPT_DIR" ]]; then
        echo "Warning: $SCRIPT_DIR does not exist"
    fi
    
    path="$SCRIPT_DIR"
    while true; do
        if [[ -d "$path" ]]; then
            if ! check_script_perms "$path"; then
                echo "Warning: wrong permissions on $path"
            fi
        fi
        if [[ "$path" == "/" ]]; then
            break
        fi
        path="$(dirname "$path")"
    done
    
    for name in "${script_names[@]}"; do
        for path in "$SCRIPT_DIR/$name"-*; do
            if [[ -e "$path" ]]; then
                if ! check_script_perms "$path"; then
                    echo "Warning: wrong permissions on $path"
                fi
            fi
        done
    done
}

# Execute security authorizationdb command.
function authdb() {
    /usr/bin/security authorizationdb "$@"
}

# Remove plugin from mechanisms.
function remove_plugin_from_mechanisms() {
    local plist="$1"
    local i=0
    local mech
    
    while mech=$(/usr/libexec/PlistBuddy -c "print :mechanisms:$i" "$plist" 2>/dev/null); do
        if [[ "${mech%%:*}" == "$PLUGIN" ]]; then
            /usr/libexec/PlistBuddy -c "delete :mechanisms:$i" "$plist"
        else
            let i++
        fi
    done
    
    return 0
}

# Insert a mechanism entry.
function add_mech() {
    local offset="$1"
    local mech="$2"
    local plist="$3"
    
    /usr/libexec/PlistBuddy -c "add :mechanisms:$((offset)) string ${PLUGIN}:$mech,privileged" "$plist"
}

# Insert entries before and after HomeDirMechanism in the rights plist.
function add_plugin_to_mechanisms() {
    local plist="$1"
    local i
    local start_homedir=-1  # The array offset where HomeDirMechanism starts.
    local num_homedir=0     # The number of HomeDirMechanism entries.
    local last_mech_offset
    local mech
    
    # Find the HomeDirMechanism entries in the mechanisms array.
    for (( i = 0; ; i++ )); do
        if ! mech=$(/usr/libexec/PlistBuddy -c "print :mechanisms:$i" "$plist" 2>/dev/null); then
            break
        fi
        if [[ "${mech%%:*}" == "HomeDirMechanism" ]]; then
            if [[ $num_homedir -eq 0 ]]; then
                start_homedir=$i
                num_homedir=1
            else
                let num_homedir++
            fi
        fi
    done
    last_mech_offset=$(( i - 1 ))
    if [[ $num_homedir -eq 0 ]]; then
        echo "HomeDirMechanism not found"
        return 1
    fi
    
    # Entries have to be inserted into the array in reverse order.
    add_mech $((last_mech_offset)) "postmount-user" "$plist"
    add_mech $((last_mech_offset)) "postmount-root" "$plist"
    add_mech $((start_homedir)) "premount-user" "$plist"
    add_mech $((start_homedir)) "premount-root" "$plist"
    
    return 0
}


declare -a tempfiles
cleanup_tempfiles() {
    rm -f "${tempfiles[@]}"
}
trap cleanup_tempfiles EXIT

function usage() {
    echo "Usage: $(basename "$0") [ enable | disable ]"
}

function main() {
    local cmd="$1"
    local plist=$(mktemp -t "$RIGHT.plist")
    tempfiles+=("$plist")
    local org_plist=$(mktemp -t "$RIGHT.org.plist")
    tempfiles+=("$org_plist")
    
    case "$cmd" in
        "enable")
            echo "* Adding $PLUGIN to $RIGHT"
            ;;
        "disable")
            echo "* Removing $PLUGIN from $RIGHT"
            ;;
        *)
            usage
            return $EX_USAGE
            ;;
    esac
    
    # Make sure the plugin is installed before trying to enable it.
    if [[ "$cmd" == "enable" ]]; then
        if [[ ! -d "$PLUGIN_PATH" ]]; then
            echo "$PLUGIN_PATH is not installed"
            return $EX_UNAVAILABLE
        fi
    fi
    
    # Read the right from the authorization db.
    if authdb read "$RIGHT" > "$plist" 2>/dev/null; then
        echo "Read $RIGHT from authorization db"
    else
        echo "Failed to read $RIGHT from authorization db"
        return $EX_OSERR
    fi
    # Save a copy of the unmodified right.
    cat "$plist" > "$org_plist"
    
    # Remove the plugin if it's enabled.
    if remove_plugin_from_mechanisms "$plist"; then
        echo "Removed plugin from $RIGHT mechanisms"
    else
        echo "Failed to remove plugin from $RIGHT mechanisms"
        return $EX_DATAERR
    fi
    
    # If we're enabling, add the plugin.
    if [[ "$cmd" == "enable" ]]; then
        if add_plugin_to_mechanisms "$plist"; then
            echo "Added plugin to $RIGHT mechanisms"
        else
            echo "Failed to add plugin to $RIGHT mechanisms"
            return $EX_DATAERR
        fi
    fi
    
    # If the right changed, write it back to the authorization db.
    if ! cmp -s "$plist" "$org_plist"; then
        if authdb write "$RIGHT" < "$plist" 2>/dev/null; then
            echo "Wrote $RIGHT to authorization db"
        else
            echo "Failed to write $RIGHT to authorization db"
            return $EX_NOPERM
        fi
    else
        echo "No change, $PLUGIN was already ${cmd}d"
    fi
    
    if [[ "$cmd" == "enable" ]]; then
        echo "* Checking script permissions"
        check_script_dir
    fi
    
    return 0
}

main "$@"
