#!/bin/bash


declare -r RIGHT="system.login.console"
declare -r PLUGIN="LoginScriptPlugin"
declare -r PLUGIN_PATH="/Library/Security/SecurityAgentPlugins/$PLUGIN.bundle"


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
	local start_homedir=-1	# The array offset where HomeDirMechanism starts.
	local num_homedir=0		# The number of HomeDirMechanism entries.
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
	if [[ $num_homedir -eq 0 ]]; then
		echo "HomeDirMechanism not found"
		return 1
	fi
	
	# Entries have to be inserted into the array in reverse order.
	add_mech $((start_homedir + num_homedir)) "postmount-user" "$plist"
	add_mech $((start_homedir + num_homedir)) "postmount-root" "$plist"
	add_mech $((start_homedir)) "premount-user" "$plist"
	add_mech $((start_homedir)) "premount-root" "$plist"
	
	return 0
}


function usage() {
    echo "Usage: $(basename "$0") [ enable | disable ]"
}

function main() {
    local cmd="$1"
	local plist=$(mktemp -t "$RIGHT.plist")
	local org_plist=$(mktemp -t "$RIGHT.org.plist")
	
	case "$cmd" in
	    "enable") ;;
	    "disable") ;;
	    *)
	        usage
	        rm -f "$plist" "$org_plist"
		    return $EX_USAGE
		    ;;
	esac
	
	if [[ ! -d "$PLUGIN_PATH" ]]; then
	    echo "$PLUGIN_PATH is not installed"
	    rm -f "$plist" "$org_plist"
		return $EX_UNAVAILABLE
	fi
	
	echo "Adding $PLUGIN to $RIGHT"
	
	if authdb read "$RIGHT" > "$plist" 2>/dev/null; then
	    echo "Read $RIGHT from authorization db"
	else
		echo "Failed to read $RIGHT from authorization db"
		rm -f "$plist" "$org_plist"
		return $EX_OSERR
	fi
	cat "$plist" > "$org_plist"
    
    if remove_plugin_from_mechanisms "$plist"; then
    	echo "Removed plugin from $RIGHT mechanisms"
    else
    	echo "Failed to remove plugin from $RIGHT mechanisms"
    	rm -f "$plist" "$org_plist"
    	return $EX_DATAERR
    fi
    
    if [[ "$cmd" == "enable" ]]; then
        if add_plugin_to_mechanisms "$plist"; then
        	echo "Added plugin to $RIGHT mechanisms"
        else
        	echo "Failed to add plugin to $RIGHT mechanisms"
        	rm -f "$plist" "$org_plist"
        	return $EX_DATAERR
        fi
    fi
    
    if ! cmp -s "$plist" "$org_plist"; then
        if authdb write "$RIGHT" < "$plist" 2>/dev/null; then
    	    echo "Wrote $RIGHT to authorization db"
    	else
    	    echo "Failed to write $RIGHT to authorization db"
    	    rm -f "$plist" "$org_plist"
    	    return $EX_NOPERM
    	fi
    else
        echo "No change, $PLUGIN was already ${cmd}d"
    fi
	
    rm -f "$plist" "$org_plist"
    return 0
}

main "$@"
