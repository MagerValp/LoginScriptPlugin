LoginScriptPlugin
=================

This is an implementation based on [TN2228, Running At Login](https://developer.apple.com/library/mac/technotes/tn2228) that allows you to execute scripts when a user logs in. It provides a replacement for LoginHooks (which have been deprecated) and have the advantage over LaunchAgents that it executes before any agents or applications are loaded, avoiding potential race conditions.


WARNING
-------

The plugin is enabled by configuring the authorization database. **Misconfiguration can lead to no one being able to log in at the login window.** Make sure you have some way to recover in case of a mishap, e.g. ssh, ARD, or single user mode.


System Requirements
-------------------

The plugin is currently tested on 10.9, but should work on 10.7 or newer.


Installation
------------

Download and install the [latest package](https://github.com/MagerValp/LoginScriptPlugin/releases).


Uninstallation
--------------

* Delete `/Library/Security/SecurityAgentPlugins/LoginScriptPlugin.bundle`
* Run `configureplugin.sh disable`. The script can be found under [Installer Resources/Scripts](https://github.com/MagerValp/LoginScriptPlugin/tree/master/Installer Resources/Scripts).


Configuration
-------------

Create the folder `/Library/Application Support/LoginScriptPlugin` and place your login scripts there. Make sure the folder and all the scripts are owned by `root:wheel` and not writable by anyone else. The plugin will execute scripts in this directory either before or after the user's home directory has been mounted, and either as root or the user that's logging in, determined by the script's name. The plugin looks for scripts that match the following patterns, in this order:

* `premount-root-*`
* `premount-user-*`
* `postmount-root-*`
* `postmount-user-*`

For example a script named `postmount-user-com.example.redirect_library.sh` will execute as the user logging in after the home directory has been mounted. The following arguments are passed to each script:

Variable | Value | Example
-------- | ----- | -------
`$1`     | UID   | 501
`$2`     | GID   | 20
`$3`     | Home  | /Users/ladmin

Please note that since the scripts are executing before the session has been fully initialized you can't count on regular shell variables being set to expected values. Notably `$HOME`, `$USER` **are not set** and `$PATH` is **very rudimentary**.

Scripts should return 0 to let the login proceed, or 77 (`EX_NOPERM`) to fail authorization.


License
-------

    Copyright 2014 Per Olofsson, University of Gothenburg. All rights reserved.
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
