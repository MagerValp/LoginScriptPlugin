LoginScriptPlugin
=================

This is an implementation based on [TN2228, Running At Login](https://developer.apple.com/library/mac/technotes/tn2228) that allows you to execute scripts when a user logs in. It provides a replacement for LoginHooks (which have been deprecated) and have the advantage over LaunchAgents that it executes before any user processes are loaded, avoiding potential race conditions.


WARNING
-------

The plugin is enabled by configuring the authorization database. **Misconfiguration can lead to no one being able to log in at the login window.** Make sure you have some way to recover in case of a mishap, e.g. ssh, ARD, or single user mode.


System Requirements
-------------------

The plugin is currently tested on 10.9, but should work on 10.7 or newer.


Installation
------------

There is no installer package yet. Compile the plugin with Xcode 6.1, copy it to `/Library/Security/SecurityAgentPlugins`, and change the owner to `root:wheel`. Then run `configureplugin.sh enable` to activate the plugin.


Configuration
-------------

*Warning: this is likely to change in a later release.*

Create the folder `/Library/Application Support/LoginScriptPlugin` and place scripts there. The plugin looks for the following four scripts:

* `premount-root`
* `premount-user`
* `postmount-root`
* `postmount-user`

They will execute in that order, either before or after the user's home directory has been mounted, and either as root or the user that's logging in. Make sure the folder and all the scripts are owned by `root:wheel` and not writable by anyone else.


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
