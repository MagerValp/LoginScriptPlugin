//
//  LoginScriptPlugin.c
//  LoginScriptPlugin
//
//  Created by Per Olofsson on 2014-11-21.
//  Copyright (c) 2014 Göteborgs universitet. All rights reserved.
//

#include <Security/AuthorizationPlugin.h>
#include <Security/AuthSession.h>
#include <Security/AuthorizationTags.h>

#include <stdlib.h>
#include <asl.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <glob.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <libgen.h>
#include <sysexits.h>
#include <pthread.h>


#include "LoginScriptPlugin.h"



/////////////////////////////////////////////////////////////////////
#pragma mark ***** Globals
/////////////////////////////////////////////////////////////////////


static const char *kLoginScriptDir = "/Library/Application Support/LoginScriptPlugin";



/////////////////////////////////////////////////////////////////////
#pragma mark ***** Core Data Structures
/////////////////////////////////////////////////////////////////////


typedef struct PluginRecord PluginRecord;           // forward decl


#pragma mark *     Mechanism

typedef enum {
    kRunAsRoot,
    kRunAsUser
} userContext;

typedef enum {
    kRunBeforeHomedirMount,
    kRunAfterHomedirMount
} scriptPhase;

enum {
    kMechanismMagic = 'MLSP'
};

/// MechanismRecord is the per-mechanism data structure.
///
/// One of these
/// is created for each mechanism that's instantiated, and holds all
/// of the data needed to run that mechanism.
///
/// Mechanisms are single threaded; the code does not have to guard
/// against multiple threads running inside the mechanism simultaneously.
struct MechanismRecord {
    OSType fMagic;         // must be kMechanismMagic
    AuthorizationEngineRef fEngine;
    const PluginRecord *fPlugin;
    userContext fContext;
    scriptPhase fPhase;
};
typedef struct MechanismRecord MechanismRecord;

static Boolean MechanismValid(const MechanismRecord *mechanism)
{
    return (mechanism != NULL)
    && (mechanism->fMagic == kMechanismMagic)
    && (mechanism->fEngine != NULL)
    && (mechanism->fPlugin != NULL);
}


#pragma mark *     Plugin

enum {
    kPluginMagic = 'PLSP'
};

/// PluginRecord is the per-plugin data structure.
///
/// As a plugin may host multiple mechanism, and there's no guarantee
/// that these mechanisms won't be running on different threads, data
/// in this record should be protected from multiple concurrent access.
struct PluginRecord {
    OSType fMagic;         // must be kPluginMagic
    const AuthorizationCallbacks *fCallbacks;
    aslclient fLogClient;
};

static Boolean PluginValid(const PluginRecord *plugin)
{
    return (plugin != NULL)
    && (plugin->fMagic == kPluginMagic)
    && (plugin->fCallbacks != NULL)
    && (plugin->fCallbacks->version >= kAuthorizationCallbacksVersion)
    && (plugin->fLogClient != NULL);
}



/////////////////////////////////////////////////////////////////////
#pragma mark ***** Mechanism Entry Points
/////////////////////////////////////////////////////////////////////


/// Called by the plugin host to create a mechanism, that is, a specific
/// instance of authentication.
///
/// inPlugin is the plugin reference, that is, the value returned by
/// AuthorizationPluginCreate.
///
/// inEngine is a reference to the engine that's running the plugin.
/// We need to keep it around because it's a parameter to all the
/// callbacks.
///
/// mechanismId is the name of the mechanism.  When you configure your
/// mechanism in "/etc/authorization", you supply a string of the
/// form:
///
///     plugin:mechanism[,privileged]
///
/// where:
///
/// * plugin is the name of this bundle (without the extension)
/// * mechanism is the string that's passed to mechanismId
/// * privileged, if present, causes this mechanism to be
///   instantiated in the privileged (rather than the GUI-capable)
///   plug-in host
///
/// You can use the mechanismId to support multiple types of
/// operation within the same plugin code.  For example, your plugin
/// might have two cooperating mechanisms, one that needs to use the
/// GUI and one that needs to run privileged.  This allows you to put
/// both mechanisms in the same plugin.
///
/// outMechanism is a pointer to a place where you return a reference to
/// the newly created mechanism.
static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,
                                AuthorizationEngineRef inEngine,
                                AuthorizationMechanismId mechanismId,
                                AuthorizationMechanismRef *outMechanism)
{
    PluginRecord *plugin;
    MechanismRecord *mechanism;
    userContext context;
    scriptPhase phase;
    
    plugin = (PluginRecord *) inPlugin;
    asl_log(plugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismCreate: inPlugin=%p, inEngine=%p, mechanismId='%s'", inPlugin, inEngine, mechanismId);
    assert(PluginValid(plugin));
    assert(inEngine != NULL);
    assert(mechanismId != NULL);
    assert(outMechanism != NULL);
    
    // Parse the mechanism ID.
    if (strcmp(mechanismId, "premount-root") == 0) {
        context = kRunAsRoot;
        phase = kRunBeforeHomedirMount;
    } else if (strcmp(mechanismId, "premount-user") == 0) {
        context = kRunAsUser;
        phase = kRunBeforeHomedirMount;
    } else if (strcmp(mechanismId, "postmount-root") == 0) {
        context = kRunAsRoot;
        phase = kRunAfterHomedirMount;
    } else if (strcmp(mechanismId, "postmount-user") == 0) {
        context = kRunAsUser;
        phase = kRunAfterHomedirMount;
    } else {
        asl_log(plugin->fLogClient, NULL, ASL_LEVEL_ERR, "Unknown mechanism '%s'", mechanismId);
        *outMechanism = NULL;
        return errAuthorizationInternal;
    }
    
    // Allocate the space for the MechanismRecord.
    mechanism = (MechanismRecord *) malloc(sizeof(*mechanism));
    if (mechanism == NULL) {
        return errAuthorizationInternal;
    }
    
    // Fill it in.
    mechanism->fMagic = kMechanismMagic;
    mechanism->fEngine = inEngine;
    mechanism->fPlugin = plugin;
    mechanism->fContext = context;
    mechanism->fPhase = phase;
    
    *outMechanism = mechanism;
    
    asl_log(plugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismCreate: *outMechanism=%p", *outMechanism);
    
    return errAuthorizationSuccess;
}

/// Get the parent directory of path in a threadsafe manner.
///
/// @param path     A string with a path.
/// @param parent   Pointer to a buffer large enough to hold
///                 the parent directory string.
/// @return true for success.
static bool GetParentDir(const char *path, char **parent) {
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    char *dirnameResult;
    
    pthread_mutex_lock(&lock);
    
    // BSD's dirname() doesn't modify the string passed so we can safely ignore
    // the const warning
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"
    dirnameResult = dirname(path);
    #pragma clang diagnostic pop
    if (dirnameResult == NULL) {
        pthread_mutex_unlock(&lock);
        return false;
    }
    strcpy(*parent, dirnameResult);
    
    pthread_mutex_unlock(&lock);

    return true;
}

/// Verify that a script is suitable for launching as root.
///
/// The script itself and its containing directories should all be owned
/// by root, and not writable by anyone other than root:wheel or root:admin.
/// The path should be absolute, on the boot volume, and must not contain
/// any symbolic links.
static bool VerifyScript(const char *path, aslclient logClient)
{
    struct stat info;
    struct stat rootInfo;
    bool pathOK;
    char *parent;
    
    pathOK = true;
    
    // Reject if we can't stat the root.
    if (lstat("/", &rootInfo)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "Can't stat /");
        pathOK = false;
    }
    
    // Reject if we can't stat the path.
    if (lstat(path, &info)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "Can't stat %s", path);
        pathOK = false;
    }
    
    // Reject if path isn't on boot volume.
    if (info.st_dev != rootInfo.st_dev) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s is not on boot volume", path);
        pathOK = false;
    }
    
    // Reject symbolic links.
    if (S_ISLNK(info.st_mode)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s is a symbolic link", path);
        pathOK = false;
    }
    
    // Ensure that it's owned by root.
    if (info.st_uid != 0) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s isn't owned by root", path);
        pathOK = false;
    }
    
    // Reject world writable paths.
    if (info.st_mode & S_IWOTH) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s is world writable", path);
        pathOK = false;
    }
    
    // Reject group writable paths unless the gid is wheel or admin.
    if (info.st_mode & S_IWGRP && !(info.st_gid == 0 || info.st_gid == 80)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s is group writable", path);
        pathOK = false;
    }
    
    // Path must be executable.
    if (! (info.st_mode & S_IXUSR)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING, "%s isn't executable", path);
        pathOK = false;
    }
    
    // Unless we're at the root, recursively check the parent directory.
    if (strcmp(path, "/") == 0) {
        return pathOK;
    
    } else {
        
        parent = malloc(strlen(path) + 1);
        if (parent == NULL) {
            asl_log(logClient, NULL, ASL_LEVEL_WARNING, "memory allocation failed");
            return false;
        }
        
        if (! GetParentDir(path, &parent)) {
            asl_log(logClient, NULL, ASL_LEVEL_WARNING, "failed to determine parent directory");
            free(parent);
            return false;
        }
        
        pathOK = VerifyScript(parent, logClient) && pathOK;
        free(parent);
        return pathOK;
    }
}

/// Execute the script at path as uid/gid.
///
/// Fail authorization if the script exits with EX_NOPERM, otherwise proceed.
static AuthorizationResult ExecuteScript(const char *path,
                                         uid_t uid,
                                         gid_t gid,
                                         const char *home,
                                         userContext context,
                                         aslclient logClient)
{
    AuthorizationResult result;
    pid_t childPid;
    int childStatus;
    long maxfd;
    long fd;
    char uidStr[3 * sizeof(uid_t) + 1];
    char gidStr[3 * sizeof(gid_t) + 1];
    char cfUserTextEncoding[2 * sizeof(uid_t) + 7];
    
    result = kAuthorizationResultAllow;
    
    if (! VerifyScript(path, logClient)) {
        asl_log(logClient, NULL, ASL_LEVEL_WARNING,
                "Not executing %s", path);
        return result;
    }
    
    asl_log(logClient, NULL, ASL_LEVEL_NOTICE,
            "Executing %s with uid=%d, gid=%d, home='%s'", path, uid, gid, home);
    
    childPid = fork();
    if (childPid == -1) {
        // Error.
        asl_log(logClient, NULL, ASL_LEVEL_WARNING,
                "Fork failed with errno %d", errno);
    } else if (childPid == 0) {
        // Child.
#warning REVIEW: User commands still run in root's session.
        if (context == kRunAsUser) {
            if (setgid(gid) || setuid(uid)) {
                asl_log(logClient, NULL, ASL_LEVEL_ERR,
                        "setgid/setuid failed, aborting execution of %s", path);
                exit(EX_NOPERM);
            }
        }
        
        // Mark any stray file descriptors for closing.
        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0) {
            maxfd = OPEN_MAX;
        }
        for (fd = STDERR_FILENO + 1; fd < maxfd; fd++) {
            // Use FD_CLOEXEC instead of close to avoid libdispatch crash.
            if (fcntl((int)fd, F_SETFD, FD_CLOEXEC) == -1) {
                if (errno != EBADF) {
                    asl_log(logClient, NULL, ASL_LEVEL_ERR,
                            "Marking file descriptor %ld for closing failed with errno %d", fd, errno);
                    exit(EX_NOPERM);
                }
            }
        }
        
        // Set default text encoding for Core Foundation.
        snprintf(cfUserTextEncoding, sizeof(cfUserTextEncoding), "0x%X:0:0", getuid());
        if (setenv("__CF_USER_TEXT_ENCODING", cfUserTextEncoding, 1) != 0) {
            asl_log(logClient, NULL, ASL_LEVEL_WARNING,
                    "Couldn't set __CF_USER_TEXT_ENCODING");
        }
        
        snprintf(uidStr, sizeof(uidStr), "%d", uid);
        snprintf(gidStr, sizeof(gidStr), "%d", gid);
        execl(path, path, uidStr, gidStr, home, (char *)NULL);
        // The following only executes if execl() fails.
        asl_log(logClient, NULL, ASL_LEVEL_ERR,
                "Executing %s failed with errno %d", path, errno);
        exit(EX_NOPERM);
        
    } else {
        // Parent.
        asl_log(logClient, NULL, ASL_LEVEL_DEBUG,
                "Waiting for child with pid %d", childPid);
        if (waitpid(childPid, &childStatus, 0) != childPid) {
            asl_log(logClient, NULL, ASL_LEVEL_DEBUG,
                    "Received errno %d while waiting for child", errno);
        }
        if (WIFSIGNALED(childStatus)) {
            asl_log(logClient, NULL, ASL_LEVEL_WARNING,
                    "%s died with signal %d", path, WTERMSIG(childStatus));
        } else {
            asl_log(logClient, NULL, ASL_LEVEL_WARNING,
                    "%s exited with status %d", path, WEXITSTATUS(childStatus));
            if (WEXITSTATUS(childStatus) == EX_NOPERM) {
                // Fail authorization.
                asl_log(logClient, NULL, ASL_LEVEL_NOTICE,
                        "%s denied authorization", path);
                result = kAuthorizationResultDeny;
            }
        }
    }
    
    return result;
}

#define NOBODY -2

/// Called by the system to invoke a mechanism.
///
/// This executes a premount or postmount script, either as root or as the user.
static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism)
{
    OSStatus err;
    MechanismRecord *mechanism;
    
    AuthorizationResult result;
    
    uid_t uid;
    gid_t gid;
    char *home;
    AuthorizationContextFlags authContextFlags;
    const AuthorizationValue *value;
    
    glob_t g;
    char scriptPattern[MAXPATHLEN];
    int i;
    
    mechanism = (MechanismRecord *) inMechanism;
    asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismInvoke: inMechanism=%p", inMechanism);
    assert(MechanismValid(mechanism));
    
    result = kAuthorizationResultAllow;
    
    // Retrieve values from the authorization context.
    uid = NOBODY;
    gid = NOBODY;
    home = NULL;
    if (mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine, "uid", &authContextFlags, &value) == errAuthorizationSuccess && value->length == sizeof(uid_t)) {
        uid = *(const uid_t *)value->data;
    }
    if (mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine, "gid", &authContextFlags, &value) == errAuthorizationSuccess && value->length == sizeof(gid_t)) {
        gid = *(const gid_t *)value->data;
    }
    if (mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine, "home", &authContextFlags, &value) == errAuthorizationSuccess) {
        if ((value->length > 0) && (((const char *) value->data)[value->length - 1] == 0)) {
            home = value->data;
        } else {
            asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_WARNING,
                    "GetContextValue didn't return a zero terminated string for home");
        }
    }
    
    if (uid == NOBODY || gid == NOBODY) {
        asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_WARNING,
                "Can't execute script, uid lookup failed");
    } else if (home == NULL) {
        asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_WARNING,
                "Can't execute script, homedir lookup failed");
    } else {
        
        // Find all scripts matching the current phase and context, aborting if
        // execution doesn't return kAuthorizationResultAllow.
        snprintf(scriptPattern, sizeof(scriptPattern), "%s/%s-%s*",
                 kLoginScriptDir,
                 mechanism->fPhase == kRunBeforeHomedirMount ? "premount" : "postmount",
                 mechanism->fContext == kRunAsRoot ? "root" : "user");
        glob(scriptPattern, 0, NULL, &g);
        for (i = 0; i < g.gl_pathc; i++) {
            result = ExecuteScript(g.gl_pathv[i], uid, gid, home, mechanism->fContext, mechanism->fPlugin->fLogClient);
            if (result != kAuthorizationResultAllow) {
                break;
            }
        }
        globfree(&g);
        
    }
    
    if ((err = mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine, result)) != errAuthorizationSuccess) {
        asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_ERR,
                "Setting authorization result failed with error %d", err);
    }
    
    asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismInvoke: result=%d", result);
    
    return result;
}

/// Called by the system to deactivate the mechanism, in the traditional
/// GUI sense of deactivating a window.  After your plugin has deactivated
/// it's UI, it should call the DidDeactivate callback.
///
/// In our case, we have no UI, so we just call DidDeactivate immediately.
static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism)
{
    OSStatus err;
    MechanismRecord *mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismDeactivate: inMechanism=%p", inMechanism);
    assert(MechanismValid(mechanism));
    
    err = mechanism->fPlugin->fCallbacks->DidDeactivate(mechanism->fEngine);
    
    asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismDeactivate: err=%ld", (long) err);
    
    return err;
}

/// Called by the system when it's done with the mechanism.
static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism)
{
    MechanismRecord *mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    asl_log(mechanism->fPlugin->fLogClient, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:MechanismDestroy: inMechanism=%p", inMechanism);
    assert(MechanismValid(mechanism));
    
    free(mechanism);
    
    return errAuthorizationSuccess;
}



/////////////////////////////////////////////////////////////////////
#pragma mark ***** Plugin Entry Points
/////////////////////////////////////////////////////////////////////


/// Called by the system when it's done with the plugin.
/// All of the mechanisms should have been destroyed by this time.
static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin)
{
    PluginRecord *plugin;
    
    plugin = (PluginRecord *) inPlugin;
    assert(PluginValid(plugin));
    
    asl_close(plugin->fLogClient);
    
    free(plugin);
    
    return errAuthorizationSuccess;
}

/// gPluginInterface is the plugin's dispatch table, a pointer to
/// which you return from AuthorizationPluginCreate. This is what
/// allows the system to call the various entry points in the plugin.
static AuthorizationPluginInterface gPluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy
};

// The primary entry point of the plugin.  Called by the system
// to instantiate the plugin.
//
// callbacks is a pointer to a bunch of callbacks that allow
// your plugin to ask the system to do operations on your behalf.
//
// outPlugin is a pointer to a place where you can return a
// reference to the newly created plugin.
//
// outPluginInterface is a pointer to a place where you can return
// a pointer to your plugin dispatch table.
extern OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                          AuthorizationPluginRef *outPlugin,
                                          const AuthorizationPluginInterface **outPluginInterface)
{
    PluginRecord *plugin;
    aslclient log_client;
    
    log_client = asl_open("LoginScriptPlugin", "se.gu.it.LoginScriptPlugin", 0);
    if (log_client == NULL) {
        syslog(LOG_ERR, "LoginScriptPlugin: asl_open() failed");
        return errAuthorizationInternal;
    }
    
    asl_log(log_client, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:AuthorizationPluginCreate: callbacks=%p", callbacks);
    
    assert(callbacks != NULL);
    assert(callbacks->version >= kAuthorizationCallbacksVersion);
    assert(outPlugin != NULL);
    assert(outPluginInterface != NULL);
    
    // Create the plugin.
    plugin = (PluginRecord *) malloc(sizeof(*plugin));
    if (plugin == NULL) {
        asl_log(log_client, NULL, ASL_LEVEL_ERR, "Plugin allocation failed");
        return errAuthorizationInternal;
    }
    
    // Fill it in.
    plugin->fMagic     = kPluginMagic;
    plugin->fCallbacks = callbacks;
    plugin->fLogClient = log_client;
    
    *outPlugin = plugin;
    *outPluginInterface = &gPluginInterface;
    
    asl_log(log_client, NULL, ASL_LEVEL_DEBUG, "LoginScriptPlugin:AuthorizationPluginCreate: *outPlugin=%p, *outPluginInterface=%p", *outPlugin, *outPluginInterface);
    
    return errAuthorizationSuccess;
}
