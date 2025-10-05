import subprocess
import shlex
from ..logger import logger

# --- Pre-written Frida Scripts ---
# In a real application, you would load these from .js files.

FRIDA_SCRIPTS = {
    # --- Basic Scripts ---
    "list_classes": """
    // Lists all classes loaded by the application's runtime.
    Java.perform(function() {
        console.log("[*] Listing all loaded classes...");
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                console.log(className);
            },
            onComplete: function() {
                console.log("[*] Class listing complete.");
            }
        });
    });
    """,
    "trace_class_methods": """
    // Traces all methods of a specific class. Replace 'com.example.SecretClass'.
    Java.perform(function() {
        var className = 'com.example.SecretClass';
        console.log(`[*] Tracing methods of class: ${className}`);
        try {
            var targetClass = Java.use(className);
            var methods = targetClass.class.getDeclaredMethods();
            methods.forEach(function(method) {
                var methodName = method.getName();
                var overloads = targetClass[methodName].overloads;
                overloads.forEach(function(overload) {
                    console.log(`  Hooking: ${className}.${methodName}`);
                    overload.implementation = function() {
                        console.log(`[+] Called: ${className}.${methodName}`);
                        var result = this[methodName].apply(this, arguments);
                        console.log(`  Result: ${result}`);
                        return result;
                    };
                });
            });
        } catch (e) {
            console.log(`[!] Failed to trace class ${className}: ${e.message}`);
        }
    });
    """,

    # --- Intermediate Scripts ---
    "bypass_ssl_pinning": """
    // A common script to bypass SSL certificate pinning.
    Java.perform(function() {
        console.log("[*] Attempting to bypass SSL Pinning...");
        // This is a generic script and might need customization for specific apps.
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.apkghost.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        
        try {
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log('[+] SSLContext.init() hooked. Bypassing pinning.');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch (e) {
            console.log(`[!] Failed to hook SSLContext: ${e.message}`);
        }
    });
    """,
    "monitor_intents": """
    // Logs intents being sent by the application, useful for tracking navigation and IPC.
    Java.perform(function () {
        console.log("[*] Monitoring intents...");
        var Activity = Java.use('android.app.Activity');
        Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
            var action = intent.getAction() ? intent.getAction().toString() : 'No Action';
            var data = intent.getDataString() ? intent.getDataString().toString() : 'No Data';
            console.log(`[+] Intent launched: Action: ${action}, Data: ${data}`);
            this.startActivity(intent);
        };
    });
    """,

    # --- Advanced Scripts ---
    "hook_native_function": """
    // Hooks a native function from a .so library. Replace 'libnative-lib.so' and 'stringFromJNI'.
    console.log("[*] Attempting to hook native function...");
    var libName = 'libnative-lib.so';
    var funcName = 'stringFromJNI'; // Example function name

    try {
        var funcPtr = Module.findExportByName(libName, funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    console.log(`[+] ${libName}->${funcName} called!`);
                    // console.log("  Arg0: " + args[0]); // Can log arguments if needed
                },
                onLeave: function(retval) {
                    console.log(`  [+] Return value: ${retval}`);
                    // Can also modify the return value, e.g., retval.replace(0x1);
                }
            });
        } else {
            console.log(`[!] Could not find export: ${funcName} in ${libName}`);
        }
    } catch(e) {
        console.log(`[!] Failed to hook native function: ${e.message}`);
    }
    """,
    "trace_file_io": """
    // Original script to trace file I/O operations.
    Java.perform(function() {
        console.log("[*] Tracing file I/O operations...");
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            console.log("File Read: " + file.getAbsolutePath());
            return this.$init(file);
        };
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            console.log("File Write: " + file.getAbsolutePath());
            return this.$init(file);
        };
    });
    """
}

def run_frida_script(script_name, package_name):
    """Executes a Frida script against a target package on a connected device."""
    logger.info(f"Running Frida script '{script_name}' on '{package_name}'")
    
    if script_name not in FRIDA_SCRIPTS:
        return f"Error: Frida script '{script_name}' not found."
    
    script_content = FRIDA_SCRIPTS[script_name]
    
    # The -U flag tells Frida to use a connected USB device.
    # The --no-pause flag ensures the app starts immediately.
    cmd = f"frida -U -f {shlex.quote(package_name)} --no-pause -e '{script_content}'"
    
    try:
        # We use Popen to stream the output in real-time
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # This function will be a generator, yielding output as it comes
        for line in iter(process.stdout.readline, ''):
            yield line.strip()
            
    except Exception as e:
        yield f"Frida execution error: {e}"