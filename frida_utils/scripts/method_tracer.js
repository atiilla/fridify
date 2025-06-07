/*
 * Method Tracer Script
 * This script traces method calls in a specified class
 */

setTimeout(function() {
    Java.perform(function() {
        console.log("[+] Method Tracer Script Loaded");
        
        // Usage: 
        // 1. Set the target class name
        // 2. Optionally set specific method names to trace
        
        var targetClassName = "com.example.targetapp.TargetClass";
        var specificMethods = []; // Leave empty to trace all methods, or add method names to trace specific methods
        
        try {
            var targetClass = Java.use(targetClassName);
            
            // Get all methods if specificMethods is empty
            var methods = specificMethods.length === 0 ? 
                Object.getOwnPropertyNames(targetClass.__proto__).filter(function(m) {
                    return m !== 'constructor' && !m.startsWith('$') && typeof targetClass[m] === 'function';
                }) : specificMethods;
            
            console.log("[+] Tracing " + methods.length + " methods in " + targetClassName);
            
            methods.forEach(function(method) {
                try {
                    // Get method overloads
                    var overloadCount = targetClass[method].overloads.length;
                    
                    // Hook each overload
                    for (var i = 0; i < overloadCount; i++) {
                        targetClass[method].overloads[i].implementation = function() {
                            var argTypes = this[method].argumentTypes;
                            var returnType = this[method].returnType.className;
                            
                            // Build argument string
                            var args = [];
                            for (var j = 0; j < arguments.length; j++) {
                                var arg = arguments[j];
                                if (arg === null) {
                                    args.push("null");
                                } else if (typeof arg === 'object') {
                                    args.push(arg.toString());
                                } else {
                                    args.push(JSON.stringify(arg));
                                }
                            }
                            
                            console.log("[+] Called: " + targetClassName + "." + method + "(" + args.join(", ") + ")");
                            
                            // Call original method and get result
                            var result = this[method].apply(this, arguments);
                            
                            // Log result
                            if (result === null) {
                                console.log("[+] Result: null");
                            } else if (typeof result === 'object') {
                                console.log("[+] Result: " + result.toString());
                            } else {
                                console.log("[+] Result: " + JSON.stringify(result));
                            }
                            
                            // Stack trace (uncomment if needed)
                            // console.log(Thread.backtrace(this.ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
                            
                            return result;
                        };
                    }
                    
                    console.log("[+] Hooked " + overloadCount + " overloads of " + method);
                } catch (err) {
                    console.log("[-] Failed to hook method " + method + ": " + err);
                }
            });
            
            console.log("[+] All methods hooked successfully");
            
        } catch (err) {
            console.log("[-] Error hooking class " + targetClassName + ": " + err);
        }
        
        console.log("[+] Method Tracer Setup Completed");
    });
}, 0); 