"""Functions for interacting with applications on Android devices."""

from frida_utils.common import (
    subprocess, logger, frida, os, time
)

def list_packages(filter_keyword=None):
    """List installed packages on the device, optionally filtered by keyword."""
    try:
        result = subprocess.run(
            ["adb", "shell", "pm", "list", "packages"], 
            capture_output=True, 
            text=True
        )
        
        packages = [line.replace("package:", "").strip() 
                   for line in result.stdout.splitlines()]
        
        if filter_keyword:
            packages = [pkg for pkg in packages if filter_keyword.lower() in pkg.lower()]
        
        return {"status": "success", "packages": packages}
    except Exception as e:
        logger.error(f"Error listing packages: {str(e)}")
        return {"status": "error", "message": str(e)}

def get_available_devices():
    """Get a list of available Frida devices."""
    try:
        devices = frida.enumerate_devices()
        device_info = [{"id": device.id, "name": device.name, "type": device.type} 
                      for device in devices]
        return {"status": "success", "devices": device_info}
    except Exception as e:
        logger.error(f"Error getting Frida devices: {str(e)}")
        return {"status": "error", "message": str(e)}

def get_running_applications():
    """Get a list of running applications on the device."""
    try:
        # Try to find the emulator device specifically
        devices = frida.enumerate_devices()
        device = None
        for d in devices:
            if "emulator" in d.id:
                device = d
                break
        
        if device is None:
            device = frida.get_usb_device(timeout=5)
            
        processes = device.enumerate_processes()
        return {"status": "success", "processes": [
            {"pid": process.pid, "name": process.name} for process in processes
        ]}
    except Exception as e:
        logger.error(f"Error getting running applications: {str(e)}")
        return {"status": "error", "message": str(e)}

def inject_script(package_name, script_path, spawn=True):
    """Inject a Frida script into an application."""
    try:
        # Handle case when script_path is just a filename without path
        if not os.path.exists(script_path):
            # Check if it exists in the scripts directory
            scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
            possible_paths = [
                os.path.join(scripts_dir, script_path),
                os.path.join(scripts_dir, f"{script_path}.js"),
                script_path,
                f"{script_path}.js"
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    script_path = path
                    break
            else:
                available_scripts = []
                if os.path.exists(scripts_dir):
                    available_scripts = [f for f in os.listdir(scripts_dir) if f.endswith('.js')]
                
                return {
                    "status": "error", 
                    "message": f"Script not found: {script_path}",
                    "available_scripts": available_scripts
                }
        
        # Read the script content for logging
        with open(script_path, "r") as file:
            js_code = file.read()
            
        logger.info(f"Using script: {script_path}")
        
        # First, check if device is rooted by trying to access su
        is_rooted = False
        try:
            result = subprocess.run(
                ["adb", "shell", "which", "su"], 
                capture_output=True, text=True, timeout=3
            )
            is_rooted = "su" in result.stdout and "/su" in result.stdout
            logger.info(f"Device root status: {'Rooted' if is_rooted else 'Not rooted'}")
        except:
            logger.warning("Could not determine if device is rooted")
        
        # Get PID if app is running
        pid = None
        if not spawn:
            # Check if the app is running using pidof
            result = subprocess.run(
                ["adb", "shell", "pidof", package_name], 
                capture_output=True, text=True
            )
            
            if result.stdout.strip():
                pid = result.stdout.strip()
                logger.info(f"Found {package_name} running with PID: {pid}")
            else:
                # Try ps command as backup
                result = subprocess.run(
                    ["adb", "shell", "ps | grep", package_name], 
                    shell=True, capture_output=True, text=True
                )
                
                if result.stdout.strip():
                    # Parse PID from ps output
                    for line in result.stdout.strip().split("\n"):
                        if package_name in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    pid = parts[1]
                                    logger.info(f"Found {package_name} running with PID: {pid} (via ps)")
                                    break
                                except:
                                    pass
            
            # If still not running, start it
            if not pid:
                logger.info(f"Starting {package_name} since it's not running...")
                subprocess.run(
                    ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"], 
                    capture_output=True
                )
                # Wait for it to start
                time.sleep(3)
                
                # Try to get PID again
                result = subprocess.run(
                    ["adb", "shell", "pidof", package_name], 
                    capture_output=True, text=True
                )
                
                if result.stdout.strip():
                    pid = result.stdout.strip()
                    logger.info(f"Started {package_name} with PID: {pid}")
        
        # Use frida CLI tool for injection
        if spawn:
            logger.info(f"Spawning {package_name} with frida...")
            cmd = ["frida", "-U", "-f", package_name, "-l", script_path]
        else:
            if pid:
                logger.info(f"Attaching to PID {pid} with frida...")
                cmd = ["frida", "-U", "-p", pid, "-l", script_path]
            else:
                logger.info(f"Attaching to {package_name} with frida...")
                cmd = ["frida", "-U", "-n", package_name, "-l", script_path]
        
        # Run the command with a timeout
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5  # 5 second timeout to avoid hanging
            )
            
            # Check output for specific errors
            if "Failed to spawn" in result.stdout and "need Gadget" in result.stdout:
                return {
                    "status": "error",
                    "message": "Device is not rooted. SSL bypass requires a rooted device, a repackaged app, or using Objection.",
                    "details": {
                        "error_type": "non_rooted_device",
                        "alternatives": [
                            "Use a rooted Android emulator",
                            "Use Objection: 'pip install objection' then 'objection --gadget " + package_name + " explore' then 'android sslpinning disable'",
                            "Repackage the app with Frida Gadget: 'objection patchapk -s <path-to-apk>'"
                        ]
                    }
                }
            elif "unable to find process" in result.stdout:
                return {
                    "status": "error",
                    "message": f"Could not find process '{package_name}'. Make sure the app is installed and running.",
                    "details": {
                        "error_type": "process_not_found",
                        "alternatives": [
                            f"Check if the app is installed: 'adb shell pm list packages | grep {package_name}'",
                            "Try starting the app manually and use non-spawn mode"
                        ]
                    }
                }
            elif "unable to connect to remote frida-server" in result.stdout:
                # Try restarting frida-server
                logger.info("Attempting to restart frida-server...")
                restart_result = subprocess.run(
                    ["python", "restart_frida.py"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Try again after restart
                logger.info("Retrying after frida-server restart...")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # If still failing, return error
                if "unable to connect to remote frida-server" in result.stdout:
                    return {
                        "status": "error",
                        "message": "Unable to connect to Frida server even after restart.",
                        "details": {
                            "error_type": "frida_server_connection",
                            "alternatives": [
                                "Ensure the Android device is properly connected",
                                "Try using objection instead: 'objection --gadget " + package_name + " explore'",
                                "Manually restart the Frida server: 'python restart_frida.py'"
                            ]
                        }
                    }
            
            # Check for success indicators in output
            if "SSL pinning bypassed" in result.stdout or "Script loaded successfully" in result.stdout:
                return {"status": "success", "message": f"Script injected into {package_name}"}
            else:
                # If there was an error in stderr, return it
                if result.stderr:
                    return {
                        "status": "error", 
                        "message": result.stderr,
                        "details": {
                            "error_type": "frida_error",
                            "output": result.stdout
                        }
                    }
                else:
                    # Return command output for debugging
                    return {"status": "success", "message": f"Script injected into {package_name}", "output": result.stdout}
                    
        except subprocess.TimeoutExpired:
            # If timeout occurred, the script might still be running in the background
            return {"status": "success", "message": f"Script injection started for {package_name} (running in background)"}
            
        
    except Exception as e:
        logger.error(f"Error injecting script: {str(e)}")
        return {
            "status": "error", 
            "message": str(e),
            "details": {
                "error_type": "general_error",
                "alternatives": [
                    "Try using a rooted Android emulator",
                    "Try using Objection instead of Frida",
                    "Check if the app is properly installed and running"
                ]
            }
        } 