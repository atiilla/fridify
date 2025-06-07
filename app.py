import os
import uvicorn
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import shutil
import tempfile
from enum import Enum
import time
import subprocess

# Import our utility functions
from frida_utils import (
    check_device_connected,
    check_frida_running,
    start_frida_server,
    list_packages,
    inject_script,
    get_available_devices,
    get_running_applications,
    get_device_architecture,
    is_emulator,
    download_frida_server
)

app = FastAPI(
    title="Frida Automation Tool",
    description="RESTful API for automating Frida-related tasks",
    version="1.0.0"
)

# Override the OpenAPI description for specific endpoints
app.openapi_tags = [
    {
        "name": "Frida Server",
        "description": "Operations related to managing the Frida server on the device"
    },
    {
        "name": "Injection",
        "description": "Operations related to script injection"
    },
    {
        "name": "Device",
        "description": "Operations related to device management"
    }
]

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create scripts directory if it doesn't exist
scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
os.makedirs(scripts_dir, exist_ok=True)

# Define models for request/response data
class FridaServerStartRequest(BaseModel):
    frida_server_path: Optional[str] = None

class FridaServerDownloadRequest(BaseModel):
    version: Optional[str] = None
    arch: Optional[str] = None

# Create a dynamic enum for available scripts
def get_script_enum():
    scripts = []
    if os.path.exists(scripts_dir):
        scripts = [f.replace('.js', '') for f in os.listdir(scripts_dir) if f.endswith('.js')]
    
    if not scripts:
        scripts = ["no_scripts_available"]
    
    return Enum('ScriptEnum', {script: script for script in scripts})

class ScriptInjectionRequest(BaseModel):
    package_name: str
    script_path: str
    spawn: bool = True

class PackageFilterRequest(BaseModel):
    filter_keyword: Optional[str] = None

# API Endpoints
@app.get("/", tags=["Status"])
async def root():
    return {"message": "Frida Automation Tool API", "status": "running"}

@app.get("/device", tags=["Device"])
async def check_device():
    """Check if any Android device is connected via ADB."""
    return check_device_connected()

@app.get("/device/arch")
async def device_architecture():
    """Get the architecture of the connected Android device."""
    return get_device_architecture()

@app.get("/device/is-emulator")
async def device_is_emulator():
    """Check if the connected device is an emulator."""
    return is_emulator()

@app.get("/frida/status", tags=["Frida Server"])
async def check_frida():
    """Check if Frida server is running on the device."""
    return check_frida_running()

@app.post("/frida/download", tags=["Frida Server"])
async def download_frida(request: FridaServerDownloadRequest = None):
    """Download a specific version of Frida server."""
    if request is None:
        request = FridaServerDownloadRequest()
    return download_frida_server(request.version, request.arch)

@app.get("/frida/start", tags=["Frida Server"], 
          summary="Start Frida server",
          description="Automatically checks if frida-server exists on the device, downloads it if needed, and starts it. No input required.",
          response_description="Frida server status information")
async def start_frida():
    """Start Frida server on the device. No input required - automatically finds or downloads the server."""
    # Create a default request object with no path specified
    
    return start_frida_server()



@app.post("/frida/auto-setup")
async def auto_setup():
    """Automatically download and start Frida server for the connected device."""
    # Check device connection
    device_check = check_device_connected()
    if device_check["status"] == "error":
        return device_check
    
    # Download Frida server
    download_result = download_frida_server()
    if download_result["status"] == "error":
        return download_result
    
    # Start Frida server
    return start_frida_server(download_result["path"])

@app.get("/packages", tags=["Device"])
async def list_all_packages():
    """List all installed packages on the device."""
    return list_packages()

@app.post("/packages/filter", tags=["Device"])
async def filter_packages(request: PackageFilterRequest):
    """Filter installed packages by keyword."""
    return list_packages(request.filter_keyword)

@app.get("/scripts", tags=["Scripts"])
async def list_scripts():
    """List available Frida scripts."""
    try:
        scripts = []
        scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
        
        # Create scripts directory if it doesn't exist
        if not os.path.exists(scripts_dir):
            os.makedirs(scripts_dir)
            return {"status": "success", "scripts": [], "directory": scripts_dir}
        
        # Get all JS files
        for filename in os.listdir(scripts_dir):
            if filename.endswith('.js'):
                script_path = os.path.join(scripts_dir, filename)
                script_name = filename.replace('.js', '')
                
                # Default description
                description = "Frida script"
                
                # Try to read description from metadata file if it exists
                meta_path = os.path.join(scripts_dir, f"{filename}.meta")
                if os.path.exists(meta_path):
                    try:
                        import json
                        with open(meta_path, 'r') as f:
                            metadata = json.load(f)
                            if "description" in metadata:
                                description = metadata["description"]
                    except:
                        pass
                else:
                    # Try to extract description from script content
                    try:
                        with open(script_path, 'r') as f:
                            content = f.read(500)  # Read first 500 chars
                            comment_lines = [line.strip() for line in content.split('\n') if '//' in line or '/*' in line]
                            if comment_lines:
                                # Remove comment markers and extract description
                                desc_line = comment_lines[0].replace('//', '').replace('/*', '').replace('*/', '').strip()
                                if desc_line:
                                    description = desc_line
                    except:
                        pass
                
                scripts.append({
                    "name": script_name,
                    "path": script_path,
                    "description": description
                })
        
        return {"status": "success", "scripts": scripts, "directory": scripts_dir}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/inject", tags=["Injection"])
async def inject_frida_script(request: ScriptInjectionRequest):
    """Inject a Frida script into an application."""
    result = inject_script(request.package_name, request.script_path, request.spawn)
    
    # If script not found, include available scripts in the response
    if result["status"] == "error" and "available_scripts" in result:
        scripts = result["available_scripts"]
        script_options = []
        for script in scripts:
            script_options.append({
                "name": script.replace(".js", ""),
                "path": os.path.join(scripts_dir, script)
            })
        result["script_options"] = script_options
    
    # Add helpful information for non-rooted device errors
    if result["status"] == "error" and "details" in result and result["details"].get("error_type") == "non_rooted_device":
        # Add information about alternative solutions
        result["non_rooted_solutions"] = {
            "objection": {
                "description": "Objection is a runtime mobile exploration toolkit that can bypass SSL pinning without root",
                "install": "pip install objection",
                "usage": f"objection --gadget {request.package_name} explore",
                "command": "android sslpinning disable"
            },
            "repackage": {
                "description": "Repackage the app with Frida Gadget embedded",
                "command": "objection patchapk -s <path-to-apk-file>"
            },
            "rooted_emulator": {
                "description": "Use a rooted Android emulator like Genymotion or modified AVD"
            }
        }
    
    # Add information about Frida server connection issues
    if result["status"] == "error" and "details" in result and result["details"].get("error_type") == "frida_server_connection":
        result["server_solutions"] = {
            "restart": {
                "description": "Restart the Frida server",
                "command": "python restart_frida.py"
            },
            "check_connection": {
                "description": "Ensure the Android device is properly connected",
                "command": "adb devices"
            },
            "check_frida": {
                "description": "Check if Frida server is running",
                "command": "adb shell ps | grep frida-server"
            }
        }
    
    return result

@app.post("/upload/script", tags=["Scripts"])
async def upload_script(
    file: UploadFile = File(...),
    name: str = Form(None),
    description: str = Form(None)
):
    """Upload a new Frida script."""
    try:
        # Use provided name or original filename
        filename = name if name else file.filename
        if not filename.endswith('.js'):
            filename += '.js'
        
        # Save the script to the scripts directory
        scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
        os.makedirs(scripts_dir, exist_ok=True)
        
        file_path = os.path.join(scripts_dir, filename)
        
        # Write file content
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # If description is provided, save it in a metadata file
        if description:
            metadata_path = os.path.join(scripts_dir, f"{filename}.meta")
            with open(metadata_path, "w") as f:
                import json
                json.dump({"name": filename, "description": description}, f)
        
        return {
            "status": "success",
            "message": f"Script uploaded successfully",
            "name": filename,
            "path": file_path,
            "description": description
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading script: {str(e)}")

# HTML documentation with script selection
@app.get("/docs/custom", response_class=HTMLResponse)
async def custom_docs():
    """Custom documentation page with script selection dropdown."""
    scripts_result = await list_scripts()
    scripts = scripts_result.get("scripts", [])
    
    script_options = "".join([f'<option value="{script["name"]}">{script["name"]} - {script["description"]}</option>' for script in scripts])
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Frida Automation Tool API</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #333; }}
            .endpoint {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
            .form-group {{ margin-bottom: 10px; }}
            label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
            input, select {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
            button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }}
            button:hover {{ background-color: #45a049; }}
            pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }}
            .response {{ margin-top: 15px; }}
            .info-box {{ background-color: #e7f3fe; border-left: 6px solid #2196F3; padding: 10px; margin-bottom: 15px; }}
            .warning-box {{ background-color: #fff3cd; border-left: 6px solid #ffc107; padding: 10px; margin-bottom: 15px; }}
            .note {{ font-size: 0.9em; color: #666; margin-top: 5px; }}
            .tabbed {{ margin-left: 20px; }}
        </style>
    </head>
    <body>
        <h1>Frida Automation Tool API</h1>
        
        <div class="info-box">
            <h3>Requirements for SSL Pinning Bypass</h3>
            <p>To successfully bypass SSL pinning, one of the following conditions must be met:</p>
            <ul>
                <li><strong>Rooted Device:</strong> Your Android device/emulator must be rooted for direct Frida injection</li>
                <li><strong>Repackaged App:</strong> The app can be repackaged with Frida Gadget embedded</li>
                <li><strong>Objection:</strong> Alternative tool that can sometimes work on non-rooted devices</li>
            </ul>
        </div>
        
        <div class="endpoint">
            <h2>Inject Script</h2>
            <div class="form-group">
                <label for="package_name">Package Name:</label>
                <input type="text" id="package_name" placeholder="com.example.app">
            </div>
            <div class="form-group">
                <label for="script_path">Script:</label>
                <select id="script_path">
                    {script_options}
                </select>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" id="spawn" checked> Spawn new instance
                </label>
                <p class="note">If unchecked, will try to attach to an already running instance</p>
            </div>
            <button onclick="injectScript()">Inject Script</button>
            <div class="response">
                <pre id="inject_response"></pre>
            </div>
            
            <div class="warning-box">
                <h3>Non-Rooted Device Solutions</h3>
                <p>If you encounter "need Gadget to attach on jailed Android" error, try:</p>
                <ol>
                    <li><strong>Objection:</strong>
                        <div class="tabbed">
                            <code>pip install objection</code><br>
                            <code>objection --gadget &lt;package_name&gt; explore</code><br>
                            <code>android sslpinning disable</code>
                        </div>
                    </li>
                    <li><strong>Repackage the app:</strong>
                        <div class="tabbed">
                            <code>objection patchapk -s &lt;path-to-apk&gt;</code>
                        </div>
                    </li>
                    <li><strong>Use a rooted emulator</strong> like Genymotion or modified AVD</li>
                </ol>
            </div>
        </div>
        
        <script>
            async function injectScript() {{
                const packageName = document.getElementById('package_name').value;
                const scriptPath = document.getElementById('script_path').value;
                const spawn = document.getElementById('spawn').checked;
                
                if (!packageName || !scriptPath) {{
                    alert('Please fill in all required fields');
                    return;
                }}
                
                try {{
                    const response = await fetch('/inject', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            package_name: packageName,
                            script_path: scriptPath,
                            spawn: spawn
                        }})
                    }});
                    
                    const data = await response.json();
                    document.getElementById('inject_response').textContent = JSON.stringify(data, null, 2);
                    
                    // If non-rooted device error, show alert with suggestions
                    if (data.status === "error" && data.details && data.details.error_type === "non_rooted_device") {{
                        alert("Your device is not rooted. See the 'Non-Rooted Device Solutions' section below for alternatives.");
                    }}
                }} catch (error) {{
                    document.getElementById('inject_response').textContent = 'Error: ' + error.message;
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    return html_content

@app.get("/frida/devices", tags=["Frida Server"])
async def list_frida_devices():
    """Get a list of available Frida devices."""
    return get_available_devices()

@app.get("/processes", tags=["Device"])
async def get_processes():
    """Get a list of running applications on the device."""
    return get_running_applications()

@app.get("/frida/diagnostics", tags=["Frida Server"])
async def frida_diagnostics():
    """Get comprehensive diagnostics about Frida server on the connected device."""
    diagnostics = {
        "status": "success",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device_connection": {},
        "frida_server": {},
        "environment": {}
    }
    
    # Check device connection
    try:
        device_result = check_device_connected()
        diagnostics["device_connection"] = {
            "connected": device_result["status"] == "success",
            "details": device_result
        }
        
        if device_result["status"] != "success":
            diagnostics["status"] = "error"
            diagnostics["message"] = "No device connected"
            return diagnostics
    except Exception as e:
        diagnostics["device_connection"] = {
            "connected": False,
            "error": str(e)
        }
        diagnostics["status"] = "error"
        diagnostics["message"] = "Error checking device connection"
        return diagnostics
    
    # Get device architecture
    try:
        arch_result = get_device_architecture()
        diagnostics["environment"]["architecture"] = arch_result
    except:
        diagnostics["environment"]["architecture"] = {"status": "error", "message": "Could not determine device architecture"}
    
    # Check if device is rooted
    try:
        result = subprocess.run(
            ["adb", "shell", "which", "su"], 
            capture_output=True, text=True, timeout=3
        )
        is_rooted = "su" in result.stdout and "/su" in result.stdout
        diagnostics["environment"]["rooted"] = is_rooted
    except:
        diagnostics["environment"]["rooted"] = "unknown"
    
    # Check if frida-server exists on device
    try:
        result = subprocess.run(
            ["adb", "shell", "ls", "-l", "/data/local/tmp/frida-server"], 
            capture_output=True, text=True
        )
        
        if "No such file" not in result.stderr and result.returncode == 0:
            diagnostics["frida_server"]["installed"] = True
            diagnostics["frida_server"]["path"] = "/data/local/tmp/frida-server"
            diagnostics["frida_server"]["file_details"] = result.stdout.strip()
            
            # Get frida-server version if installed
            try:
                version_result = subprocess.run(
                    ["adb", "shell", "/data/local/tmp/frida-server --version"], 
                    shell=True, capture_output=True, text=True, timeout=3
                )
                if version_result.stdout:
                    diagnostics["frida_server"]["version"] = version_result.stdout.strip()
            except:
                diagnostics["frida_server"]["version"] = "unknown"
        else:
            diagnostics["frida_server"]["installed"] = False
    except Exception as e:
        diagnostics["frida_server"]["installed"] = "unknown"
        diagnostics["frida_server"]["error"] = str(e)
    
    # Check if frida-server is running
    running_result = check_frida_running()
    diagnostics["frida_server"]["running"] = running_result.get("running", False)
    
    # Check available Frida devices
    try:
        devices_result = get_available_devices()
        if devices_result["status"] == "success":
            diagnostics["frida_server"]["devices"] = devices_result["devices"]
            
            # Check if Android device is in the list
            android_devices = [d for d in devices_result["devices"] if "Android" in d.get("name", "")]
            if android_devices:
                diagnostics["frida_server"]["android_device_available"] = True
            else:
                diagnostics["frida_server"]["android_device_available"] = False
                # If server is installed and running but no Android device, there might be connectivity issues
                if diagnostics["frida_server"].get("installed", False) and diagnostics["frida_server"].get("running", False):
                    diagnostics["frida_server"]["connectivity_issue"] = True
    except Exception as e:
        diagnostics["frida_server"]["devices_error"] = str(e)
    
    # Provide a summary
    if not diagnostics["frida_server"].get("installed", False):
        diagnostics["summary"] = "frida-server is not installed on the device. Use /frida/start to install it."
    elif not diagnostics["frida_server"].get("running", False):
        diagnostics["summary"] = "frida-server is installed but not running. Use /frida/start to start it."
    elif not diagnostics["frida_server"].get("android_device_available", False):
        diagnostics["summary"] = "frida-server is running but no Android device is detected by Frida. There might be connectivity issues."
    else:
        diagnostics["summary"] = "frida-server is installed, running, and connected to your Android device. Ready for injection."
    
    return diagnostics

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True) 