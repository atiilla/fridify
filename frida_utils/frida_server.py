"""Functions for managing Frida server on Android devices."""

from frida_utils.common import (
    subprocess, logger, requests, os, time, frida, re, lzma
)
from frida_utils.device import check_device_connected, get_device_architecture

def get_latest_frida_version():
    """Get the latest Frida server version from GitHub tags."""
    try:
        # First try using the GitHub API
        try:
            response = requests.get("https://api.github.com/repos/frida/frida/releases/latest")
            response.raise_for_status()
            release_info = response.json()
            version = release_info['tag_name']
            return {"status": "success", "version": version}
        except Exception as api_error:
            logger.warning(f"Failed to get version via GitHub API: {str(api_error)}")
            
            # Fallback: Scrape the tags page
            response = requests.get("https://github.com/frida/frida/tags")
            response.raise_for_status()
            
            # Simple parsing to find the first tag (latest version)
            # Look for tag patterns like: <a href="/frida/frida/releases/tag/17.1.3">17.1.3</a>
            tag_pattern = r'href="/frida/frida/releases/tag/([0-9]+\.[0-9]+\.[0-9]+)"'
            matches = re.findall(tag_pattern, response.text)
            
            if matches:
                # First match is the latest version
                version = matches[0]
                return {"status": "success", "version": version}
            else:
                raise Exception("Could not find version tag on GitHub page")
    except Exception as e:
        logger.error(f"Error getting latest Frida version: {str(e)}")
        return {"status": "error", "message": str(e)}

def download_frida_server(version=None, arch=None):
    """Download the appropriate Frida server for the device."""
    try:
        # Get the latest version if not specified or if "latest" is specified
        if version is None or version.lower() == "latest":
            version_info = get_latest_frida_version()
            if version_info["status"] == "error":
                return version_info
            version = version_info["version"]
            logger.info(f"Using latest Frida version: {version}")
        
        # Get device architecture if not specified
        if arch is None:
            arch_info = get_device_architecture()
            if arch_info["status"] == "error":
                return arch_info
            arch = arch_info["architecture"]
            logger.info(f"Using device architecture: {arch}")
        
        # Format the version string (remove 'v' prefix if present)
        if version.startswith('v'):
            version = version[1:]
        
        # Construct download URL
        download_url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"
        
        logger.info(f"Downloading Frida server from {download_url}")
        
        # Create a temporary directory for the download
        temp_dir = os.path.join(os.getcwd(), "temp")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Download the file
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        
        # Save the compressed file
        xz_path = os.path.join(temp_dir, f"frida-server-{version}-{arch}.xz")
        with open(xz_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        logger.info(f"Downloaded compressed file to {xz_path}")
        
        # Decompress the .xz file
        output_path = os.path.join(os.getcwd(), "frida-server")
        
        with lzma.open(xz_path, "rb") as xz_file:
            with open(output_path, "wb") as extracted_file:
                # Read and write in chunks to handle large files
                while True:
                    chunk = xz_file.read(8192)
                    if not chunk:
                        break
                    extracted_file.write(chunk)
        
        logger.info(f"Extracted Frida server to {output_path}")
        
        # Make executable
        os.chmod(output_path, 0o755)
        
        # Clean up temporary files
        try:
            os.remove(xz_path)
            os.rmdir(temp_dir)
        except:
            pass  # Ignore cleanup errors
        
        return {
            "status": "success", 
            "message": f"Downloaded Frida server {version} for {arch}", 
            "path": output_path
        }
    except Exception as e:
        logger.error(f"Error downloading Frida server: {str(e)}")
        return {"status": "error", "message": str(e)}

def check_frida_running():
    """Check if Frida server is running on the device."""
    try:
        result = subprocess.run(
            ["adb", "shell", "ps | grep frida-server"], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        if "frida-server" in result.stdout:
            return {"status": "success", "running": True, "message": "Frida server is running"}
        else:
            return {"status": "success", "running": False, "message": "Frida server is not running"}
    except Exception as e:
        logger.error(f"Error checking Frida status: {str(e)}")
        return {"status": "error", "message": str(e)}

def start_frida_server():
    """Start the Frida server on the device."""
    try:
        # Tek string komut, shell=True ile
        cmd = 'adb shell su 0 "/data/local/tmp/frida-server &"'
        server_proc = subprocess.Popen(cmd, shell=True)
        time.sleep(5)  # Frida server'ın başlaması için bekle
        return {"status": "success", "message": "Frida server started successfully"}
    except Exception as e:
        logger.error(f"Error starting Frida server: {str(e)}")
        return {"status": "error", "message": str(e)}
