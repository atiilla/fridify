"""Device-related functions for interacting with Android devices."""

from frida_utils.common import subprocess, logger

def check_device_connected():
    """Check if any Android device is connected via ADB."""
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        
        # Filter out lines that contain "device" but are not header lines
        devices = [line for line in lines if "device" in line and not line.startswith("List")]
        
        if devices:
            return {"status": "success", "devices": devices}
        else:
            return {"status": "error", "message": "No devices connected"}
    except Exception as e:
        logger.error(f"Error checking device connection: {str(e)}")
        return {"status": "error", "message": str(e)}

def get_device_architecture():
    """Get the architecture of the connected Android device."""
    try:
        result = subprocess.run(
            ["adb", "shell", "getprop", "ro.product.cpu.abi"], 
            capture_output=True, 
            text=True
        )
        arch = result.stdout.strip()
        
        # Map device architecture to Frida architecture
        arch_map = {
            'x86': 'x86',
            'x86_64': 'x86_64',
            'armeabi-v7a': 'arm',
            'arm64-v8a': 'arm64'
        }
        
        # Default to arm64 if unknown
        frida_arch = arch_map.get(arch, 'arm64')
        
        return {"status": "success", "architecture": frida_arch, "device_abi": arch}
    except Exception as e:
        logger.error(f"Error getting device architecture: {str(e)}")
        return {"status": "error", "message": str(e)}

def is_emulator():
    """Check if the connected device is an emulator."""
    try:
        # Check multiple properties that indicate an emulator
        props = [
            "ro.product.model",
            "ro.hardware",
            "ro.product.manufacturer",
            "ro.kernel.qemu"
        ]
        
        for prop in props:
            result = subprocess.run(
                ["adb", "shell", "getprop", prop], 
                capture_output=True, 
                text=True
            )
            value = result.stdout.strip().lower()
            
            # Check for common emulator indicators
            if any(indicator in value for indicator in ["emulator", "generic", "sdk", "genymotion", "goldfish", "ranchu"]):
                return {"status": "success", "is_emulator": True}
        
        # Check for qemu
        result = subprocess.run(
            ["adb", "shell", "getprop", "ro.kernel.qemu"], 
            capture_output=True, 
            text=True
        )
        if result.stdout.strip() == "1":
            return {"status": "success", "is_emulator": True}
            
        return {"status": "success", "is_emulator": False}
    except Exception as e:
        logger.error(f"Error checking if device is emulator: {str(e)}")
        return {"status": "error", "message": str(e)} 