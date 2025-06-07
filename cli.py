#!/usr/bin/env python3

import argparse
import sys
import os
import json

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

def print_json(data):
    """Print data as formatted JSON."""
    print(json.dumps(data, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Frida Automation CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Device check command
    device_parser = subparsers.add_parser("device", help="Check device connection")
    
    # Frida status command
    frida_status_parser = subparsers.add_parser("frida-status", help="Check Frida server status")
    
    # Start Frida server command
    frida_start_parser = subparsers.add_parser("frida-start", help="Start Frida server")
    frida_start_parser.add_argument(
        "--path", 
        "-p", 
        help="Path to frida-server binary (use 'auto' to download automatically)",
        default="auto"
    )
    
    # Download Frida server command
    frida_download_parser = subparsers.add_parser("frida-download", help="Download Frida server")
    frida_download_parser.add_argument(
        "--version", 
        "-v", 
        help="Frida server version (default: latest)"
    )
    frida_download_parser.add_argument(
        "--arch", 
        "-a", 
        help="Target architecture (default: auto-detect)"
    )
    
    # Check device architecture
    arch_parser = subparsers.add_parser("arch", help="Get device architecture")
    
    # Check if device is emulator
    emulator_parser = subparsers.add_parser("is-emulator", help="Check if device is an emulator")
    
    # List packages command
    packages_parser = subparsers.add_parser("packages", help="List installed packages")
    packages_parser.add_argument(
        "--filter", 
        "-f", 
        help="Filter packages by keyword"
    )
    
    # List processes command
    processes_parser = subparsers.add_parser("processes", help="List running processes")
    
    # Inject script command
    inject_parser = subparsers.add_parser("inject", help="Inject a Frida script")
    inject_parser.add_argument(
        "--package", 
        "-p", 
        required=True, 
        help="Target package name"
    )
    inject_parser.add_argument(
        "--script", 
        "-s", 
        required=True, 
        help="Path to script file"
    )
    inject_parser.add_argument(
        "--spawn", 
        action="store_true", 
        help="Spawn a new instance of the app (default: True)"
    )
    inject_parser.add_argument(
        "--no-spawn", 
        action="store_false", 
        dest="spawn",
        help="Attach to an already running instance"
    )
    inject_parser.set_defaults(spawn=True)
    
    # Auto setup command for emulators
    auto_parser = subparsers.add_parser("auto", help="Automatically setup for emulator")
    
    # List available scripts
    scripts_parser = subparsers.add_parser("scripts", help="List available scripts")
    
    # List Frida devices
    devices_parser = subparsers.add_parser("frida-devices", help="List available Frida devices")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute commands
    if args.command == "device":
        print_json(check_device_connected())
    
    elif args.command == "frida-status":
        print_json(check_frida_running())
    
    elif args.command == "frida-start":
        print_json(start_frida_server(args.path))
    
    elif args.command == "frida-download":
        print_json(download_frida_server(args.version, args.arch))
    
    elif args.command == "arch":
        print_json(get_device_architecture())
    
    elif args.command == "is-emulator":
        print_json(is_emulator())
    
    elif args.command == "packages":
        print_json(list_packages(args.filter))
    
    elif args.command == "processes":
        print_json(get_running_applications())
    
    elif args.command == "inject":
        print_json(inject_script(args.package, args.script, args.spawn))
    
    elif args.command == "auto":
        # Check if device is connected
        device_check = check_device_connected()
        if device_check["status"] == "error":
            print_json(device_check)
            return 1
        
        print("Device connected...")
        
        # Check if device is an emulator
        emulator_check = is_emulator()
        if emulator_check["status"] == "error":
            print_json(emulator_check)
            return 1
        
        if emulator_check.get("is_emulator", False):
            print("Detected emulator...")
        else:
            print("Device is not an emulator, but continuing anyway...")
        
        # Get device architecture
        arch_check = get_device_architecture()
        if arch_check["status"] == "error":
            print_json(arch_check)
            return 1
        
        print(f"Device architecture: {arch_check.get('architecture', 'unknown')}")
        
        # Download Frida server
        print("Downloading Frida server...")
        download_result = download_frida_server()
        if download_result["status"] == "error":
            print_json(download_result)
            return 1
        
        print(f"Downloaded Frida server to {download_result.get('path', 'unknown')}")
        
        # Start Frida server
        print("Starting Frida server...")
        start_result = start_frida_server(download_result.get('path'))
        print_json(start_result)
        
        if start_result["status"] == "success":
            print("\nFrida server is now running on the device.")
            print("You can now inject scripts with: python cli.py inject --package <package_name> --script <script_path>")
        
        return 0 if start_result["status"] == "success" else 1
    
    elif args.command == "scripts":
        scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
        if os.path.exists(scripts_dir):
            scripts = [f for f in os.listdir(scripts_dir) if f.endswith('.js')]
            print_json({
                "status": "success",
                "scripts": scripts,
                "directory": scripts_dir
            })
        else:
            print_json({
                "status": "error",
                "message": "Scripts directory not found"
            })
    
    elif args.command == "frida-devices":
        print_json(get_available_devices())
    
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 