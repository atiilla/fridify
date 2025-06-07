"""Main module for demonstrating Frida utilities."""

import argparse
import sys
import json
from frida_utils import (
    check_device_connected,
    get_device_architecture, 
    is_emulator,
    get_latest_frida_version,
    download_frida_server,
    check_frida_running,
    start_frida_server,
    list_packages,
    get_available_devices,
    get_running_applications,
    inject_script
)
from frida_utils.common import logger

def pretty_print_result(result):
    """Print a result dictionary in a readable format."""
    print(json.dumps(result, indent=2))

def main():
    """Main function to demonstrate frida_utils functionality."""
    parser = argparse.ArgumentParser(description='Frida Utilities')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Device commands
    subparsers.add_parser('check-device', help='Check if an Android device is connected')
    subparsers.add_parser('get-arch', help='Get device architecture')
    subparsers.add_parser('is-emulator', help='Check if device is an emulator')
    
    # Frida server commands
    subparsers.add_parser('frida-version', help='Get latest Frida version')
    
    download_parser = subparsers.add_parser('download-frida', help='Download Frida server')
    download_parser.add_argument('--version', help='Frida version (default: latest)')
    download_parser.add_argument('--arch', help='Device architecture (default: auto-detect)')
    
    subparsers.add_parser('check-frida-running', help='Check if Frida server is running')
    
    start_parser = subparsers.add_parser('start-frida', help='Start Frida server')
    start_parser.add_argument('--path', help='Path to Frida server (default: auto-download)')
    
    # Application commands
    list_parser = subparsers.add_parser('list-packages', help='List installed packages')
    list_parser.add_argument('--filter', help='Filter packages by keyword')
    
    subparsers.add_parser('get-devices', help='Get available Frida devices')
    subparsers.add_parser('get-apps', help='Get running applications')
    
    inject_parser = subparsers.add_parser('inject', help='Inject a Frida script')
    inject_parser.add_argument('package', help='Package name to inject into')
    inject_parser.add_argument('script', help='Path to Frida script')
    inject_parser.add_argument('--no-spawn', action='store_true', help='Attach to running app instead of spawning')
    
    args = parser.parse_args()
    
    # Execute the command
    if args.command == 'check-device':
        pretty_print_result(check_device_connected())
    
    elif args.command == 'get-arch':
        pretty_print_result(get_device_architecture())
    
    elif args.command == 'is-emulator':
        pretty_print_result(is_emulator())
    
    elif args.command == 'frida-version':
        pretty_print_result(get_latest_frida_version())
    
    elif args.command == 'download-frida':
        pretty_print_result(download_frida_server(
            version=args.version, 
            arch=args.arch
        ))
    
    elif args.command == 'check-frida-running':
        pretty_print_result(check_frida_running())
    
    elif args.command == 'start-frida':
        pretty_print_result(start_frida_server(frida_server_path=args.path))
    
    elif args.command == 'list-packages':
        pretty_print_result(list_packages(filter_keyword=args.filter))
    
    elif args.command == 'get-devices':
        pretty_print_result(get_available_devices())
    
    elif args.command == 'get-apps':
        pretty_print_result(get_running_applications())
    
    elif args.command == 'inject':
        pretty_print_result(inject_script(
            args.package, 
            args.script, 
            spawn=not args.no_spawn
        ))
    
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 