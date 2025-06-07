"""Frida utilities package for Android device interaction and Frida server management."""

from frida_utils.device import check_device_connected, get_device_architecture, is_emulator
from frida_utils.frida_server import (
    get_latest_frida_version,
    download_frida_server,
    check_frida_running,
    start_frida_server
)
from frida_utils.applications import (
    list_packages,
    get_available_devices,
    get_running_applications,
    inject_script
)
from frida_utils.messaging import on_message

__all__ = [
    'check_device_connected',
    'get_device_architecture',
    'is_emulator',
    'get_latest_frida_version',
    'download_frida_server',
    'check_frida_running',
    'start_frida_server',
    'list_packages',
    'get_available_devices',
    'on_message',
    'get_running_applications',
    'inject_script',
] 