#!/bin/bash
# Setup script for Frida server on Android

# Configuration
FRIDA_VERSION="16.1.3"
FRIDA_ARCH="arm64"  # Change to arm for 32-bit devices
DOWNLOAD_DIR="./downloads"
TARGET_DIR="/data/local/tmp"

# Create download directory if it doesn't exist
mkdir -p "$DOWNLOAD_DIR"

# Check ADB connection
echo "Checking for connected Android devices..."
ADB_DEVICES=$(adb devices | grep -v "List" | grep -v "^$" | wc -l)

if [ "$ADB_DEVICES" -eq 0 ]; then
    echo "Error: No Android devices found. Please connect a device or start an emulator."
    exit 1
fi

echo "Found $ADB_DEVICES Android device(s)"

# Get device architecture if not specified
if [ -z "$FRIDA_ARCH" ]; then
    echo "Detecting device architecture..."
    DEVICE_ABI=$(adb shell getprop ro.product.cpu.abi)
    
    if [[ "$DEVICE_ABI" == *"arm64"* ]]; then
        FRIDA_ARCH="arm64"
    elif [[ "$DEVICE_ABI" == *"armeabi"* ]]; then
        FRIDA_ARCH="arm"
    elif [[ "$DEVICE_ABI" == *"x86_64"* ]]; then
        FRIDA_ARCH="x86_64"
    elif [[ "$DEVICE_ABI" == *"x86"* ]]; then
        FRIDA_ARCH="x86"
    else
        echo "Unknown architecture: $DEVICE_ABI"
        echo "Please specify the architecture manually by editing this script."
        exit 1
    fi
    
    echo "Detected architecture: $FRIDA_ARCH"
fi

# Download Frida server if needed
FRIDA_SERVER_FILE="frida-server-$FRIDA_VERSION-android-$FRIDA_ARCH"
FRIDA_SERVER_XZ="$FRIDA_SERVER_FILE.xz"
FRIDA_SERVER_PATH="$DOWNLOAD_DIR/$FRIDA_SERVER_FILE"
FRIDA_SERVER_XZ_PATH="$DOWNLOAD_DIR/$FRIDA_SERVER_XZ"

if [ ! -f "$FRIDA_SERVER_PATH" ]; then
    echo "Downloading Frida server $FRIDA_VERSION for $FRIDA_ARCH..."
    DOWNLOAD_URL="https://github.com/frida/frida/releases/download/$FRIDA_VERSION/$FRIDA_SERVER_XZ"
    
    if command -v curl &> /dev/null; then
        curl -L "$DOWNLOAD_URL" -o "$FRIDA_SERVER_XZ_PATH"
    elif command -v wget &> /dev/null; then
        wget "$DOWNLOAD_URL" -O "$FRIDA_SERVER_XZ_PATH"
    else
        echo "Error: Neither curl nor wget is installed."
        exit 1
    fi
    
    # Extract the XZ file
    echo "Extracting Frida server..."
    if command -v xz &> /dev/null; then
        xz -d -k "$FRIDA_SERVER_XZ_PATH"
    else
        echo "Error: XZ is not installed. Please install xz-utils package."
        exit 1
    fi
    
    # Make it executable
    chmod +x "$FRIDA_SERVER_PATH"
fi

# Push Frida server to device
echo "Pushing Frida server to $TARGET_DIR..."
adb push "$FRIDA_SERVER_PATH" "$TARGET_DIR/frida-server"

# Set permissions
echo "Setting permissions..."
adb shell "chmod 755 $TARGET_DIR/frida-server"

# Check if the device is rooted
IS_ROOTED=$(adb shell "which su" | grep -v "not found" | wc -l)

# Kill any existing Frida server
echo "Killing any existing Frida server..."
if [ "$IS_ROOTED" -ne 0 ]; then
    adb shell "su -c 'killall frida-server 2>/dev/null || true'"
else
    adb shell "killall frida-server 2>/dev/null || true"
fi

# Start Frida server
echo "Starting Frida server..."
if [ "$IS_ROOTED" -ne 0 ]; then
    # Root available
    adb shell "su -c '$TARGET_DIR/frida-server &'" &
    echo "Frida server started as root"
else
    # No root
    adb shell "$TARGET_DIR/frida-server &" &
    echo "Frida server started (no root)"
    echo "Warning: Some features might not work without root access"
fi
