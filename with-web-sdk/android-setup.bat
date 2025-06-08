@echo off
REM Setup script for Frida server on Android (Windows version)

REM Configuration
set FRIDA_VERSION=16.1.3
set FRIDA_ARCH=arm64
set DOWNLOAD_DIR=.\downloads
set TARGET_DIR=/data/local/tmp

REM Create download directory if it doesn't exist
if not exist "%DOWNLOAD_DIR%" mkdir "%DOWNLOAD_DIR%"

REM Check ADB connection
echo Checking for connected Android devices...
adb devices | find "device" > nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: No Android devices found. Please connect a device or start an emulator.
    exit /b 1
)

echo Found Android device^(s^)

REM Download Frida server if needed
set FRIDA_SERVER_FILE=frida-server-%FRIDA_VERSION%-android-%FRIDA_ARCH%
set FRIDA_SERVER_XZ=%FRIDA_SERVER_FILE%.xz
set FRIDA_SERVER_PATH=%DOWNLOAD_DIR%\%FRIDA_SERVER_FILE%
set FRIDA_SERVER_XZ_PATH=%DOWNLOAD_DIR%\%FRIDA_SERVER_XZ%

if not exist "%FRIDA_SERVER_PATH%" (
    echo Downloading Frida server %FRIDA_VERSION% for %FRIDA_ARCH%...
    set DOWNLOAD_URL=https://github.com/frida/frida/releases/download/%FRIDA_VERSION%/%FRIDA_SERVER_XZ%
    
    REM Use PowerShell to download the file
    powershell -Command "& {Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%FRIDA_SERVER_XZ_PATH%'}"
    
    echo Extracting Frida server...
    if exist "%ProgramFiles%\7-Zip\7z.exe" (
        "%ProgramFiles%\7-Zip\7z.exe" e "%FRIDA_SERVER_XZ_PATH%" -o"%DOWNLOAD_DIR%"
    ) else (
        echo Error: 7-Zip is not installed at the default location.
        echo Please install 7-Zip or extract the XZ file manually.
        exit /b 1
    )
)

REM Push Frida server to device
echo Pushing Frida server to %TARGET_DIR%...
adb push "%FRIDA_SERVER_PATH%" "%TARGET_DIR%/frida-server"

REM Set permissions
echo Setting permissions...
adb shell "chmod 755 %TARGET_DIR%/frida-server"

REM Check if the device is rooted
adb shell "which su" > nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set IS_ROOTED=1
) else (
    set IS_ROOTED=0
)

REM Kill any existing Frida server
echo Killing any existing Frida server...
if %IS_ROOTED% EQU 1 (
    adb shell "su -c 'killall frida-server 2>/dev/null || true'"
) else (
    adb shell "killall frida-server 2>/dev/null || true"
)

REM Start Frida server
echo Starting Frida server...
if %IS_ROOTED% EQU 1 (
    adb shell "su -c '%TARGET_DIR%/frida-server &'"
    echo Frida server started as root
) else (
    adb shell "%TARGET_DIR%/frida-server &"
    echo Frida server started (no root)
    echo Warning: Some features might not work without root access
)

pause