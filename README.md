# Fridify - Frida Automation Tool

A comprehensive GUI and API for automating Frida-related tasks for Android application analysis and security testing.

## Features

- Device management and connection status
- Automatic Frida server download and installation
- Application listing and filtering
- Frida script injection
- SSL pinning bypass capabilities
- Simple script management

## Requirements

- Python 3.8+
- Android device or emulator with ADB connection
- Rooted device (for direct Frida injection)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/atiilla/fridify.git
cd fridify
```

2. Install required Python packages:
```bash
python -m venv venv
windows: source venv/Scripts/activate || venv\Scripts\activate
linux: source venv/bin/activate
pip install -r requirements.txt
```

3. Connect your Android device or emulator:
```bash
adb devices
```

## Usage

### Starting the API Server

```bash
python app.py
```

This will start the FastAPI server on http://localhost:8000

### Starting the Streamlit Web Interface

```bash
streamlit run web.py
```

This will start the Streamlit web interface on http://localhost:8501

## Web Interface

The Streamlit web interface provides a user-friendly way to:

1. **Device Status**: Check device connection, architecture, and running processes
2. **Frida Server**: Start, download, and manage Frida server on your device
3. **Applications**: List and filter installed applications
4. **Script Injection**: Inject Frida scripts into applications
5. **Scripts**: Manage and upload custom Frida scripts

## SSL Pinning Bypass

To bypass SSL pinning:

1. Make sure Frida server is running on your device (use the "Frida Server" page)
2. Go to "Script Injection" page
3. Select the target application
4. Choose the "ssl_pinning_bypass.js" script
5. Click "Inject Script"

## For Non-Rooted Devices

If your device is not rooted, you have these alternatives:

1. **Objection**:
   ```bash
   pip install objection
   objection --gadget <package_name> explore
   android sslpinning disable
   ```

2. **Repackage the app**:
   ```bash
   objection patchapk -s <path-to-apk>
   ```

3. Use a rooted emulator like Genymotion or modified AVD

## Creating Custom Scripts

Custom scripts should be placed in the `scripts` directory. The format should be:

```javascript
// Description: Your script description here

Java.perform(function() {
    console.log("Script loaded");
    
    // Your code here
});
```

## API Documentation

API documentation is available at:
- OpenAPI documentation: http://localhost:8000/docs
- Custom documentation: http://localhost:8000/docs/custom

## License

MIT 

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing or analyzing any application. Use of this tool against applications or systems without explicit permission from their owners may be illegal and is not recommended. 