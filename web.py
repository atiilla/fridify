import streamlit as st
import requests
import json
import os
import time

# Set page config
st.set_page_config(
    page_title="Frida Automation Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API URL
API_URL = "http://localhost:8000"

# Helper functions
def get_api_response(endpoint, method="GET", data=None):
    try:
        if method == "GET":
            response = requests.get(f"{API_URL}{endpoint}", timeout=10)
        elif method == "POST":
            response = requests.post(f"{API_URL}{endpoint}", json=data, timeout=10)
        
        return response.json()
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to API server. Make sure the API is running.")
        return {"status": "error", "message": "Cannot connect to API server"}
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return {"status": "error", "message": str(e)}

# Sidebar navigation
st.sidebar.title("Frida Automation Tool")
st.sidebar.image("https://frida.re/img/logotype.svg", width=200)
page = st.sidebar.radio("Navigation", ["Device Status", "Frida Server", "Applications", "Script Injection", "Scripts"])

# Style
st.markdown("""
<style>
    .success-box {
        padding: 10px;
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        margin-bottom: 10px;
    }
    .error-box {
        padding: 10px;
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        margin-bottom: 10px;
    }
    .info-box {
        padding: 10px;
        background-color: #e7f3fe;
        border-left: 5px solid #2196F3;
        margin-bottom: 10px;
    }
    .warning-box {
        padding: 10px;
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Device Status Page
if page == "Device Status":
    st.title("Device Status")
    
    # Create columns for better layout
    col1, col2 = st.columns(2)
    
    with col1:
        # Device connection status
        with st.container():
            st.subheader("Device Connection")
            if st.button("Check Device Connection", key="check_device"):
                device_result = get_api_response("/device")
                if device_result.get("status") == "success":
                    st.markdown('<div class="success-box">✅ Device connected</div>', unsafe_allow_html=True)
                    st.json(device_result)
                else:
                    st.markdown('<div class="error-box">❌ No device connected</div>', unsafe_allow_html=True)
                    st.json(device_result)
        
        # Device architecture
        with st.container():
            st.subheader("Device Architecture")
            if st.button("Get Device Architecture", key="get_arch"):
                arch_result = get_api_response("/device/arch")
                st.json(arch_result)
                
        # Check if device is emulator
        with st.container():
            st.subheader("Emulator Check")
            if st.button("Check if Emulator", key="check_emulator"):
                emulator_result = get_api_response("/device/is-emulator")
                if emulator_result.get("is_emulator") == True:
                    st.markdown('<div class="info-box">📱 Device is an emulator</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="info-box">📱 Device is a physical device</div>', unsafe_allow_html=True)
                st.json(emulator_result)
    
    with col2:
        # List available Frida devices
        with st.container():
            st.subheader("Frida Devices")
            if st.button("List Frida Devices", key="list_frida_devices"):
                devices_result = get_api_response("/frida/devices")
                if devices_result.get("status") == "success" and devices_result.get("devices"):
                    st.write(f"Found {len(devices_result['devices'])} devices")
                    for device in devices_result["devices"]:
                        st.markdown(f"**{device.get('name')}** ({device.get('id')})")
                else:
                    st.markdown('<div class="warning-box">⚠️ No Frida devices found</div>', unsafe_allow_html=True)
                st.json(devices_result)
        
        # List running processes
        with st.container():
            st.subheader("Running Processes")
            if st.button("List Running Processes", key="list_processes"):
                processes_result = get_api_response("/processes")
                if processes_result.get("status") == "success" and processes_result.get("processes"):
                    st.write(f"Found {len(processes_result['processes'])} processes")
                    st.dataframe(processes_result["processes"])
                else:
                    st.markdown('<div class="warning-box">⚠️ Could not retrieve processes</div>', unsafe_allow_html=True)
                    st.json(processes_result)
    
    # Full diagnostics
    st.subheader("Frida Diagnostics")
    if st.button("Run Full Diagnostics", key="diagnostics"):
        with st.spinner("Running diagnostics..."):
            diagnostics = get_api_response("/frida/diagnostics")
            
            if diagnostics.get("status") == "success":
                # Display summary
                if "summary" in diagnostics:
                    if "not installed" in diagnostics["summary"]:
                        st.markdown(f'<div class="warning-box">⚠️ {diagnostics["summary"]}</div>', unsafe_allow_html=True)
                    elif "not running" in diagnostics["summary"]:
                        st.markdown(f'<div class="warning-box">⚠️ {diagnostics["summary"]}</div>', unsafe_allow_html=True)
                    elif "connectivity issues" in diagnostics["summary"]:
                        st.markdown(f'<div class="warning-box">⚠️ {diagnostics["summary"]}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="success-box">✅ {diagnostics["summary"]}</div>', unsafe_allow_html=True)
                
                # Create tabs for different sections
                tab1, tab2, tab3 = st.tabs(["Device", "Frida Server", "Environment"])
                
                with tab1:
                    st.json(diagnostics.get("device_connection", {}))
                
                with tab2:
                    st.json(diagnostics.get("frida_server", {}))
                
                with tab3:
                    st.json(diagnostics.get("environment", {}))
            else:
                st.markdown('<div class="error-box">❌ Error running diagnostics</div>', unsafe_allow_html=True)
                st.json(diagnostics)

# Frida Server Page
elif page == "Frida Server":
    st.title("Frida Server Management")
    
    # Check if Frida server is running
    with st.container():
        st.subheader("Frida Server Status")
        if st.button("Check Frida Server Status", key="check_frida"):
            frida_result = get_api_response("/frida/status")
            if frida_result.get("running") == True:
                st.markdown('<div class="success-box">✅ Frida server is running</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="error-box">❌ Frida server is not running</div>', unsafe_allow_html=True)
            st.json(frida_result)
    
    # Start Frida server
    with st.container():
        st.subheader("Start Frida Server")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown("""
            This will automatically:
            1. Check if device is connected
            2. Download Frida server if needed
            3. Start Frida server on the device
            """)
        
        with col2:
            if st.button("Start Frida Server", key="start_frida"):
                with st.spinner("Starting Frida server..."):
                    start_result = get_api_response("/frida/start")
                    if start_result.get("status") == "success":
                        st.markdown('<div class="success-box">✅ Frida server started successfully</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-box">❌ Failed to start Frida server</div>', unsafe_allow_html=True)
                    st.json(start_result)
    
    # Download Frida server
    with st.container():
        st.subheader("Download Frida Server")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            version = st.text_input("Frida Version (leave empty for latest)", key="frida_version")
            arch = st.text_input("Architecture (leave empty for auto-detection)", key="frida_arch")
        
        with col2:
            st.write("Download Options")
            if st.button("Download Server", key="download_frida"):
                download_data = {}
                if version:
                    download_data["version"] = version
                if arch:
                    download_data["arch"] = arch
                
                with st.spinner("Downloading Frida server..."):
                    download_result = get_api_response("/frida/download", method="POST", data=download_data)
                    if download_result.get("status") == "success":
                        st.markdown('<div class="success-box">✅ Frida server downloaded successfully</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-box">❌ Failed to download Frida server</div>', unsafe_allow_html=True)
                    st.json(download_result)
    
    # Auto setup (download and start)
    with st.container():
        st.subheader("Auto Setup")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown("""
            One-click solution to:
            1. Check device connection
            2. Download the latest Frida server
            3. Start Frida server
            """)
        
        with col2:
            if st.button("Auto Setup", key="auto_setup"):
                with st.spinner("Setting up Frida..."):
                    setup_result = get_api_response("/frida/auto-setup", method="POST")
                    if setup_result.get("status") == "success":
                        st.markdown('<div class="success-box">✅ Frida server setup completed successfully</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-box">❌ Failed to setup Frida server</div>', unsafe_allow_html=True)
                    st.json(setup_result)

# Applications Page
elif page == "Applications":
    st.title("Installed Applications")
    
    # Filter section
    with st.container():
        st.subheader("Filter Applications")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            filter_keyword = st.text_input("Filter by keyword (e.g., 'com.android', 'google')", key="filter_keyword")
        
        with col2:
            if st.button("Apply Filter", key="apply_filter"):
                with st.spinner("Fetching applications..."):
                    if filter_keyword:
                        packages_result = get_api_response("/packages/filter", method="POST", data={"filter_keyword": filter_keyword})
                    else:
                        packages_result = get_api_response("/packages")
                    
                    if packages_result.get("status") == "success" and packages_result.get("packages"):
                        st.session_state.packages = packages_result.get("packages")
                        st.success(f"Found {len(packages_result['packages'])} applications")
                    else:
                        st.warning("No applications found or error occurred")
                        st.session_state.packages = []
    
    # List all applications
    with st.container():
        st.subheader("All Applications")
        if st.button("List All Applications", key="list_all"):
            with st.spinner("Fetching all applications..."):
                packages_result = get_api_response("/packages")
                if packages_result.get("status") == "success" and packages_result.get("packages"):
                    st.session_state.packages = packages_result.get("packages")
                    st.success(f"Found {len(packages_result['packages'])} applications")
                else:
                    st.warning("No applications found or error occurred")
                    st.session_state.packages = []
    
    # Display applications table
    if hasattr(st.session_state, 'packages') and st.session_state.packages:
        st.dataframe(st.session_state.packages)

# Script Injection Page
elif page == "Script Injection":
    st.title("Script Injection")
    
    # Get available scripts
    @st.cache_data(ttl=300)
    def get_available_scripts():
        scripts_result = get_api_response("/scripts")
        if scripts_result.get("status") == "success" and scripts_result.get("scripts"):
            return scripts_result.get("scripts")
        return []
    
    scripts = get_available_scripts()
    script_names = [script["name"] for script in scripts] if scripts else []
    
    # Script injection form
    with st.container():
        st.subheader("Inject Script")
        
        col1, col2 = st.columns(2)
        
        with col1:
            package_name = st.text_input("Package Name (e.g., com.android.chrome)", key="inject_package")
            script_name = st.selectbox("Select Script", script_names, key="inject_script")
            spawn = st.checkbox("Spawn New Process", value=True, key="inject_spawn")
        
        with col2:
            st.markdown("""
            ### Injection Notes:
            - Package name must be exact
            - Device must be rooted for direct injection
            - For non-rooted devices, try Objection
            """)
            st.markdown('<div class="warning-box">⚠️ Make sure Frida server is running before injection</div>', unsafe_allow_html=True)
        
        if script_names:
            selected_script = next((s for s in scripts if s["name"] == script_name), None)
            if selected_script:
                st.markdown(f"**Description**: {selected_script.get('description', 'No description available')}")
                
                if st.button("Inject Script", key="do_inject"):
                    with st.spinner("Injecting script..."):
                        inject_data = {
                            "package_name": package_name,
                            "script_path": script_name,
                            "spawn": spawn
                        }
                        inject_result = get_api_response("/inject", method="POST", data=inject_data)
                        
                        if inject_result.get("status") == "success":
                            st.markdown('<div class="success-box">✅ Script injected successfully</div>', unsafe_allow_html=True)
                        else:
                            st.markdown('<div class="error-box">❌ Script injection failed</div>', unsafe_allow_html=True)
                            
                            # Special handling for non-rooted device errors
                            if inject_result.get("details", {}).get("error_type") == "non_rooted_device":
                                st.markdown("""
                                <div class="warning-box">
                                <h3>Non-Rooted Device Detected</h3>
                                <p>Your device is not rooted. Try these alternatives:</p>
                                <ol>
                                    <li><strong>Objection:</strong> <code>pip install objection</code><br>
                                    <code>objection --gadget package_name explore</code><br>
                                    <code>android sslpinning disable</code></li>
                                    <li><strong>Repackage the app:</strong> <code>objection patchapk -s &lt;path-to-apk&gt;</code></li>
                                    <li><strong>Use a rooted emulator</strong> like Genymotion or modified AVD</li>
                                </ol>
                                </div>
                                """, unsafe_allow_html=True)
                        
                        st.json(inject_result)
        else:
            st.warning("No scripts available. Add scripts in the Scripts section.")

# Scripts Management Page
elif page == "Scripts":
    st.title("Script Management")
    
    # Get available scripts
    @st.cache_data(ttl=300)
    def get_available_scripts():
        scripts_result = get_api_response("/scripts")
        if scripts_result.get("status") == "success" and scripts_result.get("scripts"):
            return scripts_result.get("scripts"), scripts_result.get("directory")
        return [], ""
    
    scripts, scripts_dir = get_available_scripts()
    
    # Show available scripts
    with st.container():
        st.subheader("Available Scripts")
        
        if scripts:
            for script in scripts:
                with st.expander(f"{script['name']} - {script.get('description', 'No description')}"):
                    st.markdown(f"**Path**: `{script['path']}`")
                    st.markdown(f"**Description**: {script.get('description', 'No description available')}")
        else:
            st.info("No scripts available. Upload a script below.")
    
    # Upload new script
    with st.container():
        st.subheader("Upload New Script")
        
        with st.form("upload_form"):
            uploaded_file = st.file_uploader("Choose a JavaScript file", type="js")
            script_name = st.text_input("Script Name (optional)")
            script_description = st.text_area("Script Description")
            submit_button = st.form_submit_button("Upload Script")
            
            if submit_button and uploaded_file is not None:
                # Create form data
                files = {"file": uploaded_file}
                data = {}
                
                if script_name:
                    data["name"] = script_name
                if script_description:
                    data["description"] = script_description
                
                # Make the upload request
                try:
                    response = requests.post(f"{API_URL}/upload/script", files=files, data=data)
                    result = response.json()
                    
                    if result.get("status") == "success":
                        st.success("Script uploaded successfully")
                        st.experimental_rerun()  # Refresh the page to show the new script
                    else:
                        st.error(f"Failed to upload script: {result.get('message', 'Unknown error')}")
                except Exception as e:
                    st.error(f"Error uploading script: {str(e)}")
    
    # Script directory information
    with st.container():
        st.subheader("Script Directory")
        st.info(f"Scripts are stored in: {scripts_dir}")
        st.markdown("""
        ### Creating Custom Scripts
        
        Scripts should follow this format:
        ```javascript
        // Description: Your script description here
        
        Java.perform(function() {
            console.log("Script loaded");
            
            // Your code here
            
            // Example: Bypass SSL pinning
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            SSLContext.init.implementation = function(keyManagers, trustManagers, secureRandom) {
                console.log('[+] Bypassing SSL Pinning');
                this.init(keyManagers, null, secureRandom);
            };
        });
        ```
        """)

# Run the Streamlit app
if __name__ == "__main__":
    st.write("Streamlit app is running!")
